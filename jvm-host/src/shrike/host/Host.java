package shrike.host;

import java.io.PrintStream;
import java.lang.reflect.*;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Shrike's BApp compatibility host.
 *
 * Loads a Burp extension (Montoya API) in an isolated class loader and runs its
 * {@code initialize(MontoyaApi)} against a Montoya API we implement with a
 * universal reflective proxy: known calls (logging, extension name, UI tab
 * registration) do the real thing; everything else returns a safe default or a
 * nested proxy so initialization completes without NPEs. We capture what the
 * extension logged and registered and report it as JSON on stdout.
 *
 * This is the clean-room compatibility layer: we provide our own implementation
 * of PortSwigger's *published* Montoya API (used here exactly as extension
 * developers use it). Full traffic wiring is a later layer.
 *
 * Usage: java -cp host.jar:montoya-api.jar shrike.host.Host <extension.jar>
 */
public final class Host {
    static final List<String> outputs = new ArrayList<>();
    static final List<String> errors = new ArrayList<>();
    static final LinkedHashSet<String> registered = new LinkedHashSet<>();
    static String extName = null;
    static int uiWindows = 0;
    /** "probe" = load, report, exit (never block); "run" = keep UI alive. */
    static boolean probe = true;
    /** Our JSON/line channel to the Rust host (the real stdout). */
    static PrintStream out = System.out;

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println(json(false, "no extension jar given"));
            return;
        }
        String jarPath = args[0];
        probe = args.length < 2 || !"run".equals(args[1]);
        // Keep the extension's own stdout/stderr out of our JSON channel.
        PrintStream realOut = System.out;
        out = realOut;
        // Python (Jython) extensions use the legacy burp.* API, not Montoya.
        if (jarPath.toLowerCase().endsWith(".py")) {
            runPython(jarPath, realOut);
            return;
        }
        try {
            Class<?> extClass = findExtensionClass(jarPath);
            if (extClass == null) {
                realOut.println(json(false, "no class implementing burp.api.montoya.BurpExtension found"));
                return;
            }
            Object extension = extClass.getDeclaredConstructor().newInstance();
            Class<?> montoyaApi = Class.forName("burp.api.montoya.MontoyaApi", true, extClass.getClassLoader());
            Object api = proxy(montoyaApi);

            Method init = extClass.getMethod("initialize", montoyaApi);
            init.invoke(extension, api);

            realOut.println(json(true, null));
            // In "run" mode keep the JVM alive so any UI window stays open.
            if (!probe && uiWindows > 0) {
                Thread.currentThread().join();
            }
        } catch (Throwable t) {
            Throwable cause = (t instanceof InvocationTargetException && t.getCause() != null) ? t.getCause() : t;
            realOut.println(json(false, cause.getClass().getSimpleName() + ": " + cause.getMessage()));
        }
    }

    /**
     * Load a legacy Python (Jython) extension: exec the file, instantiate its
     * {@code BurpExtender}, and call {@code registerExtenderCallbacks} with a
     * reflective proxy of {@code burp.IBurpExtenderCallbacks} backed by the same
     * universal handler. Jython and the legacy burp API must be on the classpath.
     */
    static void runPython(String pyPath, PrintStream realOut) {
        try {
            Class<?> cbIface = Class.forName("burp.IBurpExtenderCallbacks");
            Object callbacks = proxy(cbIface);
            Class<?> pi = Class.forName("org.python.util.PythonInterpreter");
            Object interp = pi.getConstructor().newInstance();
            pi.getMethod("execfile", String.class).invoke(interp, pyPath);
            pi.getMethod("set", String.class, Object.class).invoke(interp, "__shrike_cb", callbacks);
            pi.getMethod("exec", String.class)
                .invoke(interp, "BurpExtender().registerExtenderCallbacks(__shrike_cb)");
            realOut.println(json(true, null));
            if (!probe && uiWindows > 0) {
                Thread.currentThread().join();
            }
        } catch (Throwable t) {
            Throwable cause = (t instanceof InvocationTargetException && t.getCause() != null) ? t.getCause() : t;
            String cn = cause.getClass().getName();
            String hint = cn.contains("PyException") || cn.startsWith("org.python")
                ? " (is this a legacy burp Python extension with a BurpExtender class?)"
                : cn.contains("ClassNotFoundException")
                    ? " (Jython / legacy burp API not on the classpath — install Jython in Extender)"
                    : "";
            realOut.println(json(false, cause.getClass().getSimpleName() + ": " + cause.getMessage() + hint));
        }
    }

    /** Find the first class in the jar that implements BurpExtension. */
    static Class<?> findExtensionClass(String jarPath) throws Exception {
        URLClassLoader loader = new URLClassLoader(new URL[]{new java.io.File(jarPath).toURI().toURL()},
                Host.class.getClassLoader());
        Class<?> burpExtension = Class.forName("burp.api.montoya.BurpExtension", true, loader);
        try (JarFile jf = new JarFile(jarPath)) {
            Enumeration<JarEntry> e = jf.entries();
            while (e.hasMoreElements()) {
                String name = e.nextElement().getName();
                if (!name.endsWith(".class") || name.contains("module-info")) continue;
                String cn = name.substring(0, name.length() - 6).replace('/', '.');
                try {
                    Class<?> c = Class.forName(cn, false, loader);
                    if (burpExtension.isAssignableFrom(c) && !c.isInterface()
                            && !Modifier.isAbstract(c.getModifiers())) {
                        return c;
                    }
                } catch (Throwable ignore) { /* skip unloadable classes */ }
            }
        }
        return null;
    }

    /** A dynamic proxy for a Montoya interface, backed by the universal handler. */
    static Object proxy(Class<?> iface) {
        return Proxy.newProxyInstance(iface.getClassLoader(), new Class<?>[]{iface}, HANDLER);
    }

    static final InvocationHandler HANDLER = (p, method, args) -> {
        String n = method.getName();
        switch (n) {
            case "logToOutput": case "println": case "output":
            case "printOutput": case "printOut": {
                String s = str(args);
                outputs.add(s);
                if (!probe) { out.println("@OUT:" + s); out.flush(); }
                return null;
            }
            case "logToError": case "error": case "printError": {
                String s = str(args);
                errors.add(s);
                if (!probe) { out.println("@ERR:" + s); out.flush(); }
                return null;
            }
            case "setName": case "setExtensionName":
                extName = str(args); return null;
            default: break;
        }
        if (n.startsWith("register")) {
            registered.add(n);
            if (n.equals("registerSuiteTab") && args != null && args.length >= 2
                    && args[1] instanceof java.awt.Component) {
                showTab(args[0] == null ? "Extension" : args[0].toString(), (java.awt.Component) args[1]);
            }
        }
        // Legacy Extender API: addSuiteTab(ITab) with getTabCaption()/getUiComponent().
        if (n.equals("addSuiteTab") && args != null && args.length >= 1 && args[0] != null) {
            registered.add("addSuiteTab");
            try {
                Object tab = args[0];
                Object cap = tab.getClass().getMethod("getTabCaption").invoke(tab);
                Object comp = tab.getClass().getMethod("getUiComponent").invoke(tab);
                if (comp instanceof java.awt.Component) {
                    showTab(cap == null ? "Extension" : cap.toString(), (java.awt.Component) comp);
                }
            } catch (Throwable t) {
                registered.add("suiteTab(unresolved)");
            }
        }
        Class<?> ret = method.getReturnType();
        if (ret == void.class || ret == Void.TYPE) return null;
        if (ret.isPrimitive()) return defaultPrimitive(ret);
        if (ret == String.class) return "";
        if (ret.isEnum()) {
            Object[] consts = ret.getEnumConstants();
            return consts != null && consts.length > 0 ? consts[0] : null;
        }
        if (ret == java.util.Optional.class) return java.util.Optional.empty();
        if (ret.isArray()) return java.lang.reflect.Array.newInstance(ret.getComponentType(), 0);
        if (Map.class.isAssignableFrom(ret)) return new HashMap<>();
        if (List.class.isAssignableFrom(ret) || Collection.class.isAssignableFrom(ret)
                || Set.class.isAssignableFrom(ret)) {
            return Set.class.isAssignableFrom(ret) ? new LinkedHashSet<>() : new ArrayList<>();
        }
        // Many extensions pipe Python's stdout to callbacks.getStdout(); hand back
        // a discarding stream/writer rather than null so they don't NPE.
        if (java.io.OutputStream.class.isAssignableFrom(ret)) {
            return new java.io.OutputStream() { public void write(int b) {} };
        }
        if (ret == java.io.PrintWriter.class) {
            return new java.io.PrintWriter(new java.io.OutputStream() { public void write(int b) {} });
        }
        if (ret.isInterface()) {
            try { return proxy(ret); } catch (Throwable t) { return null; }
        }
        return null;
    };

    static void showTab(String title, java.awt.Component comp) {
        if (probe) {
            // Don't open windows during a load-check; just note the capability.
            uiWindows++;
            registered.add("suiteTab:" + title);
            return;
        }
        try {
            javax.swing.JFrame f = new javax.swing.JFrame("Shrike — " + title);
            f.setDefaultCloseOperation(javax.swing.JFrame.DISPOSE_ON_CLOSE);
            f.add(comp);
            f.setSize(900, 600);
            f.setVisible(true);
            uiWindows++;
            registered.add("suiteTab:" + title);
        } catch (Throwable t) {
            registered.add("suiteTab(no-display):" + title);
        }
    }

    static Object defaultPrimitive(Class<?> t) {
        if (t == boolean.class) return false;
        if (t == char.class) return '\0';
        if (t == double.class) return 0d;
        if (t == float.class) return 0f;
        if (t == long.class) return 0L;
        return 0;
    }

    static String str(Object[] args) {
        if (args == null || args.length == 0) return "";
        return String.valueOf(args[0]);
    }

    static String json(boolean ok, String error) {
        StringBuilder b = new StringBuilder("{");
        b.append("\"ok\":").append(ok);
        b.append(",\"name\":").append(extName == null ? "null" : q(extName));
        b.append(",\"registered\":[").append(joinQ(registered)).append(']');
        b.append(",\"outputs\":[").append(joinQ(outputs)).append(']');
        b.append(",\"errors\":[").append(joinQ(errors)).append(']');
        b.append(",\"uiWindows\":").append(uiWindows);
        if (error != null) b.append(",\"error\":").append(q(error));
        b.append('}');
        return b.toString();
    }

    static String joinQ(Collection<String> items) {
        StringBuilder b = new StringBuilder();
        boolean first = true;
        for (String s : items) { if (!first) b.append(','); b.append(q(s)); first = false; }
        return b.toString();
    }

    static String q(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default: if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c);
            }
        }
        return b.append('"').toString();
    }
}
