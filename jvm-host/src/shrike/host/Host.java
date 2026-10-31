package shrike.host;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.lang.reflect.*;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Shrike's BApp compatibility host.
 *
 * Loads a BApp extension (Montoya API) in an isolated class loader and runs its
 * {@code initialize(MontoyaApi)} against a Montoya API we implement with a
 * universal reflective proxy: known calls (logging, extension name, UI tab
 * registration) do the real thing; everything else returns a safe default or a
 * nested proxy so initialization completes without NPEs. We capture what the
 * extension logged and registered and report it as JSON on stdout.
 *
 * This is the clean-room compatibility layer: we provide our own implementation
 * of the *published* Montoya API (used here exactly as extension
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
    /** Swing windows currently open; when this hits zero for a UI-only extension
     *  (no traffic handlers), the extension is no longer in use, so we stop. */
    static int openWindows = 0;
    /** "probe" = load, report, exit (never block); "run" = keep UI alive. */
    static boolean probe = true;
    /** "serve" = load, then process traffic frames on stdin/stdout until EOF. */
    static boolean serve = false;
    /** HTTP handlers the extension registered, in registration order. */
    static final List<HttpHandler> httpHandlers = new ArrayList<>();
    /** Our JSON/line channel to the Rust host (the real stdout). */
    static PrintStream out = System.out;

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println(json(false, "no extension jar given"));
            return;
        }
        String jarPath = args[0];
        String mode = args.length >= 2 ? args[1] : "probe";
        serve = "serve".equals(mode);
        probe = !"run".equals(mode) && !serve;
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
            // Install our object factory before initialize() so the extension's
            // static constructors (HttpRequest.httpRequest(..), etc.) work.
            MontoyaObjects.install();
            init.invoke(extension, api);

            realOut.println(json(true, null));
            realOut.flush();
            if (serve) {
                // Process traffic until the Rust side closes stdin.
                serveLoop(realOut);
            } else if (!probe && uiWindows > 0) {
                // In "run" mode keep the JVM alive so any UI window stays open.
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
            // Multi-file extensions import their own modules (e.g. `from helpers.http
            // import ...`), so the script's directory must be on sys.path, and some
            // locate their resources through __file__.
            String abs = new java.io.File(pyPath).getAbsolutePath();
            String dir = new java.io.File(abs).getParent();
            pi.getMethod("set", String.class, Object.class).invoke(interp, "__shrike_dir", dir == null ? "." : dir);
            pi.getMethod("set", String.class, Object.class).invoke(interp, "__file__", abs);
            pi.getMethod("exec", String.class).invoke(interp, "import sys\nsys.path.insert(0, __shrike_dir)");
            pi.getMethod("execfile", String.class).invoke(interp, abs);
            pi.getMethod("set", String.class, Object.class).invoke(interp, "__shrike_cb", callbacks);
            pi.getMethod("exec", String.class)
                .invoke(interp, "BurpExtender().registerExtenderCallbacks(__shrike_cb)");
            realOut.println(json(true, null));
            realOut.flush();
            if (serve) {
                // Serve mode (how addons are launched): keep the host alive and
                // drain the traffic protocol, exactly like the Montoya path. A
                // legacy Jython extension registers through the burp.* callbacks,
                // so it doesn't populate the Montoya handler list — the loop just
                // keeps the process (and any Swing UI it opened) alive until Rust
                // closes stdin. Without this the process exited the instant it
                // finished loading, so the addon showed as "not running".
                serveLoop(realOut);
            } else if (!probe && uiWindows > 0) {
                Thread.currentThread().join();
            }
        } catch (Throwable t) {
            Throwable cause = (t instanceof InvocationTargetException && t.getCause() != null) ? t.getCause() : t;
            String cn = cause.getClass().getName();
            String hint = cn.contains("PyException") || cn.startsWith("org.python")
                ? " (is this a legacy Python BApp with a BurpExtender class?)"
                : cn.contains("ClassNotFoundException")
                    ? " (Jython / legacy Extender API not on the classpath — install Jython in Addons)"
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
            captureHandler(args);
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

    /** Record any traffic handler the extension registered. */
    static void captureHandler(Object[] args) {
        if (args == null) {
            return;
        }
        for (Object a : args) {
            if (a instanceof HttpHandler) {
                httpHandlers.add((HttpHandler) a);
            }
        }
    }

    /**
     * The traffic loop: read framed requests from stdin, run them through the
     * registered handlers, write the (possibly modified) result back.
     *
     * Frame in:  {@code @REQ\t<id>\t<request|response>\t<host>\t<port>\t<secure>\t<base64 raw>}
     * Frame out: {@code @RES\t<id>\t<continue|drop>\t<base64 raw>}
     *
     * Base64 keeps binary bodies intact; tabs never appear in the fields. The
     * loop ends when Rust closes stdin, which ends the JVM.
     */
    static void serveLoop(PrintStream out) {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.ISO_8859_1));
        try {
            String line;
            while ((line = in.readLine()) != null) {
                if (!line.startsWith("@REQ\t")) {
                    continue;
                }
                String[] f = line.split("\t", -1);
                if (f.length < 7) {
                    continue;
                }
                String id = f[1];
                String phase = f[2];
                HttpService svc = new MontoyaObjects.Svc(f[3], parseIntOr(f[4], 0),
                        "1".equals(f[5]) || "true".equalsIgnoreCase(f[5]));
                byte[] raw = Base64.getDecoder().decode(f[6]);
                String[] r = "response".equals(phase) ? dispatchResponse(svc, raw) : dispatchRequest(svc, raw);
                synchronized (out) {
                    out.println("@RES\t" + id + "\t" + r[0] + "\t" + r[1]);
                    out.flush();
                }
            }
        } catch (Throwable t) {
            // stdin closed or unreadable → stop serving, let the JVM exit.
        }
    }

    /** Run a request through every HTTP handler in turn; returns {action, base64}. */
    static String[] dispatchRequest(HttpService svc, byte[] raw) {
        byte[] cur = raw;
        for (HttpHandler h : httpHandlers) {
            try {
                HttpRequestToBeSent req = (HttpRequestToBeSent) MontoyaObjects.request(svc, cur, null);
                RequestToBeSentAction a = h.handleHttpRequestToBeSent(req);
                if (a == null) {
                    continue;
                }
                Object action = a.action();
                if (action != null && action.toString().contains("DROP")) {
                    return new String[]{"drop", ""};
                }
                HttpRequest out = a.request();
                if (out != null) {
                    cur = out.toByteArray().getBytes();
                }
            } catch (Throwable t) {
                reportHandlerError(t);
            }
        }
        return new String[]{"continue", Base64.getEncoder().encodeToString(cur)};
    }

    /** Run a response through every HTTP handler in turn; returns {action, base64}. */
    static String[] dispatchResponse(HttpService svc, byte[] raw) {
        byte[] cur = raw;
        for (HttpHandler h : httpHandlers) {
            try {
                HttpResponseReceived resp = (HttpResponseReceived) MontoyaObjects.response(cur, null);
                ResponseReceivedAction a = h.handleHttpResponseReceived(resp);
                if (a == null) {
                    continue;
                }
                HttpResponse out = a.response();
                if (out != null) {
                    cur = out.toByteArray().getBytes();
                }
            } catch (Throwable t) {
                reportHandlerError(t);
            }
        }
        return new String[]{"continue", Base64.getEncoder().encodeToString(cur)};
    }

    static void reportHandlerError(Throwable t) {
        String s = t.getClass().getSimpleName() + ": " + t.getMessage();
        errors.add(s);
        if (serve) {
            out.println("@ERR:" + s);
            out.flush();
        }
    }

    static int parseIntOr(String s, int dflt) {
        try {
            return Integer.parseInt(s.trim());
        } catch (Exception e) {
            return dflt;
        }
    }

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
            openWindows++;
            registered.add("suiteTab:" + title);
            // When the user closes the last window of a UI-only extension (one with
            // no traffic handlers), it is no longer being used, so stop it. An
            // extension that also processes traffic keeps running after its window
            // closes.
            f.addWindowListener(new java.awt.event.WindowAdapter() {
                @Override public void windowClosed(java.awt.event.WindowEvent e) {
                    openWindows--;
                    if (openWindows <= 0 && httpHandlers.isEmpty()) {
                        out.println("@OUT:all extension windows closed — stopping");
                        out.flush();
                        System.exit(0);
                    }
                }
            });
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
