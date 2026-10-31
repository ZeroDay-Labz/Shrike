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
    /** Legacy (pre-Montoya) burp.IHttpListener instances, in registration order.
     *  Held as Object because the type lives on the extension's class loader. */
    static final List<Object> legacyListeners = new ArrayList<>();
    /** Montoya ContextMenuItemsProvider instances the extension registered. */
    static final List<Object> menuProviders = new ArrayList<>();
    /** Legacy burp.IContextMenuFactory instances the extension registered. */
    static final List<Object> legacyMenuFactories = new ArrayList<>();
    /** The menu items produced by the last enumeration, keyed by the id we handed
     *  the UI. Firing an id calls that item's action (which opens the extension's
     *  own window). Rebuilt on every enumeration, so only the live menu can fire. */
    static final Map<Integer, MenuEntry> menuItems = new LinkedHashMap<>();
    static int menuItemSeq = 0;

    /** One enumerated menu item: a display label and the Swing item that fires it. */
    static final class MenuEntry {
        final String label;
        final javax.swing.JMenuItem item;
        MenuEntry(String label, javax.swing.JMenuItem item) { this.label = label; this.item = item; }
    }
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
                // Not a Montoya extension — try the legacy (pre-Montoya) IBurpExtender API.
                Class<?> legacy = findLegacyExtensionClass(jarPath);
                if (legacy != null) {
                    runLegacy(legacy, realOut);
                    return;
                }
                realOut.println(json(false,
                        "no class implementing burp.api.montoya.BurpExtension or burp.IBurpExtender found"));
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

    /**
     * Load a legacy (pre-Montoya) {@code burp.IBurpExtender} jar: instantiate the
     * extender and hand it a reflective proxy of {@code burp.IBurpExtenderCallbacks}
     * backed by the same universal handler the Jython path uses. Known callbacks
     * (setExtensionName, logging, register*) do the real thing; any IHttpListener
     * it registers then processes live traffic in {@link #serveLoop}. This is the
     * clean-room legacy compatibility layer: we implement the *published* Extender
     * API exactly as extension developers consume it.
     */
    static void runLegacy(Class<?> extClass, PrintStream realOut) {
        try {
            Object extension = extClass.getDeclaredConstructor().newInstance();
            Class<?> cbIface = Class.forName("burp.IBurpExtenderCallbacks", true, extClass.getClassLoader());
            Object callbacks = proxy(cbIface);
            extClass.getMethod("registerExtenderCallbacks", cbIface).invoke(extension, callbacks);
            realOut.println(json(true, null));
            realOut.flush();
            if (serve) {
                serveLoop(realOut);
            } else if (!probe && uiWindows > 0) {
                Thread.currentThread().join();
            }
        } catch (Throwable t) {
            Throwable cause = (t instanceof InvocationTargetException && t.getCause() != null) ? t.getCause() : t;
            realOut.println(json(false, cause.getClass().getSimpleName() + ": " + cause.getMessage()));
        }
    }

    /** Find the first class in the jar that implements the legacy burp.IBurpExtender. */
    static Class<?> findLegacyExtensionClass(String jarPath) throws Exception {
        URLClassLoader loader = new URLClassLoader(new URL[]{new java.io.File(jarPath).toURI().toURL()},
                Host.class.getClassLoader());
        Class<?> iface;
        try {
            iface = Class.forName("burp.IBurpExtender", true, loader);
        } catch (ClassNotFoundException e) {
            return null; // legacy Extender API not on the classpath
        }
        // Fast path: the convention is a class literally named burp.BurpExtender.
        try {
            Class<?> c = Class.forName("burp.BurpExtender", false, loader);
            if (iface.isAssignableFrom(c) && !c.isInterface() && !Modifier.isAbstract(c.getModifiers())) {
                return c;
            }
        } catch (Throwable ignore) { /* fall through to a full scan */ }
        try (JarFile jf = new JarFile(jarPath)) {
            Enumeration<JarEntry> e = jf.entries();
            while (e.hasMoreElements()) {
                String name = e.nextElement().getName();
                if (!name.endsWith(".class") || name.contains("module-info")) continue;
                String cn = name.substring(0, name.length() - 6).replace('/', '.');
                try {
                    Class<?> c = Class.forName(cn, false, loader);
                    if (iface.isAssignableFrom(c) && !c.isInterface()
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
            if (a == null) {
                continue;
            }
            if (a instanceof HttpHandler) {
                httpHandlers.add((HttpHandler) a);
            } else if (isA(a, "burp.IHttpListener")) {
                // Legacy traffic hook: processHttpMessage(int, boolean, IHttpRequestResponse).
                legacyListeners.add(a);
            } else if (isA(a, "burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider")) {
                menuProviders.add(a);
            } else if (isA(a, "burp.IContextMenuFactory")) {
                legacyMenuFactories.add(a);
            }
        }
    }

    /** Whether {@code o} is an instance of the named interface, resolved through
     *  {@code o}'s own class loader (so it matches sub-interfaces and lambdas). */
    static boolean isA(Object o, String ifaceName) {
        try {
            return Class.forName(ifaceName, false, o.getClass().getClassLoader()).isInstance(o);
        } catch (Throwable t) {
            return false;
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
                if (line.startsWith("@REQ\t")) {
                    handleReq(out, line);
                } else if (line.startsWith("@MENU\t")) {
                    handleMenu(out, line);
                } else if (line.startsWith("@FIRE\t")) {
                    handleFire(out, line);
                }
            }
        } catch (Throwable t) {
            // stdin closed or unreadable → stop serving, let the JVM exit.
        }
    }

    /** @REQ: run one message through the handler chain and reply @RES. */
    static void handleReq(PrintStream out, String line) {
        String[] f = line.split("\t", -1);
        if (f.length < 7) {
            return;
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

    /**
     * @MENU: enumerate the context-menu items the extension contributes for a
     * selected request/response, and reply @MENURES with their labels.
     *
     * Frame: {@code @MENU\t<id>\t<host>\t<port>\t<secure>\t<b64 request>\t<b64 response>}
     * Reply: {@code @MENURES\t<id>\t<b64 json [{"id":N,"label":"..."}]>}
     */
    static void handleMenu(PrintStream out, String line) {
        String[] f = line.split("\t", -1);
        String id = f.length > 1 ? f[1] : "0";
        String host = f.length > 2 ? f[2] : "";
        int port = f.length > 3 ? parseIntOr(f[3], 0) : 0;
        boolean secure = f.length > 4 && ("1".equals(f[4]) || "true".equalsIgnoreCase(f[4]));
        byte[] req = f.length > 5 && !f[5].isEmpty() ? Base64.getDecoder().decode(f[5]) : new byte[0];
        byte[] resp = f.length > 6 && !f[6].isEmpty() ? Base64.getDecoder().decode(f[6]) : null;
        menuItems.clear();
        try {
            collectMontoyaItems(new MontoyaObjects.Svc(host, port, secure), req, resp);
        } catch (Throwable t) {
            reportHandlerError(t);
        }
        try {
            collectLegacyItems(host, port, secure, req, resp);
        } catch (Throwable t) {
            reportHandlerError(t);
        }
        StringBuilder b = new StringBuilder("[");
        boolean first = true;
        for (Map.Entry<Integer, MenuEntry> e : menuItems.entrySet()) {
            if (!first) {
                b.append(',');
            }
            first = false;
            b.append("{\"id\":").append(e.getKey()).append(",\"label\":").append(q(e.getValue().label)).append('}');
        }
        b.append(']');
        String payload = Base64.getEncoder().encodeToString(b.toString().getBytes(StandardCharsets.UTF_8));
        synchronized (out) {
            out.println("@MENURES\t" + id + "\t" + payload);
            out.flush();
        }
    }

    /** @FIRE: click the menu item with the given id (opens the extension's UI). */
    static void handleFire(PrintStream out, String line) {
        String[] f = line.split("\t", -1);
        String id = f.length > 1 ? f[1] : "0";
        int itemId = f.length > 2 ? parseIntOr(f[2], -1) : -1;
        MenuEntry e = menuItems.get(itemId);
        String status;
        if (e == null) {
            status = "err:no such menu item";
        } else {
            try {
                javax.swing.SwingUtilities.invokeLater(() -> {
                    try {
                        e.item.doClick();
                    } catch (Throwable t) {
                        reportHandlerError(t);
                    }
                });
                status = "ok";
            } catch (Throwable t) {
                status = "err:" + t.getMessage();
            }
        }
        synchronized (out) {
            out.println("@FIRED\t" + id + "\t" + status);
            out.flush();
        }
    }

    /** Ask every Montoya ContextMenuItemsProvider for items on this selection. */
    static void collectMontoyaItems(HttpService svc, byte[] req, byte[] resp) throws Exception {
        if (menuProviders.isEmpty()) {
            return;
        }
        ClassLoader cl = menuProviders.get(0).getClass().getClassLoader();
        Class<?> eventIface = Class.forName("burp.api.montoya.ui.contextmenu.ContextMenuEvent", true, cl);
        Class<?> provIface = Class.forName("burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider", true, cl);
        Object reqResp = MontoyaObjects.requestResponse(svc, req, resp);
        Class<?> merrIface = Class.forName(
                "burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse", true, cl);
        Object editor = Proxy.newProxyInstance(cl, new Class<?>[]{merrIface},
                new MessageEditorRR(reqResp));
        Object event = Proxy.newProxyInstance(cl, new Class<?>[]{eventIface},
                new ContextMenuEvent(reqResp, editor));
        Method m = provIface.getMethod("provideMenuItems", eventIface);
        for (Object p : menuProviders) {
            try {
                Object res = m.invoke(p, event);
                if (res instanceof List) {
                    for (Object c : (List<?>) res) {
                        flattenMenu(c, "");
                    }
                }
            } catch (Throwable t) {
                reportHandlerError(t);
            }
        }
    }

    /** Ask every legacy IContextMenuFactory for items on this selection. */
    static void collectLegacyItems(String host, int port, boolean secure, byte[] req, byte[] resp)
            throws Exception {
        if (legacyMenuFactories.isEmpty()) {
            return;
        }
        ClassLoader cl = legacyMenuFactories.get(0).getClass().getClassLoader();
        Class<?> ihrr = Class.forName("burp.IHttpRequestResponse", true, cl);
        Class<?> ihs = Class.forName("burp.IHttpService", true, cl);
        Class<?> invIface = Class.forName("burp.IContextMenuInvocation", true, cl);
        Class<?> facIface = Class.forName("burp.IContextMenuFactory", true, cl);
        LegacyMsg lm = new LegacyMsg(host, port, secure ? "https" : "http", req, resp);
        Object message = Proxy.newProxyInstance(cl, new Class<?>[]{ihrr, ihs}, lm);
        lm.self = message;
        Object selected = java.lang.reflect.Array.newInstance(ihrr, 1);
        java.lang.reflect.Array.set(selected, 0, message);
        Object inv = Proxy.newProxyInstance(cl, new Class<?>[]{invIface}, new ContextMenuInvocation(selected));
        Method m = facIface.getMethod("createMenuItems", invIface);
        for (Object fac : legacyMenuFactories) {
            try {
                Object res = m.invoke(fac, inv);
                if (res instanceof List) {
                    for (Object c : (List<?>) res) {
                        flattenMenu(c, "");
                    }
                }
            } catch (Throwable t) {
                reportHandlerError(t);
            }
        }
    }

    /** Walk a returned Swing component tree, registering each leaf JMenuItem (a
     *  JMenu's children are prefixed with its label) so nested menus still fire. */
    static void flattenMenu(Object c, String prefix) {
        if (c instanceof javax.swing.JMenu) {
            javax.swing.JMenu menu = (javax.swing.JMenu) c;
            String p = prefix + text(menu.getText()) + " ▸ ";
            for (int i = 0; i < menu.getItemCount(); i++) {
                flattenMenu(menu.getItem(i), p);
            }
        } else if (c instanceof javax.swing.JMenuItem) {
            javax.swing.JMenuItem item = (javax.swing.JMenuItem) c;
            String label = prefix + text(item.getText());
            menuItems.put(++menuItemSeq, new MenuEntry(label, item));
        }
    }

    static String text(String s) {
        return s == null || s.isEmpty() ? "(menu item)" : s;
    }

    /** ContextMenuEvent (Montoya): the selected request/response the user clicked. */
    static final class ContextMenuEvent implements InvocationHandler {
        final Object reqResp;
        final Object editor;
        ContextMenuEvent(Object reqResp, Object editor) { this.reqResp = reqResp; this.editor = editor; }

        @Override
        public Object invoke(Object p, Method m, Object[] a) throws Throwable {
            switch (m.getName()) {
                case "selectedRequestResponses": {
                    List<Object> l = new ArrayList<>();
                    l.add(reqResp);
                    return l;
                }
                case "messageEditorRequestResponse":
                    return Optional.of(editor);
                case "selectedClientRequestResponses":
                    return new ArrayList<>();
                case "toolType":
                    return proxyEnum(m.getReturnType());
                case "isFromTool":
                case "hasHttpRequestResponses":
                    return Boolean.TRUE;
                case "inputEvent":
                    return Optional.empty();
                default:
                    return HANDLER.invoke(p, m, a);
            }
        }
    }

    /** IContextMenuInvocation (legacy): the selected messages the user clicked. */
    static final class ContextMenuInvocation implements InvocationHandler {
        final Object selected; // IHttpRequestResponse[]
        ContextMenuInvocation(Object selected) { this.selected = selected; }

        @Override
        public Object invoke(Object p, Method m, Object[] a) {
            switch (m.getName()) {
                case "getSelectedMessages":
                    return selected;
                case "getInvocationContext":
                    return (byte) 6; // CONTEXT_PROXY_HISTORY
                case "getToolFlag":
                    return 4; // TOOL_PROXY
                case "getSelectionBounds":
                    return new int[]{0, 0};
                case "getInputEvent":
                    return null;
                default:
                    Class<?> r = m.getReturnType();
                    if (r == boolean.class) {
                        return false;
                    }
                    if (r.isPrimitive()) {
                        return defaultPrimitive(r);
                    }
                    return null;
            }
        }
    }

    /** MessageEditorHttpRequestResponse (Montoya): the editor's current message,
     *  for providers that only add items in a message-editor context. */
    static final class MessageEditorRR implements InvocationHandler {
        final Object reqResp;
        MessageEditorRR(Object reqResp) { this.reqResp = reqResp; }

        @Override
        public Object invoke(Object p, Method m, Object[] a) {
            switch (m.getName()) {
                case "requestResponse":
                    return reqResp;
                case "selectionOffsets":
                    return Optional.empty();
                case "caretPosition":
                    return 0;
                case "selectionContext":
                    return proxyEnum(m.getReturnType());
                default:
                    break;
            }
            Class<?> r = m.getReturnType();
            if (r == boolean.class) {
                return false;
            }
            if (r.isPrimitive()) {
                return defaultPrimitive(r);
            }
            if (r == Optional.class) {
                return Optional.empty();
            }
            return null;
        }
    }

    static Object proxyEnum(Class<?> ret) {
        if (ret.isEnum()) {
            Object[] consts = ret.getEnumConstants();
            return consts != null && consts.length > 0 ? consts[0] : null;
        }
        return null;
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
        cur = runLegacyListeners(svc, cur, null, true);
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
        cur = runLegacyListeners(svc, null, cur, false);
        return new String[]{"continue", Base64.getEncoder().encodeToString(cur)};
    }

    /**
     * Feed one message through every legacy burp.IHttpListener in turn. Each sees a
     * mutable IHttpRequestResponse it may rewrite via setRequest/setResponse; we
     * return the (possibly modified) bytes for the phase we are in. No-op when no
     * legacy listener is registered.
     */
    static byte[] runLegacyListeners(HttpService svc, byte[] request, byte[] response, boolean isRequest) {
        if (legacyListeners.isEmpty()) {
            return isRequest ? request : response;
        }
        try {
            ClassLoader cl = legacyListeners.get(0).getClass().getClassLoader();
            Class<?> ihrr = Class.forName("burp.IHttpRequestResponse", true, cl);
            Class<?> ihs = Class.forName("burp.IHttpService", true, cl);
            LegacyMsg h = new LegacyMsg(svc.host(), svc.port(),
                    svc.secure() ? "https" : "http", request, response);
            Object msg = Proxy.newProxyInstance(cl, new Class<?>[]{ihrr, ihs}, h);
            h.self = msg;
            // Legacy tool flag for Proxy (burp.IBurpExtenderCallbacks.TOOL_PROXY == 4).
            for (Object l : legacyListeners) {
                try {
                    Method m = l.getClass().getMethod("processHttpMessage", int.class, boolean.class, ihrr);
                    m.invoke(l, 4, isRequest, msg);
                } catch (Throwable t) {
                    reportHandlerError(t);
                }
            }
            byte[] outReq = h.request == null ? request : h.request;
            byte[] outResp = h.response == null ? response : h.response;
            return isRequest ? outReq : outResp;
        } catch (Throwable t) {
            reportHandlerError(t);
            return isRequest ? request : response;
        }
    }

    /**
     * A mutable IHttpRequestResponse (and its IHttpService) for legacy listeners.
     * One instance backs a proxy implementing both interfaces; getHttpService()
     * returns the same proxy, so getHost/getPort/getProtocol resolve off it too.
     */
    static final class LegacyMsg implements InvocationHandler {
        final String host;
        final int port;
        final String protocol;
        byte[] request;
        byte[] response;
        Object self;

        LegacyMsg(String host, int port, String protocol, byte[] request, byte[] response) {
            this.host = host;
            this.port = port;
            this.protocol = protocol;
            this.request = request;
            this.response = response;
        }

        @Override
        public Object invoke(Object p, Method m, Object[] a) {
            switch (m.getName()) {
                case "getRequest": return request == null ? new byte[0] : request;
                case "setRequest": request = (byte[]) a[0]; return null;
                case "getResponse": return response == null ? new byte[0] : response;
                case "setResponse": response = (byte[]) a[0]; return null;
                case "getHttpService": return self;
                case "getHost": return host;
                case "getPort": return port;
                case "getProtocol": return protocol;
                default: break;
            }
            Class<?> r = m.getReturnType();
            if (r == boolean.class) {
                return false;
            }
            if (r.isPrimitive()) {
                return defaultPrimitive(r);
            }
            return null;
        }
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
