package shrike.host;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.RequestAction;
import burp.api.montoya.http.handler.ResponseAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Clean-room implementation of the published Montoya object model.
 *
 * The Montoya API's static constructors — {@code HttpRequest.httpRequest(..)},
 * {@code ByteArray.byteArray(..)}, {@code HttpService.httpService(..)} — and the
 * handler action builders — {@code RequestToBeSentAction.continueWith(..)} —
 * all delegate to a singleton {@link MontoyaObjectFactory} resolved through
 * {@link ObjectFactoryLocator#FACTORY}. Extensions call these constantly to read
 * and rewrite traffic. Burp ships that factory; Shrike does not, so until one is
 * installed every such call NPEs or returns nothing and handlers can't touch
 * traffic.
 *
 * {@link #install()} puts our own factory in that slot. HTTP messages are modeled
 * as byte-backed facades (a {@link Msg} invocation handler that parses the wire
 * bytes for getters and rebuilds them for every {@code withX(..)} mutation), so a
 * handler that reads headers/body and returns a modified request round-trips
 * faithfully. The small value types (header, service, annotations, parameter) are
 * plain classes. We implement the methods real extensions use and fall back to
 * safe defaults for the rest of the surface.
 */
final class MontoyaObjects {
    private MontoyaObjects() {}

    /** ISO-8859-1 keeps request/response bytes lossless through String round-trips. */
    static final java.nio.charset.Charset WIRE = StandardCharsets.ISO_8859_1;

    /** Install our factory into the API's locator. Idempotent. */
    static void install() {
        if (ObjectFactoryLocator.FACTORY == null) {
            ObjectFactoryLocator.FACTORY = (MontoyaObjectFactory) Proxy.newProxyInstance(
                    MontoyaObjectFactory.class.getClassLoader(),
                    new Class<?>[]{MontoyaObjectFactory.class},
                    new Factory());
        }
    }

    // --- HTTP message facade -------------------------------------------------

    /** Build a request facade usable as HttpRequest and HttpRequestToBeSent. */
    static HttpRequest request(HttpService service, byte[] raw, Annotations ann) {
        Msg m = new Msg(true, service, raw == null ? new byte[0] : raw, ann);
        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class<?>[]{
                        HttpRequest.class,
                        burp.api.montoya.http.handler.HttpRequestToBeSent.class,
                        burp.api.montoya.proxy.http.InterceptedRequest.class,
                },
                m);
    }

    /** Build a response facade usable as HttpResponse and HttpResponseReceived. */
    static HttpResponse response(byte[] raw, Annotations ann) {
        Msg m = new Msg(false, null, raw == null ? new byte[0] : raw, ann);
        return (HttpResponse) Proxy.newProxyInstance(
                HttpResponse.class.getClassLoader(),
                new Class<?>[]{
                        HttpResponse.class,
                        burp.api.montoya.http.handler.HttpResponseReceived.class,
                        burp.api.montoya.proxy.http.InterceptedResponse.class,
                },
                m);
    }

    /**
     * A single HTTP message, backed by its wire bytes. Getters parse the bytes;
     * {@code withX(..)} methods rebuild them and return a fresh facade, so the
     * original is never mutated (the Montoya messages are immutable).
     */
    static final class Msg implements InvocationHandler {
        final boolean isRequest;
        final HttpService service;
        final byte[] raw;
        final Annotations ann;
        // Parsed lazily on first access.
        private String startLine;
        private List<String[]> headers; // {name, value}
        private int bodyOffset = -1;

        Msg(boolean isRequest, HttpService service, byte[] raw, Annotations ann) {
            this.isRequest = isRequest;
            this.service = service;
            this.raw = raw;
            this.ann = ann != null ? ann : new Ann();
        }

        private void parse() {
            if (startLine != null) {
                return;
            }
            int bs = raw.length;
            for (int i = 0; i + 1 < raw.length; i++) {
                if (raw[i] == '\n' && raw[i + 1] == '\n') { bs = i + 2; break; }
                if (i + 3 < raw.length && raw[i] == '\r' && raw[i + 1] == '\n'
                        && raw[i + 2] == '\r' && raw[i + 3] == '\n') { bs = i + 4; break; }
            }
            bodyOffset = bs;
            String head = new String(raw, 0, bs, WIRE);
            String[] lines = head.split("\r\n|\n", -1);
            startLine = lines.length > 0 ? lines[0] : "";
            headers = new ArrayList<>();
            for (int i = 1; i < lines.length; i++) {
                String ln = lines[i];
                if (ln.isEmpty()) continue;
                int c = ln.indexOf(':');
                if (c < 0) continue;
                String name = ln.substring(0, c).trim();
                String value = ln.substring(c + 1).trim();
                headers.add(new String[]{name, value});
            }
        }

        private byte[] body() {
            parse();
            int len = raw.length - bodyOffset;
            byte[] b = new byte[Math.max(0, len)];
            if (len > 0) System.arraycopy(raw, bodyOffset, b, 0, len);
            return b;
        }

        private String tok(int i) {
            parse();
            String[] t = startLine.split(" ", 3);
            return i < t.length ? t[i] : "";
        }

        private String headerValue(String name) {
            parse();
            for (String[] h : headers) {
                if (h[0].equalsIgnoreCase(name)) return h[1];
            }
            return null;
        }

        /** Reassemble wire bytes from a (possibly modified) start line + headers + body. */
        private byte[] rebuild(String start, List<String[]> hs, byte[] bodyBytes) {
            StringBuilder sb = new StringBuilder();
            sb.append(start).append("\r\n");
            for (String[] h : hs) {
                sb.append(h[0]).append(": ").append(h[1]).append("\r\n");
            }
            sb.append("\r\n");
            byte[] head = sb.toString().getBytes(WIRE);
            byte[] out = new byte[head.length + bodyBytes.length];
            System.arraycopy(head, 0, out, 0, head.length);
            System.arraycopy(bodyBytes, 0, out, head.length, bodyBytes.length);
            return out;
        }

        private List<String[]> copyHeaders() {
            parse();
            List<String[]> c = new ArrayList<>(headers.size());
            for (String[] h : headers) c.add(new String[]{h[0], h[1]});
            return c;
        }

        private Object self(String start, List<String[]> hs, byte[] bodyBytes) {
            byte[] out = rebuild(start, hs, bodyBytes);
            return isRequest ? request(service, out, ann) : response(out, ann);
        }

        private Object withBody(byte[] newBody) {
            parse();
            List<String[]> hs = copyHeaders();
            boolean set = false;
            for (String[] h : hs) {
                if (h[0].equalsIgnoreCase("Content-Length")) { h[1] = Integer.toString(newBody.length); set = true; }
            }
            if (!set && newBody.length > 0) hs.add(new String[]{"Content-Length", Integer.toString(newBody.length)});
            return self(startLine, hs, newBody);
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            String n = method.getName();
            switch (n) {
                // java.lang.Object
                case "equals": return proxy == (args == null ? null : args[0]);
                case "hashCode": return System.identityHashCode(proxy);
                case "toString": return new String(raw, WIRE);

                // shared
                case "messageId": return 1;
                case "annotations": return ann;
                case "isInScope": return Boolean.FALSE;
                case "httpService": return service;
                case "httpVersion": return isRequest ? tok(2) : tok(0);
                case "bodyOffset": parse(); return bodyOffset;
                case "body": return bytes(body());
                case "bodyToString": return new String(body(), WIRE);
                case "toByteArray": return bytes(raw);
                case "markers": return new ArrayList<>();
                case "header": return headerFor(str(args));
                case "headerValue": return headerValue(str(args));
                case "contains": return contains(args);

                // request line
                case "method": return tok(0);
                case "path": return tok(1);
                case "pathWithoutQuery": { String p = tok(1); int q = p.indexOf('?'); return q < 0 ? p : p.substring(0, q); }
                case "url": return url();

                // response line
                case "statusCode": return (short) parseInt(tok(1), 0);
                case "reasonPhrase": { parse(); String[] t = startLine.split(" ", 3); return t.length > 2 ? t[2] : ""; }

                case "headers": return headerList();
                case "hasHeader": return hasHeader(args);

                default:
                    break;
            }

            // Mutators: with*(..) → a fresh facade with the change applied.
            if (n.startsWith("with")) {
                Object r = mutate(n, args);
                if (r != null) return r;
                // Unhandled mutator → return an equivalent copy so chains survive.
                return isRequest ? request(service, raw, ann) : response(raw, ann);
            }

            return defaultReturn(method.getReturnType());
        }

        private Object mutate(String n, Object[] args) {
            parse();
            switch (n) {
                case "withBody":
                    return withBody(bodyOf(args[0]));
                case "withService":
                    return request((HttpService) args[0], raw, ann);
                case "withMethod": {
                    String[] t = startLine.split(" ", 3);
                    t[0] = String.valueOf(args[0]);
                    return self(String.join(" ", t), copyHeaders(), body());
                }
                case "withPath": {
                    String[] t = startLine.split(" ", 3);
                    if (t.length > 1) t[1] = String.valueOf(args[0]);
                    return self(String.join(" ", t), copyHeaders(), body());
                }
                case "withStatusCode": {
                    String[] t = startLine.split(" ", 3);
                    if (t.length > 1) t[1] = String.valueOf(((Number) args[0]).intValue());
                    return self(String.join(" ", t), copyHeaders(), body());
                }
                case "withReasonPhrase": {
                    String[] t = startLine.split(" ", 3);
                    String v = String.valueOf(args[0]);
                    String s = (t.length > 0 ? t[0] : "") + " " + (t.length > 1 ? t[1] : "") + " " + v;
                    return self(s.trim(), copyHeaders(), body());
                }
                case "withHttpVersion": {
                    String[] t = startLine.split(" ", 3);
                    if (isRequest) { if (t.length > 2) t[2] = String.valueOf(args[0]); }
                    else if (t.length > 0) { t[0] = String.valueOf(args[0]); }
                    return self(String.join(" ", t), copyHeaders(), body());
                }
                case "withAddedHeader": {
                    List<String[]> hs = copyHeaders();
                    hs.add(headerPair(args));
                    return self(startLine, hs, body());
                }
                case "withUpdatedHeader": {
                    String[] pair = headerPair(args);
                    List<String[]> hs = copyHeaders();
                    boolean found = false;
                    for (String[] h : hs) {
                        if (h[0].equalsIgnoreCase(pair[0])) { h[1] = pair[1]; found = true; }
                    }
                    if (!found) hs.add(pair);
                    return self(startLine, hs, body());
                }
                case "withRemovedHeader": {
                    String name = headerName(args);
                    List<String[]> hs = copyHeaders();
                    hs.removeIf(h -> h[0].equalsIgnoreCase(name));
                    return self(startLine, hs, body());
                }
                default:
                    return null;
            }
        }

        private Object contains(Object[] args) {
            if (args == null || args.length == 0) return Boolean.FALSE;
            if (args[0] instanceof Pattern) {
                return ((Pattern) args[0]).matcher(new String(raw, WIRE)).find();
            }
            String needle = String.valueOf(args[0]);
            boolean caseSensitive = args.length > 1 && Boolean.TRUE.equals(args[1]);
            String hay = new String(raw, WIRE);
            return caseSensitive ? hay.contains(needle)
                    : hay.toLowerCase().contains(needle.toLowerCase());
        }

        private Object hasHeader(Object[] args) {
            if (args == null || args.length == 0) return Boolean.FALSE;
            if (args.length == 2 && args[0] instanceof String) {
                String v = headerValue((String) args[0]);
                return v != null && v.equalsIgnoreCase(String.valueOf(args[1]));
            }
            if (args[0] instanceof HttpHeader) {
                return headerValue(((HttpHeader) args[0]).name()) != null;
            }
            return headerValue(String.valueOf(args[0])) != null;
        }

        private HttpHeader headerFor(String name) {
            String v = headerValue(name);
            return v == null ? null : new Hdr(name, v);
        }

        private List<HttpHeader> headerList() {
            parse();
            List<HttpHeader> out = new ArrayList<>(headers.size());
            for (String[] h : headers) out.add(new Hdr(h[0], h[1]));
            return out;
        }

        private String url() {
            parse();
            String path = tok(1);
            if (service == null) return path;
            String scheme = service.secure() ? "https" : "http";
            int port = service.port();
            boolean defPort = (service.secure() && port == 443) || (!service.secure() && port == 80);
            String auth = defPort ? service.host() : service.host() + ":" + port;
            return scheme + "://" + auth + path;
        }
    }

    // --- value types ---------------------------------------------------------

    static byte[] bodyOf(Object o) {
        if (o instanceof ByteArray) return ((ByteArray) o).getBytes();
        return String.valueOf(o).getBytes(WIRE);
    }

    static String[] headerPair(Object[] args) {
        if (args.length >= 1 && args[0] instanceof HttpHeader) {
            HttpHeader h = (HttpHeader) args[0];
            return new String[]{h.name(), h.value()};
        }
        return new String[]{String.valueOf(args[0]), args.length > 1 ? String.valueOf(args[1]) : ""};
    }

    static String headerName(Object[] args) {
        if (args.length >= 1 && args[0] instanceof HttpHeader) return ((HttpHeader) args[0]).name();
        return String.valueOf(args[0]);
    }

    /** An immutable HTTP header. */
    static final class Hdr implements HttpHeader {
        final String name;
        final String value;
        Hdr(String name, String value) { this.name = name; this.value = value; }
        @Override public String name() { return name; }
        @Override public String value() { return value; }
        @Override public String toString() { return name + ": " + value; }
    }

    /** An HTTP service (host/port/secure). */
    static final class Svc implements HttpService {
        final String host;
        final int port;
        final boolean secure;
        Svc(String host, int port, boolean secure) { this.host = host; this.port = port; this.secure = secure; }
        @Override public String host() { return host; }
        @Override public int port() { return port; }
        @Override public boolean secure() { return secure; }
        @Override public String ipAddress() { return null; }
        @Override public String toString() { return (secure ? "https://" : "http://") + host + ":" + port; }
    }

    /** Mutable annotations (notes + highlight colour). */
    static final class Ann implements Annotations {
        private String notes;
        private HighlightColor color;
        Ann() {}
        Ann(String notes, HighlightColor color) { this.notes = notes; this.color = color; }
        @Override public String notes() { return notes; }
        @Override public boolean hasNotes() { return notes != null && !notes.isEmpty(); }
        @Override public boolean hasHighlightColor() { return color != null && color != HighlightColor.NONE; }
        @Override public void setNotes(String n) { this.notes = n; }
        @Override public HighlightColor highlightColor() { return color == null ? HighlightColor.NONE : color; }
        @Override public void setHighlightColor(HighlightColor c) { this.color = c; }
        @Override public Annotations withNotes(String n) { return new Ann(n, color); }
        @Override public Annotations withHighlightColor(HighlightColor c) { return new Ann(notes, c); }
    }

    /** An HTTP parameter (name/value/type). */
    static final class Param implements HttpParameter {
        final String name;
        final String value;
        final HttpParameterType type;
        Param(String name, String value, HttpParameterType type) { this.name = name; this.value = value; this.type = type; }
        @Override public HttpParameterType type() { return type; }
        @Override public String name() { return name; }
        @Override public String value() { return value; }
    }

    /** A byte array backed by a real buffer. */
    static ByteArray bytes(byte[] b) {
        return (ByteArray) Proxy.newProxyInstance(
                ByteArray.class.getClassLoader(),
                new Class<?>[]{ByteArray.class},
                new BA(b == null ? new byte[0] : b));
    }

    static final class BA implements InvocationHandler {
        final byte[] b;
        BA(byte[] b) { this.b = b; }
        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            switch (method.getName()) {
                case "equals": return proxy == (args == null ? null : args[0]);
                case "hashCode": return System.identityHashCode(proxy);
                case "toString": return new String(b, WIRE);
                case "length": return b.length;
                case "getBytes": return b;
                case "getByte": return b[(Integer) args[0]];
                case "iterator": {
                    return new Iterator<Byte>() {
                        int i = 0;
                        public boolean hasNext() { return i < b.length; }
                        public Byte next() { return b[i++]; }
                    };
                }
                case "copy": return bytes(b.clone());
                case "copyToTempFile": return proxy;
                case "subArray": {
                    int from = (Integer) args[0];
                    int to = (Integer) args[1];
                    byte[] s = new byte[Math.max(0, to - from)];
                    System.arraycopy(b, from, s, 0, s.length);
                    return bytes(s);
                }
                case "indexOf": {
                    String hay = new String(b, WIRE);
                    String needle = args[0] instanceof ByteArray
                            ? new String(((ByteArray) args[0]).getBytes(), WIRE)
                            : String.valueOf(args[0]);
                    return hay.indexOf(needle);
                }
                default: return defaultReturn(method.getReturnType());
            }
        }
    }

    // --- the factory ---------------------------------------------------------

    /** Dispatches the ~160 factory methods; implements the ones extensions use. */
    static final class Factory implements InvocationHandler {
        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            String n = method.getName();
            switch (n) {
                case "equals": return proxy == (args == null ? null : args[0]);
                case "hashCode": return System.identityHashCode(proxy);
                case "toString": return "ShrikeMontoyaObjectFactory";

                case "byteArray": return bytes(toBytes(args[0]));
                case "httpHeader": return makeHeader(args);
                case "httpService": return makeService(args);
                case "annotations": return makeAnnotations(args);

                case "httpRequest": return makeRequest(args);
                case "httpResponse": return makeResponse(args);

                case "parameter":
                    return new Param(String.valueOf(args[0]), String.valueOf(args[1]), (HttpParameterType) args[2]);
                case "urlParameter":
                    return new Param(String.valueOf(args[0]), String.valueOf(args[1]), HttpParameterType.URL);
                case "bodyParameter":
                    return new Param(String.valueOf(args[0]), String.valueOf(args[1]), HttpParameterType.BODY);
                case "cookieParameter":
                    return new Param(String.valueOf(args[0]), String.valueOf(args[1]), HttpParameterType.COOKIE);

                // Handler action builders: continueWith/drop delegate here.
                case "requestResult":
                    return action(method.getReturnType(), requestArg(args), null, RequestAction.CONTINUE, annFrom(args));
                case "responseResult":
                    return action(method.getReturnType(), null, responseArg(args), null, annFrom(args));
                case "requestFinalInterceptResultContinueWith":
                case "requestInitialInterceptResultIntercept":
                case "requestInitialInterceptResultDoNotIntercept":
                case "requestInitialInterceptResultFollowUserRules":
                    return action(method.getReturnType(), requestArg(args), null, RequestAction.CONTINUE, annFrom(args));
                case "responseFinalInterceptResultContinueWith":
                case "responseInitialInterceptResultIntercept":
                case "responseInitialInterceptResultDoNotIntercept":
                case "responseInitialInterceptResultFollowUserRules":
                    return action(method.getReturnType(), null, responseArg(args), null, annFrom(args));
                case "proxyRequestReceivedAction":
                case "proxyRequestToBeSentAction":
                    return action(method.getReturnType(), requestArg(args), null, RequestAction.CONTINUE, annFrom(args));
                case "proxyResponseReceivedAction":
                case "proxyResponseToReturnAction":
                    return action(method.getReturnType(), null, responseArg(args), null, annFrom(args));

                default:
                    return defaultReturn(method.getReturnType());
            }
        }

        private Object makeRequest(Object[] args) {
            if (args == null || args.length == 0) return request(null, new byte[0], null);
            if (args[0] instanceof HttpService) {
                byte[] raw = args.length > 1 ? toBytes(args[1]) : new byte[0];
                return request((HttpService) args[0], raw, null);
            }
            return request(null, toBytes(args[0]), null);
        }

        private Object makeResponse(Object[] args) {
            if (args == null || args.length == 0) return response(new byte[0], null);
            return response(toBytes(args[0]), null);
        }

        private Object makeHeader(Object[] args) {
            if (args.length == 1) {
                String s = String.valueOf(args[0]);
                int c = s.indexOf(':');
                return c < 0 ? new Hdr(s, "") : new Hdr(s.substring(0, c).trim(), s.substring(c + 1).trim());
            }
            if (args[0] instanceof byte[]) {
                return new Hdr(new String((byte[]) args[0], WIRE), new String((byte[]) args[1], WIRE));
            }
            return new Hdr(String.valueOf(args[0]), String.valueOf(args[1]));
        }

        private Object makeService(Object[] args) {
            String host = String.valueOf(args[0]);
            if (args.length == 1) {
                if (host.contains("://")) {
                    boolean sec = host.startsWith("https");
                    String rest = host.substring(host.indexOf("://") + 3);
                    int slash = rest.indexOf('/');
                    if (slash >= 0) rest = rest.substring(0, slash);
                    int colon = rest.indexOf(':');
                    if (colon >= 0) return new Svc(rest.substring(0, colon), parseInt(rest.substring(colon + 1), sec ? 443 : 80), sec);
                    return new Svc(rest, sec ? 443 : 80, sec);
                }
                return new Svc(host, 80, false);
            }
            if (args.length == 2) {
                boolean sec = Boolean.TRUE.equals(args[1]);
                return new Svc(host, sec ? 443 : 80, sec);
            }
            return new Svc(host, ((Number) args[1]).intValue(), Boolean.TRUE.equals(args[2]));
        }

        private Object makeAnnotations(Object[] args) {
            if (args == null || args.length == 0) return new Ann();
            if (args.length == 1 && args[0] instanceof HighlightColor) return new Ann(null, (HighlightColor) args[0]);
            if (args.length == 1) return new Ann(String.valueOf(args[0]), null);
            return new Ann(String.valueOf(args[0]), (HighlightColor) args[1]);
        }
    }

    /** First HttpRequest among the args (action builders take req in varying slots). */
    static HttpRequest requestArg(Object[] args) {
        if (args != null) for (Object a : args) if (a instanceof HttpRequest) return (HttpRequest) a;
        return null;
    }

    static HttpResponse responseArg(Object[] args) {
        if (args != null) for (Object a : args) if (a instanceof HttpResponse) return (HttpResponse) a;
        return null;
    }

    static Annotations annFrom(Object[] args) {
        if (args != null) for (Object a : args) if (a instanceof Annotations) return (Annotations) a;
        return new Ann();
    }

    /** A proxy for one of the many *Action result interfaces. */
    static Object action(Class<?> iface, HttpRequest req, HttpResponse resp, RequestAction ra, Annotations ann) {
        InvocationHandler h = (proxy, method, a) -> {
            switch (method.getName()) {
                case "equals": return proxy == (a == null ? null : a[0]);
                case "hashCode": return System.identityHashCode(proxy);
                case "toString": return "Action";
                case "request": return req;
                case "response": return resp;
                case "annotations": return ann;
                case "action": {
                    Class<?> rt = method.getReturnType();
                    if (rt == RequestAction.class) return ra == null ? RequestAction.CONTINUE : ra;
                    if (rt == ResponseAction.class) return ResponseAction.CONTINUE;
                    return defaultReturn(rt);
                }
                default: return defaultReturn(method.getReturnType());
            }
        };
        return Proxy.newProxyInstance(iface.getClassLoader(), new Class<?>[]{iface}, h);
    }

    // --- helpers -------------------------------------------------------------

    static byte[] toBytes(Object o) {
        if (o == null) return new byte[0];
        if (o instanceof byte[]) return (byte[]) o;
        if (o instanceof ByteArray) return ((ByteArray) o).getBytes();
        if (o instanceof int[]) {
            int[] in = (int[]) o;
            byte[] b = new byte[in.length];
            for (int i = 0; i < in.length; i++) b[i] = (byte) in[i];
            return b;
        }
        return String.valueOf(o).getBytes(WIRE);
    }

    static String str(Object[] args) {
        return (args == null || args.length == 0) ? "" : String.valueOf(args[0]);
    }

    static int parseInt(String s, int dflt) {
        try { return Integer.parseInt(s.trim()); } catch (Exception e) { return dflt; }
    }

    /** Safe default for an unimplemented method, so extensions don't NPE. */
    static Object defaultReturn(Class<?> ret) {
        if (ret == void.class || ret == Void.TYPE) return null;
        if (ret == boolean.class) return false;
        if (ret == char.class) return '\0';
        if (ret == byte.class || ret == short.class || ret == int.class) return 0;
        if (ret == long.class) return 0L;
        if (ret == float.class) return 0f;
        if (ret == double.class) return 0d;
        if (ret == String.class) return "";
        if (ret.isEnum()) {
            Object[] c = ret.getEnumConstants();
            return c != null && c.length > 0 ? c[0] : null;
        }
        if (ret == Optional.class) return Optional.empty();
        if (ret.isArray()) return java.lang.reflect.Array.newInstance(ret.getComponentType(), 0);
        if (Map.class.isAssignableFrom(ret)) return new java.util.HashMap<>();
        if (List.class.isAssignableFrom(ret) || java.util.Collection.class.isAssignableFrom(ret)) return new ArrayList<>();
        if (ret.isInterface()) {
            try {
                return Proxy.newProxyInstance(ret.getClassLoader(), new Class<?>[]{ret},
                        (p, m, a) -> defaultReturn(m.getReturnType()));
            } catch (Throwable t) { return null; }
        }
        return null;
    }
}
