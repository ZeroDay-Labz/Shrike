import type { BodyView, Header, RequestView, ResponseView } from "./types";

export function humanBytes(n: number): string {
  const units = ["B", "kB", "MB", "GB", "TB"];
  let v = n, i = 0;
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
  return i === 0 ? `${n} B` : `${v.toFixed(1)} ${units[i]}`;
}

/** Wall-clock time of day, to the second (fits a narrow table column). */
export function timeShort(ms: number): string {
  if (!ms) return "";
  return new Date(ms).toLocaleTimeString([], { hour12: false });
}

/** Full local date and time with milliseconds, for tooltips. */
export function timeFull(ms: number): string {
  if (!ms) return "";
  const d = new Date(ms);
  return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour12: false }) + "." +
    String(d.getMilliseconds()).padStart(3, "0");
}

/** A compact label for a media type: `application/json; charset=utf-8` → `json`. */
export function shortMime(mime?: string | null): string {
  if (!mime) return "";
  const base = mime.split(";")[0].trim().toLowerCase();
  const known: Record<string, string> = {
    "text/html": "html", "application/xhtml+xml": "html", "text/plain": "text",
    "text/css": "css", "application/javascript": "js", "text/javascript": "js",
    "application/x-www-form-urlencoded": "form", "multipart/form-data": "multipart",
    "application/octet-stream": "binary", "image/svg+xml": "svg",
  };
  if (known[base]) return known[base];
  if (base.endsWith("+json") || base.endsWith("/json")) return "json";
  if (base.endsWith("+xml") || base.endsWith("/xml")) return "xml";
  const sub = base.split("/")[1] ?? base;
  return sub.replace(/^x-/, "");
}

/** Raw bytes of a body: decode base64, or UTF-8 encode the text. */
export function bodyBytes(b: BodyView): Uint8Array {
  if (b.base64 != null) {
    const bin = atob(b.base64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  return new TextEncoder().encode(b.text ?? "");
}

function headerLines(headers: Header[]): string {
  return headers.map((h) => `${h.name}: ${h.value}`).join("\r\n");
}

export function rawRequest(r: RequestView): string {
  const head = `${r.method} ${r.target} ${r.version}\r\n${headerLines(r.headers)}\r\n\r\n`;
  return head + bodyText(r.body);
}

export function rawResponse(r: ResponseView): string {
  const head = `${r.version} ${r.status} ${r.reason}\r\n${headerLines(r.headers)}\r\n\r\n`;
  return head + bodyText(r.body);
}

function bodyText(b: BodyView): string {
  if (b.is_text) return b.text ?? "";
  return b.base64 ? `<${b.len} bytes of binary; see Hex>` : "";
}

export function prettyBody(b: BodyView, mime?: string): string {
  const text = b.is_text ? (b.text ?? "") : "";
  if (!text) return bodyText(b);
  const m = (mime ?? "").toLowerCase();
  if (m.includes("json") || looksJson(text)) {
    try { return JSON.stringify(JSON.parse(text), null, 2); } catch { /* fall through */ }
  }
  return text;
}

function looksJson(s: string): boolean {
  const t = s.trim();
  return t.startsWith("{") || t.startsWith("[");
}

export function hexDump(bytes: Uint8Array, max = 64 * 1024): string {
  const n = Math.min(bytes.length, max);
  const lines: string[] = [];
  for (let off = 0; off < n; off += 16) {
    const slice = bytes.subarray(off, Math.min(off + 16, n));
    const hex = Array.from(slice).map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(slice).map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${off.toString(16).padStart(8, "0")}  ${hex.padEnd(16 * 3 - 1, " ")}  ${ascii}`);
  }
  if (bytes.length > n) lines.push(`… ${humanBytes(bytes.length - n)} more`);
  return lines.join("\n");
}

export function statusClass(status?: number): string {
  if (status == null) return "s-none";
  if (status < 200) return "s-1xx";
  if (status < 300) return "s-2xx";
  if (status < 400) return "s-3xx";
  if (status < 500) return "s-4xx";
  return "s-5xx";
}
