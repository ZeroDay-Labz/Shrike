import type { Header, RequestView, Service } from "./types";

export interface ParsedRequest {
  method: string;
  target: string;
  headers: Header[];
  body: string;
}

/** Parse an edited raw HTTP/1.1 request into parts for the sender. */
export function parseRaw(raw: string): ParsedRequest {
  const norm = raw.replace(/\r\n/g, "\n");
  const sep = norm.indexOf("\n\n");
  const head = sep >= 0 ? norm.slice(0, sep) : norm;
  const body = sep >= 0 ? norm.slice(sep + 2) : "";
  const lines = head.split("\n");
  const start = (lines.shift() ?? "").trim();
  const m = start.split(/\s+/);
  const method = (m[0] || "GET").toUpperCase();
  const target = m[1] || "/";
  const headers: Header[] = [];
  for (const line of lines) {
    if (!line.trim()) continue;
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    headers.push({ name: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() });
  }
  return { method, target, headers, body };
}

/** Render a captured request as an editable raw request (Host added if absent). */
export function buildRaw(r: RequestView): string {
  const hasHost = r.headers.some((h) => h.name.toLowerCase() === "host");
  const lines = [`${r.method} ${r.target} ${r.version || "HTTP/1.1"}`];
  if (!hasHost) {
    const dflt = (r.service.secure && r.service.port === 443) || (!r.service.secure && r.service.port === 80);
    lines.push(`Host: ${r.service.host}${dflt ? "" : ":" + r.service.port}`);
  }
  for (const h of r.headers) lines.push(`${h.name}: ${h.value}`);
  lines.push("");
  const body = r.body.is_text ? r.body.text ?? "" : "";
  return lines.join("\n") + "\n" + body;
}

export async function copyText(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    return;
  } catch { /* fall back */ }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand("copy"); } finally { document.body.removeChild(ta); }
}

/** Build a copy-pasteable curl command for a captured request. */
export function toCurl(r: RequestView): string {
  const parts = [`curl -i -x http://127.0.0.1:8080`, `-X ${r.method}`, `'${r.url}'`];
  for (const h of r.headers) {
    if (h.name.toLowerCase() === "content-length") continue;
    parts.push(`-H '${h.name}: ${h.value.replace(/'/g, "'\\''")}'`);
  }
  if (r.body.is_text && r.body.text) parts.push(`--data-raw '${r.body.text.replace(/'/g, "'\\''")}'`);
  return parts.join(" \\\n  ");
}

export interface RepeaterTab {
  id: number;
  name: string;
  service: Service;
  raw: string;
  sending: boolean;
  status?: number;
  durationMs?: number;
  responseView?: import("./types").ResponseView;
  error?: string;
}
