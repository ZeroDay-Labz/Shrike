import { useCallback, useEffect, useRef, useState } from "react";
import type { ContentHit, DiscoveryEvent } from "../types";
import { api, events } from "../api";
import { Icon } from "./Icon";

/**
 * Content discovery: brute-force paths and files under a target to surface
 * unlinked endpoints (admin panels, backups, API routes, config files). Runs
 * off the built-in wordlist plus the tester's own words, filters soft-404s via
 * a learned baseline, and streams hits live. Scope-gated in the engine.
 * Keep-alive so a long run survives tab switches.
 */
export function Discovery() {
  const [baseUrl, setBaseUrl] = useState("");
  const [exts, setExts] = useState("");
  const [extraWords, setExtraWords] = useState("");
  const [running, setRunning] = useState(false);
  const [done, setDone] = useState(0);
  const [total, setTotal] = useState(0);
  const [hits, setHits] = useState<ContentHit[]>([]);
  const [baseline, setBaseline] = useState<string>("");
  const [err, setErr] = useState("");
  const [copied, setCopied] = useState(false);
  const copyTimer = useRef<number | null>(null);

  const onEvent = useCallback((ev: DiscoveryEvent) => {
    switch (ev.type) {
      case "baseline":
        setBaseline(
          ev.status == null
            ? "unstable server — reporting notable statuses only"
            : `not-found looks like ${ev.status}${ev.length != null ? ` (~${ev.length} bytes)` : ""}`,
        );
        break;
      case "found":
        setHits((prev) => {
          const next = [...prev, ev as ContentHit];
          next.sort((a, b) => a.path.localeCompare(b.path));
          return next;
        });
        break;
      case "progress":
        setDone(ev.done);
        setTotal(ev.total);
        break;
      case "finished":
        setRunning(false);
        break;
      case "error":
        setErr(ev.message);
        break;
    }
  }, []);

  useEffect(() => {
    const un = events.onDiscovery(onEvent);
    return () => {
      void un.then((f) => f());
    };
  }, [onEvent]);

  async function start() {
    const url = baseUrl.trim();
    if (!url) { setErr("enter a target URL, e.g. https://target.example"); return; }
    setErr("");
    setHits([]);
    setDone(0);
    setTotal(0);
    setBaseline("");
    const words = extraWords.split(/\r?\n/).map((w) => w.trim()).filter(Boolean);
    const extensions = exts.split(/[,\s]+/).map((e) => e.trim().replace(/^\./, "")).filter(Boolean);
    try {
      await api.contentDiscoveryStart(url, words, extensions);
      setRunning(true);
    } catch (e) {
      setErr(String(e));
    }
  }

  async function stop() {
    try { await api.contentDiscoveryStop(); } catch { /* ignore */ }
    setRunning(false);
  }

  function fullUrl(path: string): string {
    try {
      const u = new URL(baseUrl.trim());
      return `${u.protocol}//${u.host}${path}`;
    } catch {
      return path;
    }
  }

  async function copyAll() {
    const text = hits.map((h) => fullUrl(h.path)).join("\n");
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      if (copyTimer.current) window.clearTimeout(copyTimer.current);
      copyTimer.current = window.setTimeout(() => setCopied(false), 1400);
    } catch { /* ignore */ }
  }

  const pct = total > 0 ? Math.round((done / total) * 100) : 0;

  return (
    <div className="disco">
      <div className="disco-head">
        <div className="disco-title">
          <h2>Content discovery</h2>
          <span className="mut">Brute-force paths &amp; files to find what isn't linked. Scope-gated.</span>
        </div>
      </div>

      <div className="disco-form">
        <label className="disco-url">
          Target
          <input
            value={baseUrl}
            placeholder="https://target.example  (or https://target.example/app to scan under a path)"
            spellCheck={false}
            onChange={(e) => setBaseUrl(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !running && start()}
          />
        </label>
        <label className="disco-exts">
          Extensions
          <input value={exts} placeholder="php, bak, json, old" spellCheck={false}
            onChange={(e) => setExts(e.target.value)} />
        </label>
        <div className="disco-go">
          {running ? (
            <button className="btn" onClick={stop}><Icon name="pause" size={13} /> Stop</button>
          ) : (
            <button className="btn start" onClick={start}><Icon name="search" size={13} /> Start</button>
          )}
        </div>
      </div>

      <details className="disco-adv">
        <summary>Extra words <span className="mut">(one per line, added to the built-in list)</span></summary>
        <textarea rows={4} value={extraWords} spellCheck={false}
          placeholder={"custom-endpoint\ninternal-api\nbackup-2024"}
          onChange={(e) => setExtraWords(e.target.value)} />
      </details>

      {err && <div className="msg err">{err}</div>}

      <div className="disco-statusbar">
        {running && <span className="disco-run"><span className="run-dot" /> scanning…</span>}
        {total > 0 && (
          <span className="disco-prog">
            <span className="disco-bar"><span className="disco-fill" style={{ width: `${pct}%` }} /></span>
            {done}/{total}
          </span>
        )}
        {baseline && <span className="mut disco-baseline">{baseline}</span>}
        <span className="spacer" />
        <span className="disco-count">{hits.length} found</span>
        {hits.length > 0 && (
          <button className="btn ghost" onClick={copyAll}>{copied ? "Copied" : "Copy URLs"}</button>
        )}
      </div>

      {hits.length === 0 ? (
        <div className="hint">
          {running ? "scanning — hits appear here as they're found" : "enter a target in scope and press Start"}
        </div>
      ) : (
        <div className="disco-results">
          <table className="disco-table">
            <thead>
              <tr><th>Status</th><th>Path</th><th>Length</th><th>Words</th><th>Redirect</th></tr>
            </thead>
            <tbody>
              {hits.map((h, i) => (
                <tr key={i} title={fullUrl(h.path)} onClick={() => navigator.clipboard.writeText(fullUrl(h.path)).catch(() => {})}>
                  <td><span className={"disco-status " + statusClass(h.status)}>{h.status}</span></td>
                  <td className="mono">{h.path}</td>
                  <td className="mut">{h.length.toLocaleString()}</td>
                  <td className="mut">{h.words.toLocaleString()}</td>
                  <td className="mono mut disco-redir">{h.redirect ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function statusClass(status: number): string {
  if (status >= 200 && status < 300) return "s-2xx";
  if (status >= 300 && status < 400) return "s-3xx";
  if (status >= 400 && status < 500) return "s-4xx";
  return "s-5xx";
}
