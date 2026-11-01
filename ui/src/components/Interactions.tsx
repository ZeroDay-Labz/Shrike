import { useCallback, useEffect, useRef, useState } from "react";
import type { OobInteraction, OobStatus } from "../types";
import { api, events } from "../api";
import { Icon } from "./Icon";

/**
 * Out-of-band interactions (OAST). Shows the self-hosted DNS + HTTP listener's
 * status, mints payloads to inject into probes, and streams every callback the
 * target makes to the tester's domain — the signal that confirms blind SSRF,
 * blind XSS, blind SQLi and OOB RCE. Mounted keep-alive so callbacks are never
 * missed while the tester is on another tab.
 */
export function Interactions(props: { onGoToSettings: () => void }) {
  const [status, setStatus] = useState<OobStatus>();
  const [hits, setHits] = useState<OobInteraction[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [lastPayload, setLastPayload] = useState<string>("");
  const [copied, setCopied] = useState("");
  const copyTimer = useRef<number | null>(null);

  const refresh = useCallback(async () => {
    try {
      setStatus(await api.oobStatus());
      setHits(await api.oobInteractions());
    } catch (e) {
      setErr(String(e));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const un = events.onOob((hit) => setHits((prev) => [...prev, hit]));
    return () => {
      void un.then((f) => f());
    };
  }, [refresh]);

  // Keep the status's interaction count honest as live hits stream in.
  useEffect(() => {
    setStatus((s) => (s ? { ...s, interactions: hits.length } : s));
  }, [hits.length]);

  async function start() {
    setBusy(true);
    setErr("");
    try {
      setStatus(await api.oobStart());
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function stop() {
    setBusy(true);
    setErr("");
    try {
      setStatus(await api.oobStop());
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  function flashCopied(what: string) {
    setCopied(what);
    if (copyTimer.current) window.clearTimeout(copyTimer.current);
    copyTimer.current = window.setTimeout(() => setCopied(""), 1400);
  }

  async function copy(text: string, what: string) {
    try {
      await navigator.clipboard.writeText(text);
      flashCopied(what);
    } catch {
      /* clipboard denied — ignore */
    }
  }

  async function generate() {
    setErr("");
    try {
      const h = await api.oobGenerate();
      setLastPayload(h.payload_host);
      await copy(h.payload_host, "payload");
    } catch (e) {
      setErr(String(e));
    }
  }

  const running = !!status?.running;
  const sel = selected != null ? hits[selected] : undefined;

  return (
    <div className="oob">
      <div className="oob-head">
        <div className="oob-title">
          <span className={"run-dot" + (running ? "" : " off")} />
          <h2>Interactions</h2>
          <span className="mut">
            Out-of-band callbacks — the proof that a blind payload fired.
          </span>
        </div>
        <div className="oob-actions">
          {running ? (
            <>
              <button className="btn start" onClick={generate} title="Mint a payload and copy it">
                <Icon name="send" size={13} /> Generate payload
              </button>
              <button className="btn" disabled={busy} onClick={stop}>Stop server</button>
            </>
          ) : (
            <button className="btn start" disabled={busy} onClick={start}>Start server</button>
          )}
        </div>
      </div>

      {err && <div className="msg err">{err}</div>}

      {running ? (
        <div className="oob-status">
          <StatusCell label="Payload domain" value={status?.domain || "—"} />
          <StatusCell label="DNS listener" value={status?.dns_addr || "—"} />
          <StatusCell label="HTTP listener" value={status?.http_addr || "—"} />
          <StatusCell label="Answers A with" value={status?.public_ip || "(none)"} />
          {lastPayload && (
            <div className="oob-payload">
              <span className="mut">Last payload</span>
              <code onClick={() => copy(lastPayload, "payload")} title="Click to copy">{lastPayload}</code>
            </div>
          )}
          {copied && <span className="oob-copied">Copied {copied}</span>}
        </div>
      ) : (
        <div className="oob-setup">
          <p>
            The interaction server is a self-hosted DNS + HTTP listener on <b>your</b> machine.
            Point a wildcard DNS record (<code>*.your-domain</code>) at this host's public IP,
            set the domain and IP in Settings, then start the server. Each generated payload is a
            unique <code>&lt;token&gt;.your-domain</code> — inject it anywhere a target might
            reach out, and its DNS/HTTP callback shows up here, correlated to that token.
          </p>
          <p className="mut">
            Port 53 and 80 need privilege; for an unprivileged run set higher bind ports in Settings
            (e.g. <code>0.0.0.0:5353</code> / <code>0.0.0.0:8080</code>) and forward to them.
          </p>
          <button className="btn" onClick={props.onGoToSettings}>Open Settings →</button>
        </div>
      )}

      <div className="oob-log">
        <div className="oob-log-bar">
          <span className="oob-count">{hits.length} interaction{hits.length === 1 ? "" : "s"}</span>
          {hits.length > 0 && (
            <button className="btn ghost" onClick={() => { setHits([]); setSelected(null); }}>Clear view</button>
          )}
        </div>
        {hits.length === 0 ? (
          <div className="hint">
            {running ? "Waiting for callbacks — generate a payload and inject it into a target." : "Start the server to capture callbacks."}
          </div>
        ) : (
          <div className="oob-split">
            <table className="oob-table">
              <thead>
                <tr><th>Type</th><th>Source</th><th>Token</th><th>Time</th><th>Detail</th></tr>
              </thead>
              <tbody>
                {hits.map((h, i) => (
                  <tr key={i} className={i === selected ? "sel" : ""} onClick={() => setSelected(i)}>
                    <td><span className={"oob-kind k-" + h.kind}>{h.kind.toUpperCase()}</span></td>
                    <td className="mono">{h.source}</td>
                    <td className="mono">{h.correlation_id || "—"}</td>
                    <td className="mut">{new Date(h.at_ms).toLocaleTimeString()}</td>
                    <td className="oob-detail-cell mono">{h.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {sel && (
              <div className="oob-detail">
                <div className="oob-detail-row"><span className="mut">Type</span><b>{sel.kind.toUpperCase()}</b></div>
                <div className="oob-detail-row"><span className="mut">Source</span><span className="mono">{sel.source}</span></div>
                <div className="oob-detail-row"><span className="mut">Token</span><span className="mono">{sel.correlation_id || "—"}</span></div>
                <div className="oob-detail-row"><span className="mut">When</span>{new Date(sel.at_ms).toLocaleString()}</div>
                <div className="oob-detail-row col"><span className="mut">Detail</span><pre className="mono">{sel.detail}</pre></div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function StatusCell(props: { label: string; value: string }) {
  return (
    <div className="oob-cell">
      <span className="mut">{props.label}</span>
      <span className="mono">{props.value}</span>
    </div>
  );
}
