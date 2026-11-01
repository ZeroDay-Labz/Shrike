import { useEffect, useState } from "react";
import type { ConfigView } from "../types";
import { api } from "../api";
import { ScopeEditor } from "./ScopeEditor";
import { MatchReplaceEditor } from "./MatchReplaceEditor";

export function Settings(props: { config?: ConfigView; onSaved: (c: ConfigView) => void; onImported?: () => void }) {
  const [listen, setListen] = useState("127.0.0.1:8080");
  const [insecure, setInsecure] = useState(false);
  const [passthrough, setPassthrough] = useState("");
  // Proxy scope mode: "all" global proxy, "capture" record only in-scope, "block" 403 out-of-scope.
  const [scopeMode, setScopeMode] = useState<"all" | "capture" | "block">("all");
  const [chromiumPath, setChromiumPath] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [requireScope, setRequireScope] = useState(true);
  const [timeoutMs, setTimeoutMs] = useState(30000);
  const [historyMax, setHistoryMax] = useState(0);
  const [passiveScan, setPassiveScan] = useState(true);
  const [oobServer, setOobServer] = useState("");
  const [oobPublicIp, setOobPublicIp] = useState("");
  const [oobDnsBind, setOobDnsBind] = useState("0.0.0.0:53");
  const [oobHttpBind, setOobHttpBind] = useState("0.0.0.0:80");
  const [msg, setMsg] = useState("");
  const [importPath, setImportPath] = useState("");
  const [importing, setImporting] = useState(false);
  const [importMsg, setImportMsg] = useState("");

  useEffect(() => {
    if (props.config) {
      setListen(props.config.listen);
      setInsecure(props.config.insecure_upstream);
      setPassthrough(props.config.passthrough_hosts.join("\n"));
      setScopeMode(props.config.drop_out_of_scope ? "block" : props.config.capture_in_scope_only ? "capture" : "all");
      setChromiumPath(props.config.chromium_path ?? "");
      setGithubToken(props.config.github_token ?? "");
      setRequireScope(props.config.intruder_require_scope ?? true);
      setTimeoutMs(props.config.request_timeout_ms ?? 30000);
      setHistoryMax(props.config.history_max_rows ?? 0);
      setPassiveScan(props.config.passive_scan_enabled ?? true);
      setOobServer(props.config.oob_server ?? "");
      setOobPublicIp(props.config.oob_public_ip ?? "");
      setOobDnsBind(props.config.oob_dns_bind || "0.0.0.0:53");
      setOobHttpBind(props.config.oob_http_bind || "0.0.0.0:80");
    }
  }, [props.config]);

  async function save() {
    if (!props.config) return;
    setMsg("");
    try {
      const next: ConfigView = {
        ...props.config,
        listen,
        insecure_upstream: insecure,
        passthrough_hosts: passthrough.split(/\s+/).map((s) => s.trim()).filter(Boolean),
        drop_out_of_scope: scopeMode === "block",
        capture_in_scope_only: scopeMode === "capture",
        chromium_path: chromiumPath.trim(),
        github_token: githubToken.trim(),
        intruder_require_scope: requireScope,
        request_timeout_ms: timeoutMs,
        history_max_rows: historyMax,
        passive_scan_enabled: passiveScan,
        oob_server: oobServer.trim(),
        oob_public_ip: oobPublicIp.trim(),
        oob_dns_bind: oobDnsBind.trim(),
        oob_http_bind: oobHttpBind.trim(),
      };
      const saved = await api.configSet(next);
      props.onSaved(saved);
      setMsg("Saved. The proxy was restarted if it was running.");
    } catch (e) { setMsg(String(e)); }
  }

  async function runImport() {
    const p = importPath.trim();
    if (!p) { setImportMsg("enter the path to an XML item export"); return; }
    setImporting(true); setImportMsg("");
    try {
      const n = await api.importTraffic(p);
      setImportMsg(`Imported ${n} request${n === 1 ? "" : "s"} into history.`);
      setImportPath("");
      props.onImported?.();
    } catch (e) { setImportMsg(String(e)); }
    finally { setImporting(false); }
  }

  return (
    <div className="settings">
      <div className="settings-head">
        <h2>Settings</h2>
        <span className="mut">Proxy, engagement safety, integrations and data — grouped. Changes apply on Save; the proxy restarts if it was running.</span>
      </div>

      <div className="settings-grid">
        <section className="settings-card">
          <h3>Proxy listener</h3>
          <label>Listen address
            <input value={listen} onChange={(e) => setListen(e.target.value)} />
          </label>
          <label className="row">
            <input type="checkbox" checked={insecure} onChange={(e) => setInsecure(e.target.checked)} />
            Accept invalid upstream certificates (lab targets only)
          </label>
          <label>Passthrough hosts (one per line; a leading dot matches subdomains)
            <textarea rows={4} value={passthrough} onChange={(e) => setPassthrough(e.target.value)} />
          </label>
        </section>

        <section className="settings-card">
          <h3>Scope &amp; engagement safety</h3>
          <fieldset className="radio-group">
            <legend>Proxy scope mode</legend>
            <label className="radio">
              <input type="radio" name="scopemode" checked={scopeMode === "all"} onChange={() => setScopeMode("all")} />
              <span><b>Global proxy</b> — intercept and record all traffic (default).</span>
            </label>
            <label className="radio">
              <input type="radio" name="scopemode" checked={scopeMode === "capture"} onChange={() => setScopeMode("capture")} />
              <span><b>Capture in-scope only</b> — everything still browses normally, but only requests to the target scope below are recorded. Best for staying clean during an engagement. (With no scope rules, everything is captured.)</span>
            </label>
            <label className="radio">
              <input type="radio" name="scopemode" checked={scopeMode === "block"} onChange={() => setScopeMode("block")} />
              <span><b>Block out-of-scope</b> — refuse anything outside the scope with 403. Enforced in the Rust core. With no scope rules, everything is refused.</span>
            </label>
          </fieldset>
          <label className="row">
            <input type="checkbox" checked={requireScope} onChange={(e) => setRequireScope(e.target.checked)} />
            Require target scope for Intruder &amp; race attacks. Enforced in the Rust core: out-of-scope requests are blocked and never sent. With an empty scope, an attack is refused. Recommended on.
          </label>
          <label className="row">
            <input type="checkbox" checked={passiveScan} onChange={(e) => setPassiveScan(e.target.checked)} />
            Passive scanning — inspect captured traffic and raise Findings (security headers, cookie flags, reflected input, info leaks). Sends no extra requests.
          </label>
        </section>

        <section className="settings-card">
          <h3>Integrations</h3>
          <label>Integrated browser path (optional)
            <input value={chromiumPath} placeholder="leave blank to use the bundled Firefox (or a system Firefox/Chromium)"
              onChange={(e) => setChromiumPath(e.target.value)} />
          </label>
          <label>GitHub token for the extension catalog (optional)
            <input type="password" value={githubToken} placeholder="lifts GitHub's 60-requests/hour limit when browsing/installing"
              onChange={(e) => setGithubToken(e.target.value)} />
          </label>
        </section>

        <section className="settings-card">
          <h3>Out-of-band interactions (OAST)</h3>
          <p className="mut">
            A self-hosted DNS + HTTP listener for confirming blind vulnerabilities. Point a wildcard
            DNS record (<code>*.your-domain</code>) at this host's public IP. Start/stop it and watch
            callbacks in the Interactions tab.
          </p>
          <label>Payload domain
            <input value={oobServer} placeholder="oast.your-domain.com"
              onChange={(e) => setOobServer(e.target.value)} />
          </label>
          <label>Public IP (answer for A queries)
            <input value={oobPublicIp} placeholder="203.0.113.10 — this host as targets reach it"
              onChange={(e) => setOobPublicIp(e.target.value)} />
          </label>
          <label>DNS listener bind
            <input value={oobDnsBind} placeholder="0.0.0.0:53"
              onChange={(e) => setOobDnsBind(e.target.value)} />
          </label>
          <label>HTTP listener bind
            <input value={oobHttpBind} placeholder="0.0.0.0:80"
              onChange={(e) => setOobHttpBind(e.target.value)} />
          </label>
          <p className="mut">Ports 53/80 need privilege — use high ports (e.g. 5353 / 8080) for an unprivileged run.</p>
        </section>

        <section className="settings-card">
          <h3>Performance &amp; data</h3>
          <label>Request timeout (ms) — Repeater &amp; Intruder
            <input value={timeoutMs} inputMode="numeric"
              onChange={(e) => setTimeoutMs(Math.max(1000, Number(e.target.value) || 30000))} />
          </label>
          <label>History retention — keep newest N requests (0 = unlimited)
            <input value={historyMax} inputMode="numeric"
              onChange={(e) => setHistoryMax(Math.max(0, Number(e.target.value) || 0))} />
          </label>
          <p className="mut">Data directory: {props.config?.data_dir}</p>
        </section>
      </div>

      <div className="settings-save row">
        <button className="btn start" onClick={save}>Save settings</button>
        {msg && <span className="msg">{msg}</span>}
      </div>

      <hr className="sep" />
      <h2>Import traffic</h2>
      <p className="mut">
        Import an <b>XML item export</b> from another proxy tool into history (its "Save selected
        items" / export-history feature). Other tools' binary project files aren't supported — export items as XML first.
      </p>
      <div className="bapp-import">
        <input placeholder="/path/to/items-export.xml" value={importPath}
          onChange={(e) => setImportPath(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && runImport()} />
        <button className="btn start" disabled={importing} onClick={runImport}>{importing ? "Importing…" : "Import"}</button>
      </div>
      {importMsg && <div className="msg">{importMsg}</div>}

      <hr className="sep" />
      <ScopeEditor />
      <hr className="sep" />
      <MatchReplaceEditor />
    </div>
  );
}
