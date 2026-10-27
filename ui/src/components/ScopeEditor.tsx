import { useEffect, useState } from "react";
import type { ScopeRule } from "../types";
import { api } from "../api";

const blank = (): ScopeRule => ({ enabled: true, kind: "include", host: "", port: null, path: null, is_regex: false });

/** Target scope rules. Enforced in the Rust core; this just edits the persisted list. */
export function ScopeEditor() {
  const [rules, setRules] = useState<ScopeRule[]>([]);
  const [dirty, setDirty] = useState(false);
  const [msg, setMsg] = useState("");
  const [probe, setProbe] = useState("");
  const [probeResult, setProbeResult] = useState<string>("");

  useEffect(() => { api.scopeGet().then(setRules).catch((e) => setMsg(String(e))); }, []);

  function update(i: number, patch: Partial<ScopeRule>) {
    setRules((r) => r.map((x, j) => (j === i ? { ...x, ...patch } : x)));
    setDirty(true);
  }
  function remove(i: number) { setRules((r) => r.filter((_, j) => j !== i)); setDirty(true); }
  function add(kind: ScopeRule["kind"]) { setRules((r) => [...r, { ...blank(), kind }]); setDirty(true); }

  async function save() {
    setMsg("");
    try {
      const cleaned = rules
        .map((r) => ({ ...r, host: r.host.trim(), path: r.path?.trim() || null }))
        .filter((r) => r.host.length > 0);
      const saved = await api.scopeSet(cleaned);
      setRules(saved); setDirty(false);
      setMsg(`Saved ${saved.length} rule${saved.length === 1 ? "" : "s"}. Applied live to the proxy.`);
    } catch (e) { setMsg("Rejected: " + String(e)); }
  }

  async function check() {
    if (!probe.trim()) return;
    try { setProbeResult((await api.scopeCheck(probe.trim())) ? "IN scope" : "out of scope"); }
    catch (e) { setProbeResult(String(e)); }
  }

  const includes = rules.filter((r) => r.enabled && r.kind === "include").length;

  return (
    <div className="scope">
      <h2>Target scope</h2>
      <p className="mut">
        A request is in scope when it matches an enabled <b>include</b> rule and no enabled <b>exclude</b> rule.
        Hosts: exact <code>example.com</code>, or <code>.example.com</code> for the domain and all subdomains; tick
        <i> regex</i> to match host/path with regular expressions. With no include rules, nothing is in scope.
      </p>
      {includes === 0 && <div className="warnbar">No enabled include rules — nothing is in scope. Automated tools will refuse to run, and "refuse out-of-scope requests" would block everything.</div>}

      <div className="scope-table">
        <div className="scope-head">
          <span>on</span><span>kind</span><span>host</span><span>port</span><span>path</span><span>regex</span><span />
        </div>
        {rules.map((r, i) => (
          <div className="scope-row" key={i}>
            <input type="checkbox" checked={r.enabled} onChange={(e) => update(i, { enabled: e.target.checked })} />
            <select value={r.kind} onChange={(e) => update(i, { kind: e.target.value as ScopeRule["kind"] })}>
              <option value="include">include</option><option value="exclude">exclude</option>
            </select>
            <input placeholder={r.is_regex ? "^(dev|stage)\\.example\\.com$" : ".example.com"} value={r.host}
              onChange={(e) => update(i, { host: e.target.value })} />
            <input placeholder="any" value={r.port ?? ""} inputMode="numeric"
              onChange={(e) => update(i, { port: e.target.value ? Number(e.target.value) : null })} />
            <input placeholder={r.is_regex ? "^/api/" : "/api/ (prefix)"} value={r.path ?? ""}
              onChange={(e) => update(i, { path: e.target.value || null })} />
            <input type="checkbox" checked={r.is_regex} onChange={(e) => update(i, { is_regex: e.target.checked })} />
            <button className="link" onClick={() => remove(i)} title="remove">✕</button>
          </div>
        ))}
      </div>
      <div className="row">
        <button className="btn" onClick={() => add("include")}>+ include</button>
        <button className="btn" onClick={() => add("exclude")}>+ exclude</button>
        <span className="spacer" />
        <button className="btn start" disabled={!dirty} onClick={save}>Save scope</button>
      </div>
      {msg && <div className="msg">{msg}</div>}

      <div className="row probe">
        <input placeholder="https://host/path — test a URL against the saved scope" value={probe}
          onChange={(e) => setProbe(e.target.value)} onKeyDown={(e) => e.key === "Enter" && check()} />
        <button className="btn" onClick={check}>Check</button>
        {probeResult && <span className={"pill " + (probeResult.startsWith("IN") ? "live" : "idle")}>{probeResult}</span>}
      </div>
    </div>
  );
}
