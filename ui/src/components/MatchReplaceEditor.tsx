import { useEffect, useState } from "react";
import type { MatchReplacePart, MatchReplaceRule } from "../types";
import { api } from "../api";

const PARTS: { value: MatchReplacePart; label: string }[] = [
  { value: "request_header", label: "request header" },
  { value: "request_body", label: "request body" },
  { value: "response_header", label: "response header" },
  { value: "response_body", label: "response body" },
];

const blank = (): MatchReplaceRule => ({
  enabled: true, name: "", part: "request_header", is_regex: false, match: "", replace: "",
});

/** Match & replace rules. Applied in the Rust proxy handler; this edits the persisted list. */
export function MatchReplaceEditor() {
  const [rules, setRules] = useState<MatchReplaceRule[]>([]);
  const [dirty, setDirty] = useState(false);
  const [msg, setMsg] = useState("");

  useEffect(() => { api.matchReplaceGet().then(setRules).catch((e) => setMsg(String(e))); }, []);

  function update(i: number, patch: Partial<MatchReplaceRule>) {
    setRules((r) => r.map((x, j) => (j === i ? { ...x, ...patch } : x)));
    setDirty(true);
  }
  function remove(i: number) { setRules((r) => r.filter((_, j) => j !== i)); setDirty(true); }
  function add() { setRules((r) => [...r, blank()]); setDirty(true); }

  async function save() {
    setMsg("");
    try {
      const cleaned = rules.filter((r) => r.match.length > 0);
      const saved = await api.matchReplaceSet(cleaned);
      setRules(saved); setDirty(false);
      setMsg(`Saved ${saved.length} rule${saved.length === 1 ? "" : "s"}. Applied live to the proxy.`);
    } catch (e) { setMsg("Rejected: " + String(e)); }
  }

  return (
    <div className="scope mr">
      <h2>Match &amp; replace</h2>
      <p className="mut">
        Rewrite requests and responses as they pass through the proxy. Each rule matches a
        literal string or, with <i>regex</i> ticked, a regular expression (use <code>$1</code> for
        capture groups in the replacement). A header rule matches the whole <code>Name: Value</code>{" "}
        line; replacing it with nothing removes the header. <code>Content-Length</code> is recomputed
        automatically.
      </p>

      <div className="mr-table">
        <div className="mr-head">
          <span>on</span><span>part</span><span>match</span><span>replace</span><span>regex</span><span />
        </div>
        {rules.map((r, i) => (
          <div className="mr-row" key={i}>
            <input type="checkbox" checked={r.enabled} onChange={(e) => update(i, { enabled: e.target.checked })} />
            <select value={r.part} onChange={(e) => update(i, { part: e.target.value as MatchReplacePart })}>
              {PARTS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
            </select>
            <input placeholder={r.is_regex ? "^User-Agent:.*$" : "User-Agent: curl/8.0"} value={r.match}
              onChange={(e) => update(i, { match: e.target.value })} />
            <input placeholder="User-Agent: Shrike" value={r.replace}
              onChange={(e) => update(i, { replace: e.target.value })} />
            <input type="checkbox" checked={r.is_regex} onChange={(e) => update(i, { is_regex: e.target.checked })} />
            <button className="link" onClick={() => remove(i)} title="remove">✕</button>
          </div>
        ))}
      </div>
      <div className="row">
        <button className="btn" onClick={add}>+ rule</button>
        <span className="spacer" />
        <button className="btn start" disabled={!dirty} onClick={save}>Save rules</button>
      </div>
      {msg && <div className="msg">{msg}</div>}
    </div>
  );
}
