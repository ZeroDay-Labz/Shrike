import { useCallback, useEffect, useMemo, useState } from "react";
import type { Confidence, Finding, FindingStatus, Severity } from "../types";
import { SEVERITIES } from "../types";
import { api, events } from "../api";

const CONFIDENCES: Confidence[] = ["tentative", "firm", "certain"];
const STATUSES: FindingStatus[] = ["open", "confirmed", "false_positive", "resolved"];
const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/**
 * Findings: the triage list. Each row is a recorded issue (operator-raised
 * today; the home for scanner output later). Edit severity/confidence/status,
 * notes and linked transactions, and export a JSON/HTML report.
 */
export function Findings(props: { onShowTransaction?: (id: number) => void }) {
  const [items, setItems] = useState<Finding[]>([]);
  const [selId, setSelId] = useState<number | undefined>();
  const [msg, setMsg] = useState("");

  const load = useCallback(async () => {
    try {
      const list = await api.findingsList();
      setItems(list);
      setMsg("");
    } catch (e) { setMsg(String(e)); }
  }, []);
  useEffect(() => { load(); }, [load]);

  // Live updates: scanners (and manual adds) emit `finding-added`.
  useEffect(() => {
    const un = events.onFinding((f) => {
      setItems((prev) => (prev.some((x) => x.id === f.id)
        ? prev.map((x) => (x.id === f.id ? f : x))
        : [f, ...prev]));
    });
    return () => { un.then((fn) => fn()); };
  }, []);

  const sorted = useMemo(
    () => [...items].sort((a, b) =>
      SEV_RANK[b.severity] - SEV_RANK[a.severity] || b.updated_at_ms - a.updated_at_ms),
    [items],
  );
  const sel = items.find((f) => f.id === selId);

  const create = useCallback(async () => {
    try {
      const f = await api.findingCreate({ title: "New finding", severity: "info" });
      setItems((prev) => [f, ...prev]);
      setSelId(f.id);
    } catch (e) { setMsg(String(e)); }
  }, []);

  // Patch one field; the backend returns the updated row.
  const patch = useCallback(async (id: number, field: Partial<Finding>) => {
    // optimistic
    setItems((prev) => prev.map((f) => (f.id === id ? { ...f, ...field } : f)));
    try {
      const updated = await api.findingUpdate(id, field);
      if (updated) setItems((prev) => prev.map((f) => (f.id === id ? updated : f)));
    } catch (e) { setMsg(String(e)); }
  }, []);

  const remove = useCallback(async (id: number) => {
    try {
      await api.findingDelete(id);
      setItems((prev) => prev.filter((f) => f.id !== id));
      setSelId((cur) => (cur === id ? undefined : cur));
    } catch (e) { setMsg(String(e)); }
  }, []);

  const exportReport = useCallback(async (format: "json" | "html") => {
    try {
      const body = await api.findingsReport(format);
      const mime = format === "html" ? "text/html" : "application/json";
      const blob = new Blob([body], { type: mime });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `shrike-findings.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) { setMsg(String(e)); }
  }, []);

  const counts = useMemo(() => {
    const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of items) c[f.severity]++;
    return c;
  }, [items]);

  return (
    <div className="findings">
      <div className="findings-head">
        <h2>Findings</h2>
        <div className="findings-summary">
          {SEVERITIES.map((s) => (
            <span key={s} className={"sev-pill sev-" + s} title={s}>
              <i /> {counts[s]}
            </span>
          ))}
        </div>
        <span className="spacer" />
        <button className="btn" onClick={() => exportReport("html")} disabled={!items.length}>Export HTML</button>
        <button className="btn" onClick={() => exportReport("json")} disabled={!items.length}>Export JSON</button>
        <button className="btn start" onClick={create}>New finding</button>
      </div>
      {msg && <div className="errbar">{msg}</div>}

      <div className="findings-body">
        <div className="findings-list">
          {sorted.length === 0 && <div className="hint">no findings yet — record one with “New finding”, or send a request here from the proxy</div>}
          {sorted.map((f) => (
            <button
              key={f.id}
              className={"finding-row" + (f.id === selId ? " on" : "")}
              onClick={() => setSelId(f.id)}
            >
              <span className={"sev-dot sev-" + f.severity} title={f.severity} />
              <span className="finding-row-title">{f.title || "(untitled)"}</span>
              {f.status !== "open" && <span className={"finding-status st-" + f.status}>{label(f.status)}</span>}
              {f.host && <span className="finding-row-host">{f.host}</span>}
            </button>
          ))}
        </div>

        <div className="findings-detail">
          {!sel ? (
            <div className="hint">select a finding to edit it</div>
          ) : (
            <div className="finding-edit">
              <input
                className="finding-title-input"
                value={sel.title}
                placeholder="title"
                onChange={(e) => patch(sel.id, { title: e.target.value })}
              />
              <div className="finding-selectors">
                <label>Severity
                  <select value={sel.severity} onChange={(e) => patch(sel.id, { severity: e.target.value as Severity })}>
                    {SEVERITIES.map((s) => <option key={s} value={s}>{label(s)}</option>)}
                  </select>
                </label>
                <label>Confidence
                  <select value={sel.confidence} onChange={(e) => patch(sel.id, { confidence: e.target.value as Confidence })}>
                    {CONFIDENCES.map((s) => <option key={s} value={s}>{label(s)}</option>)}
                  </select>
                </label>
                <label>Status
                  <select value={sel.status} onChange={(e) => patch(sel.id, { status: e.target.value as FindingStatus })}>
                    {STATUSES.map((s) => <option key={s} value={s}>{label(s)}</option>)}
                  </select>
                </label>
              </div>
              {(sel.host || sel.path) && (
                <div className="finding-loc">
                  {sel.host && <code>{sel.host}</code>}
                  {sel.path && <code>{sel.path}</code>}
                </div>
              )}
              <textarea
                className="finding-detail-input"
                value={sel.detail}
                placeholder="detail / evidence / reproduction…"
                onChange={(e) => patch(sel.id, { detail: e.target.value })}
              />
              {sel.transaction_ids.length > 0 && (
                <div className="finding-evidence">
                  <span>Evidence:</span>
                  {sel.transaction_ids.map((id) => (
                    <button
                      key={id}
                      className="link-chip"
                      onClick={() => props.onShowTransaction?.(id)}
                      title="show this transaction in the proxy"
                    >#{id}</button>
                  ))}
                </div>
              )}
              <div className="finding-actions">
                <span className="spacer" />
                <button className="btn stop" onClick={() => remove(sel.id)}>Delete</button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function label(s: string): string {
  return s.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}
