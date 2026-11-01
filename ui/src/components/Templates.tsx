import { useCallback, useEffect, useState } from "react";
import type { TemplateEvent, TemplateMatch, TemplateSummary } from "../types";
import { api, events } from "../api";
import { Icon } from "./Icon";

/**
 * Templated scanner: runs data-driven detection templates (matchers/extractors)
 * against a target. Built-in templates ship with Shrike; the tester can add
 * their own JSON templates in the data directory's templates/ folder. Matches
 * stream here and are also filed as Findings. Keep-alive so a run survives a
 * tab switch. Scope-gated in the engine.
 */
export function Templates() {
  const [list, setList] = useState<TemplateSummary[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [baseUrl, setBaseUrl] = useState("");
  const [running, setRunning] = useState(false);
  const [done, setDone] = useState(0);
  const [total, setTotal] = useState(0);
  const [matches, setMatches] = useState<TemplateMatch[]>([]);
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    try {
      const l = await api.templatesList();
      setList(l);
      setSelected(new Set(l.map((t) => t.id))); // all selected by default
    } catch (e) {
      setErr(String(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const onEvent = useCallback((ev: TemplateEvent) => {
    switch (ev.type) {
      case "match":
        setMatches((prev) => [...prev, ev as TemplateMatch]);
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
    const un = events.onTemplate(onEvent);
    return () => {
      void un.then((f) => f());
    };
  }, [onEvent]);

  function toggle(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function run() {
    const url = baseUrl.trim();
    if (!url) { setErr("enter a target URL, e.g. https://target.example"); return; }
    if (selected.size === 0) { setErr("select at least one template"); return; }
    setErr("");
    setMatches([]);
    setDone(0);
    setTotal(0);
    try {
      await api.templatesScanStart(url, [...selected]);
      setRunning(true);
    } catch (e) {
      setErr(String(e));
    }
  }

  async function stop() {
    try { await api.templatesScanStop(); } catch { /* ignore */ }
    setRunning(false);
  }

  const pct = total > 0 ? Math.round((done / total) * 100) : 0;
  const allOn = list.length > 0 && selected.size === list.length;

  return (
    <div className="tpl">
      <div className="tpl-head">
        <div className="tpl-title">
          <h2>Templates</h2>
          <span className="mut">Data-driven detections — run matchers/extractors against a target.</span>
        </div>
        <button className="btn ghost" onClick={load} title="Reload templates from disk">Reload</button>
      </div>

      <div className="tpl-form">
        <input
          className="tpl-url"
          value={baseUrl}
          placeholder="https://target.example"
          spellCheck={false}
          onChange={(e) => setBaseUrl(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && !running && run()}
        />
        {running ? (
          <button className="btn" onClick={stop}><Icon name="pause" size={13} /> Stop</button>
        ) : (
          <button className="btn start" onClick={run}><Icon name="bolt" size={13} /> Run ({selected.size})</button>
        )}
      </div>

      {err && <div className="msg err">{err}</div>}

      <div className="tpl-statusbar">
        {total > 0 && (
          <span className="tpl-prog">
            <span className="tpl-bar"><span className="tpl-fill" style={{ width: `${pct}%` }} /></span>
            {done}/{total}
          </span>
        )}
        <span className="tpl-matched">{matches.length} match{matches.length === 1 ? "" : "es"}</span>
        <span className="mut">· filed to Findings</span>
      </div>

      <div className="tpl-body">
        <div className="tpl-list">
          <div className="tpl-list-bar">
            <label className="tpl-selall">
              <input type="checkbox" checked={allOn}
                onChange={() => setSelected(allOn ? new Set() : new Set(list.map((t) => t.id)))} />
              {list.length} templates
            </label>
          </div>
          <div className="tpl-list-scroll">
            {list.map((t) => (
              <label key={t.id} className="tpl-item" title={t.description}>
                <input type="checkbox" checked={selected.has(t.id)} onChange={() => toggle(t.id)} />
                <span className={"tpl-sev sev-" + sevKey(t.severity)}>{sevKey(t.severity)}</span>
                <span className="tpl-name">{t.name}</span>
                {!t.builtin && <span className="tpl-user" title="Loaded from your templates folder">user</span>}
                <span className="tpl-tags">{t.tags.slice(0, 3).map((tag) => <span key={tag} className="tpl-tag">{tag}</span>)}</span>
              </label>
            ))}
            {list.length === 0 && <div className="hint">no templates loaded</div>}
          </div>
          <p className="mut tpl-hint">Drop <code>.json</code> templates in your data dir's <code>templates/</code> folder, then Reload.</p>
        </div>

        <div className="tpl-matches">
          {matches.length === 0 ? (
            <div className="hint">{running ? "scanning — matches appear here" : "select templates, enter a target, and Run"}</div>
          ) : (
            <table className="tpl-match-table">
              <thead>
                <tr><th>Severity</th><th>Template</th><th>Path</th><th>Extracted</th></tr>
              </thead>
              <tbody>
                {matches.map((m, i) => (
                  <tr key={i}>
                    <td><span className={"tpl-sev sev-" + sevKey(m.severity)}>{sevKey(m.severity)}</span></td>
                    <td>{m.name}</td>
                    <td className="mono">{m.path}</td>
                    <td className="mono mut">{m.extracted.join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}

function sevKey(s: string): string {
  const k = (s || "info").toLowerCase();
  return ["critical", "high", "medium", "low", "info"].includes(k) ? k : "info";
}
