import { useCallback, useEffect, useMemo, useState } from "react";
import type { ScopeRule, SiteNode, TransactionView } from "../types";
import { api, events } from "../api";
import { MessageViewer } from "./MessageViewer";
import { SplitPane } from "./SplitPane";
import { Icon } from "./Icon";
import { statusClass } from "../util";

interface HostGroup {
  key: string;
  host: string;
  port: number;
  secure: boolean;
  origin: string;
  nodes: SiteNode[];
}

function group(nodes: SiteNode[]): HostGroup[] {
  const map = new Map<string, HostGroup>();
  for (const n of nodes) {
    const key = `${n.secure ? "https" : "http"}://${n.host}:${n.port}`;
    let g = map.get(key);
    if (!g) {
      const origin = n.secure
        ? `https://${n.host}${n.port === 443 ? "" : ":" + n.port}`
        : `http://${n.host}${n.port === 80 ? "" : ":" + n.port}`;
      g = { key, host: n.host, port: n.port, secure: n.secure, origin, nodes: [] };
      map.set(key, g);
    }
    g.nodes.push(n);
  }
  return [...map.values()].sort((a, b) => a.origin.localeCompare(b.origin));
}

/** Is `host` covered by an enabled include rule? (exact or leading-dot suffix) */
function hostInScope(host: string, rules: ScopeRule[]): boolean {
  const h = host.toLowerCase();
  return rules.some((r) => {
    if (!r.enabled || r.kind !== "include" || r.is_regex) return false;
    const rh = r.host.toLowerCase();
    if (rh.startsWith(".")) return h === rh.slice(1) || h.endsWith(rh);
    return h === rh;
  });
}

const includeRule = (host: string): ScopeRule =>
  ({ enabled: true, kind: "include", host, port: null, path: null, is_regex: false });

/** Site map: history as a host→path tree, where selecting a host sets the engagement scope. */
export function Target(props: {
  onContextMenu: (e: React.MouseEvent, node: SiteNode) => void;
}) {
  const [nodes, setNodes] = useState<SiteNode[]>([]);
  const [rules, setRules] = useState<ScopeRule[]>([]);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [selected, setSelected] = useState<SiteNode>();
  const [detail, setDetail] = useState<TransactionView>();
  const [msg, setMsg] = useState("");
  const [seed, setSeed] = useState("");
  const [crawling, setCrawling] = useState(false);
  const [crawlStat, setCrawlStat] = useState<{ visited: number; queued: number } | null>(null);

  const load = useCallback(async () => {
    try { setNodes(await api.siteMap()); setMsg(""); }
    catch (e) { setMsg(String(e)); }
  }, []);
  const loadScope = useCallback(async () => {
    try { setRules(await api.scopeGet()); } catch { /* ignore */ }
  }, []);
  useEffect(() => { load(); loadScope(); }, [load, loadScope]);

  useEffect(() => {
    if (!selected) { setDetail(undefined); return; }
    api.historyGet(selected.id).then((d) => setDetail(d ?? undefined));
  }, [selected]);

  // Live crawl progress; refresh the site map as pages come in and when it ends.
  useEffect(() => {
    const un = events.onCrawl((ev) => {
      if (ev.type === "progress") {
        setCrawlStat({ visited: ev.visited, queued: ev.queued });
        if (ev.visited % 10 === 0) load();
      } else {
        setCrawling(false);
        setCrawlStat({ visited: ev.visited, queued: 0 });
        setMsg(ev.stopped ? `Crawl stopped after ${ev.visited} pages` : `Crawl finished — ${ev.visited} pages`);
        load();
      }
    });
    return () => { un.then((fn) => fn()); };
  }, [load]);

  const startCrawl = useCallback(async () => {
    const s = seed.trim();
    if (!s) { setMsg("enter a seed URL to crawl, e.g. https://host/"); return; }
    try { await api.crawlerStart(s); setCrawling(true); setCrawlStat({ visited: 0, queued: 1 }); setMsg(""); }
    catch (e) { setMsg(String(e)); }
  }, [seed]);
  const stopCrawl = useCallback(async () => {
    try { await api.crawlerStop(); } catch { /* ignore */ }
  }, []);

  const groups = useMemo(() => group(nodes), [nodes]);
  const engagement = useMemo(
    () => rules.filter((r) => r.enabled && r.kind === "include" && !r.is_regex).map((r) => r.host),
    [rules],
  );

  // Make this host the sole engagement (replace scope with just this host).
  const setEngagement = useCallback(async (host: string) => {
    try { setRules(await api.scopeSet([includeRule(host)])); setMsg(`Engagement scoped to ${host}`); }
    catch (e) { setMsg(String(e)); }
  }, []);
  // Add a host to the engagement (keep the others).
  const addToEngagement = useCallback(async (host: string) => {
    const next = [...rules.filter((r) => !(r.kind === "include" && r.host === host)), includeRule(host)];
    try { setRules(await api.scopeSet(next)); setMsg(`Added ${host} to engagement`); }
    catch (e) { setMsg(String(e)); }
  }, [rules]);
  const removeFromEngagement = useCallback(async (host: string) => {
    const next = rules.filter((r) => !(r.kind === "include" && r.host.toLowerCase() === host.toLowerCase()));
    try { setRules(await api.scopeSet(next)); setMsg(`Removed ${host} from engagement`); }
    catch (e) { setMsg(String(e)); }
  }, [rules]);
  const clearEngagement = useCallback(async () => {
    try { setRules(await api.scopeSet([])); setMsg("Engagement cleared"); } catch (e) { setMsg(String(e)); }
  }, []);

  const tree = (
    <div className="target-tree">
      <div className="target-toolbar">
        <span className="mut">{nodes.length} endpoint{nodes.length === 1 ? "" : "s"}</span>
        <span className="spacer" />
        {engagement.length > 0 && <button className="link" onClick={clearEngagement} title="Clear the engagement scope">clear scope</button>}
        <button className="btn" onClick={() => { load(); loadScope(); }}>Refresh</button>
      </div>
      {engagement.length > 0 && (
        <div className="target-engagement" title="Tools (Intruder, scanner, crawler) act only on in-scope hosts">
          <Icon name="target" size={13} />
          <span className="eng-label">Engagement:</span>
          {engagement.map((h) => <span className="eng-chip" key={h}>{h}</span>)}
        </div>
      )}
      <div className="target-crawl" title="Spider the seed host (scope exclusions honoured). Crawled pages flow into history, the site map and the passive scanner.">
        <input
          className="crawl-seed"
          placeholder="crawl seed, e.g. https://lab.test/"
          value={seed}
          onChange={(e) => setSeed(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && !crawling && startCrawl()}
        />
        {crawling
          ? <button className="btn stop" onClick={stopCrawl}>Stop</button>
          : <button className="btn" onClick={startCrawl}>Crawl</button>}
        {crawlStat && (
          <span className="mut crawl-stat">
            {crawling ? "crawling… " : ""}{crawlStat.visited} visited{crawlStat.queued ? `, ${crawlStat.queued} queued` : ""}
          </span>
        )}
      </div>
      <div className="target-list">
        {groups.length === 0 && <div className="hint">no traffic yet — browse through the proxy</div>}
        {groups.map((g) => {
          const expanded = open[g.key] ?? true;
          const inScope = hostInScope(g.host, rules);
          return (
            <div key={g.key} className="target-host">
              <div className={"target-host-row" + (inScope ? " in-scope" : "")}>
                <span className="tw" onClick={() => setOpen((o) => ({ ...o, [g.key]: !expanded }))}>{expanded ? "▾" : "▸"}</span>
                <span className="target-origin" onClick={() => setOpen((o) => ({ ...o, [g.key]: !expanded }))}>{g.origin}</span>
                {inScope && <span className="scope-dot" title="in scope">●</span>}
                <span className="mut">{g.nodes.length}</span>
                <span className="host-actions">
                  {inScope
                    ? <button className="link" onClick={(e) => { e.stopPropagation(); removeFromEngagement(g.host); }} title="Remove this host from the engagement">remove</button>
                    : <button className="link" onClick={(e) => { e.stopPropagation(); addToEngagement(g.host); }} title="Add this host to the engagement">+ add</button>}
                  <button className="btn eng-btn" onClick={(e) => { e.stopPropagation(); setEngagement(g.host); }}
                    title="Make this host the sole engagement scope">Set as engagement</button>
                </span>
              </div>
              {expanded && g.nodes.map((n) => (
                <div
                  key={n.id}
                  className={"target-path" + (selected?.id === n.id ? " on" : "")}
                  onClick={() => setSelected(n)}
                  onContextMenu={(e) => props.onContextMenu(e, n)}
                >
                  <span className="target-method">{n.method}</span>
                  <span className="target-pathtext">{n.path}</span>
                  {n.status != null && <span className={statusClass(n.status)}>{n.status}</span>}
                </div>
              ))}
            </div>
          );
        })}
      </div>
      {msg && <div className="target-msg">{msg}</div>}
    </div>
  );

  const view = detail ? (
    <div className="detail">
      <div className="detailbar">
        <span className="detail-url" title={detail.request.url}>{detail.request.method} {detail.request.url}</span>
      </div>
      <SplitPane
        direction="horizontal" storageKey="shrike.target.h" defaultSize={50}
        first={<MessageViewer title="Request" request={detail.request} />}
        second={<MessageViewer title={detail.response ? `Response · ${detail.response.status}` : (detail.error ? "Error" : "Response")} response={detail.response} />}
      />
      {detail.error && <div className="errbar">upstream error: {detail.error}</div>}
    </div>
  ) : (
    <div className="hint">select an endpoint to inspect its latest request/response</div>
  );

  return (
    <div className="target">
      <SplitPane direction="horizontal" storageKey="shrike.target.tree" defaultSize={38} first={tree} second={view} />
    </div>
  );
}
