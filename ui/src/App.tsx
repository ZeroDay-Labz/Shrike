import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, events } from "./api";
import type {
  CaInfo, ConfigView, HistoryFilter, ProxyStatus, TransactionSummary, TransactionView, WsMessage,
} from "./types";
import { HistoryTable } from "./components/HistoryTable";
import { WsTable } from "./components/WsTable";
import { MessageViewer } from "./components/MessageViewer";
import { TopBar } from "./components/TopBar";
import { Settings } from "./components/Settings";
import { Repeater } from "./components/Repeater";
import { ContextMenu, type MenuItem } from "./components/ContextMenu";
import { SplitPane } from "./components/SplitPane";
import { Intruder } from "./components/Intruder";
import { Decoder } from "./components/Decoder";
import { Intercept } from "./components/Intercept";
import { Target } from "./components/Target";
import { Comparer } from "./components/Comparer";
import { Logger } from "./components/Logger";
import { Dashboard } from "./components/Dashboard";
import { Sequencer } from "./components/Sequencer";
import { Extender } from "./components/Extender";
import { ExtensionTab } from "./components/ExtensionTab";
import { Jwt } from "./components/Jwt";
import { Icon } from "./components/Icon";
import type { BappOutput, InstalledBapp, RunningBapp } from "./types";
import { CommandPalette, type Command } from "./components/CommandPalette";
import { getTheme, setTheme, type Theme } from "./theme";
import type { InterceptItem, Service, SiteNode } from "./types";
import { buildRaw, parseRaw, copyText, toCurl, type RepeaterTab } from "./repeater";
import { rawRequest, rawResponse } from "./util";

type Tool = { id: string; label: string; icon: string; group: string };
const TOOLS: Tool[] = [
  { id: "dashboard", label: "Dashboard", icon: "dashboard", group: "Overview" },
  { id: "proxy", label: "Proxy", icon: "proxy", group: "Capture" },
  { id: "target", label: "Target", icon: "target", group: "Capture" },
  { id: "logger", label: "Logger", icon: "logger", group: "Capture" },
  { id: "intruder", label: "Intruder", icon: "intruder", group: "Attack" },
  { id: "repeater", label: "Repeater", icon: "repeater", group: "Attack" },
  { id: "sequencer", label: "Sequencer", icon: "sequencer", group: "Tools" },
  { id: "decoder", label: "Decoder", icon: "decoder", group: "Tools" },
  { id: "comparer", label: "Comparer", icon: "comparer", group: "Tools" },
  { id: "jwt", label: "JWT", icon: "key", group: "Tools" },
  { id: "settings", label: "Settings", icon: "settings", group: "System" },
];
const TOOL_GROUPS = TOOLS.reduce<{ name: string; tools: Tool[] }[]>((acc, t) => {
  const last = acc[acc.length - 1];
  if (last && last.name === t.group) last.tools.push(t);
  else acc.push({ name: t.group, tools: [t] });
  return acc;
}, []);

const MAX_ROWS = 5000;

function matches(s: TransactionSummary, f: HistoryFilter): boolean {
  if (f.host && !s.host.toLowerCase().includes(f.host.toLowerCase())) return false;
  if (f.method && s.method.toUpperCase() !== f.method.toUpperCase()) return false;
  if (f.status != null && s.status !== f.status) return false;
  if (f.status_class != null && (s.status == null || Math.floor(s.status / 100) !== f.status_class)) return false;
  if (f.search && !s.url.toLowerCase().includes(f.search.toLowerCase())) return false;
  if (f.only_errors && !s.error) return false;
  return true;
}

export default function App() {
  const [tool, setTool] = useState<string>("proxy");
  const [status, setStatus] = useState<ProxyStatus>({ running: false, listen: "127.0.0.1:8080" });
  const [ca, setCa] = useState<CaInfo>();
  const [config, setConfig] = useState<ConfigView>();
  const [rows, setRows] = useState<TransactionSummary[]>([]);
  const [wsRows, setWsRows] = useState<WsMessage[]>([]);
  const [tab, setTab] = useState<"http" | "ws">("http");
  const [selId, setSelId] = useState<number>();
  const [detail, setDetail] = useState<TransactionView>();
  const [filter, setFilter] = useState<HistoryFilter>({});
  const [repTabs, setRepTabs] = useState<RepeaterTab[]>([]);
  const [activeRep, setActiveRep] = useState<number>();
  const [menu, setMenu] = useState<{ x: number; y: number; items: MenuItem[] } | null>(null);
  const [intruderSeed, setIntruderSeed] = useState<{ service: Service; raw: string }>();
  const [intercepting, setIntercepting] = useState(false);
  const [held, setHeld] = useState<InterceptItem[]>([]);
  const [comparerSeed, setComparerSeed] = useState<{ a: string; b: string }>({ a: "", b: "" });
  const [decoderSeed, setDecoderSeed] = useState<{ text: string }>();
  const [proxyView, setProxyView] = useState<"request" | "response">("request");
  const [project, setProject] = useState<import("./types").ProjectMeta>();
  const repLoadedRef = useRef(false);
  const [theme, setThemeState] = useState<Theme>(() => getTheme());
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [extMeta, setExtMeta] = useState<RunningBapp[]>([]);
  const [extLogs, setExtLogs] = useState<Record<string, BappOutput[]>>({});
  const [railCollapsed, setRailCollapsed] = useState(() => {
    try { return localStorage.getItem("shrike.rail") === "1"; } catch { return false; }
  });
  const nextRepId = useRef(1);
  const queryReloadTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [query, setQuery] = useState("");
  const [queryErr, setQueryErr] = useState("");
  const filterRef = useRef(filter);
  filterRef.current = filter;

  // SHRIKE_START_TOOL=<tool id> opens the app on that tool (automation / screenshots).
  useEffect(() => {
    api.startupTool().then((t) => { if (t) setTool(t); }).catch(() => {});
  }, []);

  // Addons live in their own expand/retract side section: every installed addon
  // is listed there; running ones also carry live metadata and streamed logs.
  const [installedBapps, setInstalledBapps] = useState<InstalledBapp[]>([]);
  const [addonsOpen, setAddonsOpen] = useState(() => {
    try { return localStorage.getItem("shrike.addons") !== "0"; } catch { return true; }
  });
  const toggleAddons = useCallback(() => {
    setAddonsOpen((o) => {
      const n = !o;
      try { localStorage.setItem("shrike.addons", n ? "1" : "0"); } catch { /* ignore */ }
      return n;
    });
  }, []);
  const refreshExtMeta = useCallback(() => {
    api.bappRunningMeta().then(setExtMeta).catch(() => {});
    api.bappInstalled().then(setInstalledBapps).catch(() => {});
  }, []);
  useEffect(() => {
    refreshExtMeta();
    const un = events.onBappOutput((o) => {
      setExtLogs((prev) => {
        const next = (prev[o.sha256] ?? []).concat(o).slice(-500);
        return { ...prev, [o.sha256]: next };
      });
      if (o.stream === "meta") refreshExtMeta();
    });
    const poll = setInterval(refreshExtMeta, 3000);
    return () => { un.then((f) => f()); clearInterval(poll); };
  }, [refreshExtMeta]);

  const runExt = useCallback(async (sha: string) => {
    try { await api.bappRun(sha); } catch { /* status is shown in the addon view */ }
    refreshExtMeta();
  }, [refreshExtMeta]);
  const stopExt = useCallback(async (sha: string) => {
    try { await api.bappStop(sha); } catch { /* ignore */ }
    refreshExtMeta();
  }, [refreshExtMeta]);
  const uninstallExt = useCallback(async (sha: string) => {
    try { await api.bappStop(sha).catch(() => {}); await api.bappUninstall(sha); } catch { /* ignore */ }
    setExtLogs((prev) => { const n = { ...prev }; delete n[sha]; return n; });
    // If that addon's window was open, go back to the store.
    setTool((t) => (t === "addon:" + sha ? "extender" : t));
    refreshExtMeta();
  }, [refreshExtMeta]);

  const queryRef = useRef("");
  queryRef.current = query;

  const reload = useCallback(async () => {
    const q = queryRef.current.trim();
    if (q) {
      try { setRows(await api.historyQuery(q, MAX_ROWS, 0)); setQueryErr(""); }
      catch (e) { setQueryErr(String(e)); }
    } else {
      setRows(await api.historyPage(filterRef.current, 1000, 0));
      setQueryErr("");
    }
  }, []);

  useEffect(() => {
    (async () => {
      setStatus(await api.proxyStatus());
      setCa(await api.caInfo());
      setConfig(await api.configGet());
      setIntercepting(await api.interceptGetEnabled());
      setProject(await api.projectInfo().catch(() => undefined));
      // Restore Repeater tabs saved in the project (request only; responses re-fetch on Send).
      try {
        const saved = await api.uiStateGet("repeater");
        if (saved) {
          const tabs = JSON.parse(saved) as RepeaterTab[];
          if (Array.isArray(tabs) && tabs.length) {
            setRepTabs(tabs.map((t) => ({ ...t, sending: false })));
            nextRepId.current = Math.max(...tabs.map((t) => t.id)) + 1;
            setActiveRep(tabs[0].id);
          }
        }
      } catch { /* ignore malformed saved state */ }
      repLoadedRef.current = true;
      await reload();
    })();
    const uns: Array<Promise<() => void>> = [
      events.onCompleted((t) => {
        if (queryRef.current.trim()) {
          // In query mode, re-run the query (debounced) so matches stay correct.
          if (queryReloadTimer.current) clearTimeout(queryReloadTimer.current);
          queryReloadTimer.current = setTimeout(() => { reload(); }, 600);
        } else if (matches(t, filterRef.current)) {
          setRows((prev) => [t, ...prev.filter((r) => r.id !== t.id)].slice(0, MAX_ROWS));
        }
      }),
      events.onWs((w) => setWsRows((prev) => [w, ...prev].slice(0, 2000))),
      events.onIntercept((item) => setHeld((prev) => [...prev, item])),
    ];
    return () => { uns.forEach((p) => p.then((f) => f())); };
  }, [reload]);

  // Reload on filter change, or (debounced) as the query is typed.
  useEffect(() => {
    const id = setTimeout(() => { reload(); }, query ? 250 : 0);
    return () => clearTimeout(id);
  }, [filter, query, reload]);

  // Persist Repeater tabs to the project (debounced; request only, not responses).
  useEffect(() => {
    if (!repLoadedRef.current) return;
    const id = setTimeout(() => {
      const slim = repTabs.map((t) => ({ id: t.id, name: t.name, service: t.service, raw: t.raw, sending: false }));
      api.uiStateSet("repeater", JSON.stringify(slim)).catch(() => {});
    }, 500);
    return () => clearTimeout(id);
  }, [repTabs]);

  useEffect(() => {
    if (selId == null) { setDetail(undefined); return; }
    api.historyGet(selId).then((d) => setDetail(d ?? undefined));
  }, [selId]);

  const addRepeaterFromView = useCallback((view: TransactionView) => {
    const id = nextRepId.current++;
    let path = view.request.target;
    try { path = new URL(view.request.url).pathname; } catch { /* keep target */ }
    const t: RepeaterTab = {
      id, name: `${view.request.method} ${path}`.slice(0, 32),
      service: { ...view.request.service }, raw: buildRaw(view.request), sending: false,
    };
    setRepTabs((prev) => [...prev, t]);
    setActiveRep(id);
    setTool("repeater");
  }, []);

  const addToIntruder = useCallback((view: TransactionView) => {
    setIntruderSeed({ service: { ...view.request.service }, raw: buildRaw(view.request) });
    setTool("intruder");
  }, []);

  const newRepeaterTab = useCallback(() => {
    const id = nextRepId.current++;
    const t: RepeaterTab = {
      id, name: "New request",
      service: { host: "example.com", port: 443, secure: true },
      raw: "GET / HTTP/1.1\nHost: example.com\nUser-Agent: Shrike\nAccept: */*\n\n",
      sending: false,
    };
    setRepTabs((prev) => [...prev, t]);
    setActiveRep(id);
    setTool("repeater");
  }, []);

  const sendRepeater = useCallback(async (id: number) => {
    setRepTabs((prev) => prev.map((t) => (t.id === id ? { ...t, sending: true, error: undefined } : t)));
    const tab = repTabs.find((t) => t.id === id);
    if (!tab) return;
    const parsed = parseRaw(tab.raw);
    try {
      const res = await api.repeaterSend({
        service: tab.service, method: parsed.method, target: parsed.target,
        headers: parsed.headers, body: parsed.body,
      });
      setRepTabs((prev) => prev.map((t) => t.id === id ? {
        ...t, sending: false, status: res.response.status, durationMs: res.duration_ms,
        responseView: res.response, error: undefined,
      } : t));
    } catch (e) {
      setRepTabs((prev) => prev.map((t) => t.id === id ? { ...t, sending: false, error: String(e) } : t));
    }
  }, [repTabs]);

  const sendToComparer = useCallback((view: TransactionView, slot: "a" | "b") => {
    const text = view.response ? rawResponse(view.response) : rawRequest(view.request);
    setComparerSeed((prev) => ({ ...prev, [slot]: text }));
    setTool("comparer");
  }, []);

  const sendToDecoder = useCallback((view: TransactionView) => {
    const b = view.request.body;
    const text = b.text && b.text.length > 0 ? b.text : view.request.url;
    setDecoderSeed({ text });
    setTool("decoder");
  }, []);

  // The full set of "send to …" actions that make sense for a captured request,
  // shared by the Proxy, Logger and Target context menus.
  const sendItems = useCallback((getView: () => Promise<TransactionView | null>): MenuItem[] => [
    { label: "Send to Repeater", onClick: async () => { const v = await getView(); if (v) addRepeaterFromView(v); } },
    { label: "Send to Intruder", onClick: async () => { const v = await getView(); if (v) addToIntruder(v); } },
    { label: "Send to Comparer (A)", onClick: async () => { const v = await getView(); if (v) sendToComparer(v, "a"); } },
    { label: "Send to Comparer (B)", onClick: async () => { const v = await getView(); if (v) sendToComparer(v, "b"); } },
    { label: "Send to Decoder", onClick: async () => { const v = await getView(); if (v) sendToDecoder(v); } },
  ], [addRepeaterFromView, addToIntruder, sendToComparer, sendToDecoder]);

  const addHostToScope = useCallback(async (host: string) => {
    const cur = await api.scopeGet();
    if (cur.some((r) => r.host.toLowerCase() === host.toLowerCase() && r.kind === "include")) return;
    await api.scopeSet([...cur, { enabled: true, kind: "include", host, port: null, path: null, is_regex: false }]);
  }, []);

  const toggleIntercept = useCallback(async () => {
    const next = !intercepting;
    await api.interceptSetEnabled(next);
    setIntercepting(next);
    // Turning it off releases everything held on the engine side; clear the UI queue too.
    if (!next) setHeld([]);
  }, [intercepting]);

  const resolveHeld = useCallback(async (id: number, action: "forward" | "drop", raw?: string) => {
    try { await api.interceptResolve(id, action, raw); }
    finally { setHeld((prev) => prev.filter((h) => h.id !== id)); }
  }, []);

  const resolveAllHeld = useCallback(async (action: "forward" | "drop", activeId?: number, raw?: string) => {
    const items = held;
    setHeld([]);
    await Promise.all(items.map((h) =>
      api.interceptResolve(h.id, action, action === "forward" && h.id === activeId ? raw : undefined).catch(() => {})
    ));
  }, [held]);

  const toggleTheme = useCallback(() => {
    setThemeState((t) => { const next: Theme = t === "dark" ? "light" : "dark"; setTheme(next); return next; });
  }, []);

  const toggleRail = useCallback(() => {
    setRailCollapsed((c) => { const next = !c; try { localStorage.setItem("shrike.rail", next ? "1" : "0"); } catch { /* ignore */ } return next; });
  }, []);

  const clearHistory = useCallback(async () => {
    await api.historyClear(); setRows([]); setWsRows([]); setSelId(undefined); setDetail(undefined);
  }, []);

  // ⌘K / Ctrl-K opens the command palette.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const openRowMenu = useCallback((e: React.MouseEvent, row: TransactionSummary) => {
    e.preventDefault();
    const getView = () => api.historyGet(row.id);
    const items: MenuItem[] = [
      ...sendItems(getView),
      { label: "Copy URL", separatorBefore: true, onClick: () => copyText(row.url) },
      { label: "Copy as curl", onClick: async () => { const v = await getView(); if (v) copyText(toCurl(v.request)); } },
      { label: `Add host to scope (${row.host})`, separatorBefore: true, onClick: () => addHostToScope(row.host) },
    ];
    setMenu({ x: e.clientX, y: e.clientY, items });
  }, [sendItems, addHostToScope]);

  const openNodeMenu = useCallback((e: React.MouseEvent, node: SiteNode) => {
    e.preventDefault();
    const origin = node.secure
      ? `https://${node.host}${node.port === 443 ? "" : ":" + node.port}`
      : `http://${node.host}${node.port === 80 ? "" : ":" + node.port}`;
    const getView = () => api.historyGet(node.id);
    const items: MenuItem[] = [
      ...sendItems(getView),
      { label: "Copy URL", separatorBefore: true, onClick: () => copyText(origin + node.path) },
      { label: "Copy as curl", onClick: async () => { const v = await getView(); if (v) copyText(toCurl(v.request)); } },
      { label: `Add host to scope (${node.host})`, separatorBefore: true, onClick: () => addHostToScope(node.host) },
    ];
    setMenu({ x: e.clientX, y: e.clientY, items });
  }, [sendItems, addHostToScope]);

  const commands = useMemo<Command[]>(() => {
    const nav: Command[] = TOOLS.map((t) => ({
      id: "go:" + t.id, label: "Go to " + t.label, section: "Navigate", icon: t.icon, tag: "tool",
      run: () => setTool(t.id),
    }));
    nav.push({ id: "go:extender", label: "Go to Addons", section: "Navigate", icon: "extender", tag: "tool",
      run: () => setTool("extender") });
    const actions: Command[] = [
      { id: "act:proxy", label: status.running ? "Stop proxy" : "Start proxy", section: "Actions", icon: "proxy",
        run: async () => { try { setStatus(status.running ? await api.proxyStop() : await api.proxyStart()); } catch { /* shown elsewhere */ } } },
      { id: "act:intercept", label: intercepting ? "Turn intercept off" : "Turn intercept on", section: "Actions", icon: "bolt",
        run: toggleIntercept },
      { id: "act:repeater", label: "New Repeater tab", section: "Actions", icon: "repeater", run: newRepeaterTab },
      { id: "act:browser", label: "Open integrated browser", section: "Actions", icon: "globe", run: () => { api.launchBrowser().catch(() => {}); } },
      { id: "act:theme", label: theme === "dark" ? "Switch to light theme" : "Switch to dark theme", section: "Actions", icon: theme === "dark" ? "sun" : "moon", run: toggleTheme },
      { id: "act:clear", label: "Clear history", section: "Actions", icon: "logger", run: clearHistory },
    ];
    return [...nav, ...actions];
  }, [status, intercepting, theme, toggleIntercept, newRepeaterTab, toggleTheme, clearHistory]);

  const count = rows.length;

  const main = useMemo(() => {
    if (tool === "settings") {
      return <Settings config={config} onSaved={setConfig} onImported={() => reload()} />;
    }
    if (tool === "repeater") {
      return (
        <Repeater
          tabs={repTabs} activeId={activeRep}
          onActivate={setActiveRep}
          onClose={(id) => setRepTabs((prev) => prev.filter((t) => t.id !== id))}
          onEditRaw={(id, raw) => setRepTabs((prev) => prev.map((t) => t.id === id ? { ...t, raw } : t))}
          onEditService={(id, patch) => setRepTabs((prev) => prev.map((t) => t.id === id ? { ...t, service: { ...t.service, ...patch } } : t))}
          onSend={sendRepeater}
          onNew={newRepeaterTab}
        />
      );
    }
    if (tool === "intruder") {
      return <Intruder seed={intruderSeed} />;
    }
    if (tool === "decoder") {
      return <Decoder seed={decoderSeed} />;
    }
    if (tool === "target") {
      return <Target onContextMenu={openNodeMenu} />;
    }
    if (tool === "comparer") {
      return <Comparer seed={comparerSeed} />;
    }
    if (tool === "logger") {
      return <Logger rows={rows} onContextMenu={openRowMenu} />;
    }
    if (tool === "dashboard") {
      return <Dashboard running={status.running} listen={status.listen} />;
    }
    if (tool === "sequencer") {
      return <Sequencer />;
    }
    if (tool === "jwt") {
      return <Jwt />;
    }
    if (tool === "extender") {
      return (
        <Extender
          extMeta={extMeta}
          extLogs={extLogs}
          onStop={stopExt}
          onUninstall={uninstallExt}
          refreshExtMeta={refreshExtMeta}
        />
      );
    }
    if (tool.startsWith("addon:")) {
      const sha = tool.slice(6);
      const meta = extMeta.find((m) => m.sha256 === sha);
      return (
        <ExtensionTab
          meta={meta}
          installed={installedBapps.find((b) => b.sha256 === sha)}
          logs={extLogs[sha] ?? []}
          running={!!meta}
          onRun={() => runExt(sha)}
          onStop={() => stopExt(sha)}
          onUninstall={() => uninstallExt(sha)}
        />
      );
    }
    return (
      <div className="proxy">
        {held.length > 0 && (
          <Intercept
            item={held[0]}
            queued={held.length}
            onForward={(id, raw) => resolveHeld(id, "forward", raw)}
            onDrop={(id) => resolveHeld(id, "drop")}
            onForwardAll={(id, raw) => resolveAllHeld("forward", id, raw)}
            onDropAll={() => resolveAllHeld("drop")}
          />
        )}
        <FilterBar filter={filter} setFilter={setFilter} count={count} tab={tab} setTab={setTab} wsCount={wsRows.length}
          query={query} setQuery={setQuery} queryErr={queryErr} />
        {tab === "ws" ? (
          <div className="pane-fill"><WsTable rows={wsRows} /></div>
        ) : (
          <SplitPane
            direction="vertical" storageKey="shrike.proxy.v" defaultSize={46}
            first={<HistoryTable rows={rows} selectedId={selId} onSelect={setSelId} onContextMenu={openRowMenu} />}
            second={detail ? (
              <div className="detail">
                <div className="detailbar">
                  <div className="seg">
                    <button className={proxyView === "request" ? "on" : ""} onClick={() => setProxyView("request")}>Request</button>
                    <button className={proxyView === "response" ? "on" : ""} onClick={() => setProxyView("response")} disabled={!detail.response}>Response</button>
                  </div>
                  <span className="detail-url" title={detail.request.url}>{detail.request.method} {detail.request.url}</span>
                  <span className="spacer" />
                  <button className="btn" onClick={() => addRepeaterFromView(detail)}>⤷ Repeater</button>
                  <button className="btn" onClick={() => addToIntruder(detail)}>⤷ Intruder</button>
                  <button className="btn" onClick={() => sendToComparer(detail, "a")} title="Send to Comparer A">⤷ Cmp A</button>
                  <button className="btn" onClick={() => sendToComparer(detail, "b")} title="Send to Comparer B">⤷ Cmp B</button>
                  <button className="btn" onClick={() => sendToDecoder(detail)}>⤷ Decoder</button>
                  <button className="btn" onClick={() => copyText(toCurl(detail.request))}>curl</button>
                </div>
                <div className="pane-fill">
                  {proxyView === "response" && detail.response
                    ? <MessageViewer title={`Response · ${detail.response.status}`} response={detail.response} />
                    : <MessageViewer title="Request" request={detail.request} />}
                </div>
                {detail.error && <div className="errbar">upstream error: {detail.error}</div>}
              </div>
            ) : (
              <div className="hint">select a request to inspect it</div>
            )}
          />
        )}
      </div>
    );
  }, [tool, status, config, filter, count, tab, wsRows, rows, selId, detail, proxyView, repTabs, activeRep, openRowMenu, openNodeMenu, sendRepeater, newRepeaterTab, addRepeaterFromView, addToIntruder, intruderSeed, held, resolveHeld, resolveAllHeld, comparerSeed, decoderSeed, sendToComparer, sendToDecoder, extMeta, extLogs, installedBapps, runExt, stopExt, uninstallExt, refreshExtMeta, reload]);

  return (
    <div className="app">
      <TopBar
        status={status} ca={ca} dataDir={config?.data_dir} project={project}
        intercepting={intercepting} heldCount={held.length} theme={theme}
        onToggleIntercept={toggleIntercept}
        onToggleTheme={toggleTheme}
        onOpenPalette={() => setPaletteOpen(true)}
        onProjectChange={setProject}
        onStatus={setStatus}
        onClear={clearHistory}
      />
      <div className="body">
        <nav className={"rail" + (railCollapsed ? " collapsed" : "")}>
          <div className="rail-groups">
            {TOOL_GROUPS.map((g) => (
              <div className="rail-group" key={g.name}>
                <div className="rail-group-label">{g.name}</div>
                {g.tools.map((t) => (
                  <button
                    key={t.id}
                    className={"rail-item" + (tool === t.id ? " on" : "")}
                    onClick={() => setTool(t.id)}
                    title={t.label}
                  >
                    <span className="rail-ico"><Icon name={t.icon} /></span>
                    <span className="rail-label">{t.label}</span>
                  </button>
                ))}
              </div>
            ))}
            <div className="rail-group">
              <button className="rail-group-label rail-toggle" onClick={toggleAddons}
                title={addonsOpen ? "Collapse addons" : "Expand addons"}>
                <span>Addons</span>
                <span className="chev">{addonsOpen ? "▾" : "▸"}</span>
              </button>
              {addonsOpen && (
                <>
                  <button
                    className={"rail-item" + (tool === "extender" ? " on" : "")}
                    onClick={() => setTool("extender")}
                    title="Addon store, installed extensions and runtime"
                  >
                    <span className="rail-ico"><Icon name="extender" /></span>
                    <span className="rail-label">Store &amp; installed</span>
                  </button>
                  {installedBapps.map((b) => {
                    const live = extMeta.some((m) => m.sha256 === b.sha256);
                    return (
                      <button
                        key={b.sha256}
                        className={"rail-item" + (tool === "addon:" + b.sha256 ? " on" : "")}
                        onClick={() => setTool("addon:" + b.sha256)}
                        title={(b.name || b.filename) + (live ? " — running" : "")}
                      >
                        <span className="rail-ico"><span className={"run-dot" + (live ? "" : " off")} /></span>
                        <span className="rail-label">{b.name || b.filename}</span>
                      </button>
                    );
                  })}
                  {installedBapps.length === 0 && <div className="rail-hint">none installed yet</div>}
                </>
              )}
            </div>
          </div>
          <button className="rail-collapse" onClick={toggleRail} title={railCollapsed ? "Expand sidebar" : "Collapse sidebar"}>
            <span className="rail-ico"><Icon name="sidebar" /></span>
            <span className="rail-label">Collapse</span>
          </button>
        </nav>
        <main className="content">{main}</main>
      </div>
      {menu && <ContextMenu x={menu.x} y={menu.y} items={menu.items} onClose={() => setMenu(null)} />}
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} commands={commands} />
    </div>
  );
}

function FilterBar(props: {
  filter: HistoryFilter;
  setFilter: (f: HistoryFilter) => void;
  count: number;
  tab: "http" | "ws";
  setTab: (t: "http" | "ws") => void;
  wsCount: number;
  query: string;
  setQuery: (q: string) => void;
  queryErr: string;
}) {
  const { filter, setFilter } = props;
  return (
    <div className="filterbar">
      <div className="tabs">
        <button className={props.tab === "http" ? "on" : ""} onClick={() => props.setTab("http")}>
          HTTP history <span className="n">{props.count}</span>
        </button>
        <button className={props.tab === "ws" ? "on" : ""} onClick={() => props.setTab("ws")}>
          WebSockets <span className="n">{props.wsCount}</span>
        </button>
      </div>
      {props.tab === "http" && (
        <>
          <input
            className={"hql" + (props.queryErr ? " err" : "")}
            placeholder='query e.g. host:example.com code>=400 method:POST'
            title={props.queryErr || "Shrike query: host: method: code: url: mime: body: port: — AND / OR / NOT, ( )"}
            value={props.query}
            onChange={(e) => props.setQuery(e.target.value)} />
          {props.query
            ? <button className="link" onClick={() => props.setQuery("")}>clear query</button>
            : <>
          <input placeholder="filter host…" value={filter.host ?? ""}
            onChange={(e) => setFilter({ ...filter, host: e.target.value || null })} />
          <input placeholder="search URL…" value={filter.search ?? ""}
            onChange={(e) => setFilter({ ...filter, search: e.target.value || null })} />
          <select value={filter.method ?? ""} onChange={(e) => setFilter({ ...filter, method: e.target.value || null })}>
            <option value="">any method</option>
            {["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"].map((m) => <option key={m}>{m}</option>)}
          </select>
          <select value={filter.status_class ?? ""} onChange={(e) => setFilter({ ...filter, status_class: e.target.value ? Number(e.target.value) : null })}>
            <option value="">any status</option>
            {[2, 3, 4, 5].map((c) => <option key={c} value={c}>{c}xx</option>)}
          </select>
          <label className="chk">
            <input type="checkbox" checked={!!filter.only_errors}
              onChange={(e) => setFilter({ ...filter, only_errors: e.target.checked || null })} /> errors
          </label>
              </>
          }
          {props.queryErr && <span className="query-err" title={props.queryErr}>⚠ query error</span>}
        </>
      )}
    </div>
  );
}
