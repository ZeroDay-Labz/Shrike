import { useEffect, useMemo, useState } from "react";
import type { BappEntry, BappOutput, InstalledBapp, JvmStatus, PluginManifest, RunningBapp } from "../types";
import { api } from "../api";
import { ExtensionTab } from "./ExtensionTab";

const SAMPLE = `{
  "id": "com.example.header-logger",
  "name": "Header Logger",
  "version": "0.1.0",
  "author": "you",
  "description": "Logs an interesting response header.",
  "permissions": ["read_traffic"],
  "hooks": ["on_response"]
}`;

/**
 * The Addons hub: one clean side entry whose top tabs hold the BApp Store, the
 * installed/runtime manager, native plugins, and a live console tab for each
 * running extension (a Java Swing UI still opens in its own OS window — see
 * ExtensionTab). Running-extension state is owned by App and passed in.
 */
export function Extender(props: {
  extMeta: RunningBapp[];
  extLogs: Record<string, BappOutput[]>;
  onStop: (sha: string) => void;
  onUninstall: (sha: string) => void;
  refreshExtMeta: () => void;
}) {
  const [sub, setSub] = useState<string>("store");

  // If the active console's extension stopped, fall back to the Installed tab.
  useEffect(() => {
    if (sub.length === 64 && !props.extMeta.some((m) => m.sha256 === sub)) setSub("installed");
  }, [sub, props.extMeta]);

  const activeMeta = props.extMeta.find((m) => m.sha256 === sub);

  return (
    <div className="ext">
      <div className="ext-head">
        <h2>Addons</h2>
        <div className="seg ext-tabs">
          <button className={sub === "store" ? "on" : ""} onClick={() => setSub("store")}>BApp Store</button>
          <button className={sub === "installed" ? "on" : ""} onClick={() => setSub("installed")}>Installed</button>
          <button className={sub === "native" ? "on" : ""} onClick={() => setSub("native")}>Native plugins</button>
          {props.extMeta.map((m) => (
            <button key={m.sha256} className={sub === m.sha256 ? "on" : ""}
              title={m.name ?? m.sha256} onClick={() => setSub(m.sha256)}>
              <span className="run-dot" /> {m.name ?? ("BApp " + m.sha256.slice(0, 6))}
            </button>
          ))}
        </div>
      </div>

      {sub === "store" && <BappStore onChanged={props.refreshExtMeta} />}
      {sub === "installed" && (
        <InstalledPanel
          onChanged={props.refreshExtMeta}
          onOpenConsole={(sha) => setSub(sha)}
        />
      )}
      {sub === "native" && <NativePlugins />}
      {sub.length === 64 && (
        <ExtensionTab
          meta={activeMeta}
          logs={props.extLogs[sub] ?? []}
          running={!!activeMeta}
          onStop={() => props.onStop(sub)}
          onUninstall={() => { props.onUninstall(sub); setSub("installed"); }}
        />
      )}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* BApp Store (browse + install)                                              */
/* -------------------------------------------------------------------------- */

function BappStore(props: { onChanged: () => void }) {
  const [catalog, setCatalog] = useState<BappEntry[]>([]);
  const [installed, setInstalled] = useState<InstalledBapp[]>([]);
  const [q, setQ] = useState("");
  const [cat, setCat] = useState("");
  const [msg, setMsg] = useState("");
  const [busyId, setBusyId] = useState("");
  const [loadingCat, setLoadingCat] = useState(false);
  const [limit, setLimit] = useState(60);
  const [notInstallable, setNotInstallable] = useState<Record<string, string>>({});

  const installedFor = (e: BappEntry) =>
    installed.find((b) => b.origin === e.id) ??
    (e.download_url ? installed.find((b) => b.filename === e.download_url!.split("/").pop()) : undefined);

  useEffect(() => {
    api.bappCatalogFull(false).then(setCatalog).catch((e) => setMsg(String(e)));
    api.bappInstalled().then(setInstalled).catch(() => {});
  }, []);

  const categories = useMemo(() => [...new Set(catalog.map((e) => e.category))].sort(), [catalog]);
  const matches = useMemo(() => catalog.filter((e) => {
    if (cat && e.category !== cat) return false;
    if (!q) return true;
    const n = q.toLowerCase();
    return e.name.toLowerCase().includes(n) || e.description.toLowerCase().includes(n) || e.author.toLowerCase().includes(n);
  }), [catalog, q, cat]);
  const featured = useMemo(() => matches.filter((e) => e.featured), [matches]);
  const rest = useMemo(() => matches.filter((e) => !e.featured), [matches]);
  const restShown = rest.slice(0, limit);
  useEffect(() => { setLimit(60); }, [q, cat]);

  const open = (url: string) => { if (url) api.openExternal(url).catch((e) => setMsg(String(e))); };

  async function install(e: BappEntry) {
    setBusyId(e.id); setMsg("");
    try {
      const outcome = await api.bappInstallEntry(e.id);
      if (outcome.kind === "installed") {
        setInstalled(outcome.installed);
        setMsg(`Installed ${e.name}. Open it from the Installed tab to run it.`);
        props.onChanged();
      } else {
        setNotInstallable((m) => ({ ...m, [e.id]: outcome.reason }));
        setMsg(outcome.reason);
      }
    } catch (err) { setMsg(String(err)); }
    finally { setBusyId(""); }
  }
  async function uninstall(sha: string) {
    try { await api.bappStop(sha).catch(() => {}); setInstalled(await api.bappUninstall(sha)); props.onChanged(); }
    catch (e) { setMsg(String(e)); }
  }
  async function reloadCatalog() {
    setLoadingCat(true); setMsg("");
    try { setCatalog(await api.bappCatalogFull(true)); }
    catch (e) { setMsg(String(e)); }
    finally { setLoadingCat(false); }
  }

  const card = (e: BappEntry) => (
    <div className="bapp-card" key={e.id}>
      <div className="bapp-card-top">
        <span className="bapp-name">{e.name}</span>
        <span className="bapp-cat">{e.category}</span>
      </div>
      <div className="mut bapp-author">{e.author}</div>
      <div className="bapp-desc">{e.description}</div>
      <div className="bapp-tags">
        <span className="bapp-runtime">{e.runtime}</span>
        {e.native_equivalent
          ? <span className="bapp-native">native: {e.native_equivalent}</span>
          : <span className="bapp-gap">no native equivalent yet</span>}
      </div>
      <div className="bapp-actions">
        {(() => {
          const inst = installedFor(e);
          if (inst) return <button className="btn uninstall" onClick={() => uninstall(inst.sha256)}>Uninstall</button>;
          if (notInstallable[e.id]) return <button className="btn" title={notInstallable[e.id]} onClick={() => open(e.repo_url || e.listing_url)}>Open source ↗</button>;
          return <button className="btn install" disabled={busyId === e.id} onClick={() => install(e)}>{busyId === e.id ? "Installing…" : "Install"}</button>;
        })()}
        <span className="spacer" />
        <button className="link" onClick={() => open(e.listing_url)}>Listing ↗</button>
        {e.repo_url && <button className="link" onClick={() => open(e.repo_url)}>Source ↗</button>}
      </div>
    </div>
  );

  return (
    <>
      <div className="warnbar">
        Install from the catalog in one click. Shrike grabs a release package, a committed jar, or a Python
        source file directly — no commercial licence needed. Java/Kotlin extensions that must be compiled show
        <b> Open source</b> instead. Installed extensions appear under the <b>Installed</b> tab.
      </div>
      <div className="bapp-controls">
        <input placeholder="search extensions…" value={q} onChange={(e) => setQ(e.target.value)} />
        <select value={cat} onChange={(e) => setCat(e.target.value)}>
          <option value="">all categories</option>
          {categories.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <span className="mut">{matches.length} of {catalog.length}</span>
        <span className="spacer" />
        <button className="btn" disabled={loadingCat} onClick={reloadCatalog} title="Re-pull the full catalog from its GitHub mirror">
          {loadingCat ? "Refreshing…" : "⟳ Refresh catalog"}
        </button>
      </div>
      {msg && <div className="msg">{msg}</div>}

      {featured.length > 0 && (
        <>
          <h3 className="bapp-h3">Featured</h3>
          <div className="bapp-grid">{featured.map(card)}</div>
        </>
      )}
      {rest.length > 0 && (
        <>
          <h3 className="bapp-h3">All extensions <span className="mut">({rest.length})</span></h3>
          <div className="bapp-grid">{restShown.map(card)}</div>
          {rest.length > restShown.length && (
            <div className="bapp-more">
              <span className="mut">showing {restShown.length} of {rest.length}</span>
              <button className="btn" onClick={() => setLimit((n) => n + 120)}>Show more</button>
              <span className="mut small">or search to narrow the list</span>
            </div>
          )}
        </>
      )}
      {catalog.length > 0 && matches.length === 0 && <div className="hint">no extensions match your search</div>}
    </>
  );
}

/* -------------------------------------------------------------------------- */
/* Installed + JVM runtime manager                                            */
/* -------------------------------------------------------------------------- */

function InstalledPanel(props: { onChanged: () => void; onOpenConsole: (sha: string) => void }) {
  const [installed, setInstalled] = useState<InstalledBapp[]>([]);
  const [running, setRunning] = useState<string[]>([]);
  const [jvm, setJvm] = useState<JvmStatus>();
  const [setup, setSetup] = useState("");
  const [importPath, setImportPath] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  const refresh = () => {
    api.jvmStatus().then(setJvm).catch(() => {});
    api.bappInstalled().then(setInstalled).catch(() => {});
    api.bappRunning().then(setRunning).catch(() => {});
  };
  useEffect(() => { refresh(); }, []);

  async function runJvmSetup() {
    setSetup("Setting up Java runtime…"); setMsg("");
    try { setJvm(await api.jvmSetup()); setMsg("Java runtime ready."); }
    catch (e) { setMsg(String(e)); }
    finally { setSetup(""); }
  }
  async function runJythonSetup() {
    setSetup("Installing Jython + legacy API (≈50 MB)…"); setMsg("");
    try { setJvm(await api.jythonSetup()); setMsg("Jython installed — Python extensions can now run."); }
    catch (e) { setMsg(String(e)); }
    finally { setSetup(""); }
  }
  async function runInstall() {
    setMsg("");
    const p = importPath.trim();
    if (!p) { setMsg("enter the path to a downloaded .bapp / .jar / .py file"); return; }
    setBusy(true);
    try { setInstalled(await api.bappInstall(p)); setImportPath(""); props.onChanged(); }
    catch (e) { setMsg(String(e)); }
    finally { setBusy(false); }
  }
  async function uninstall(sha: string) {
    try { await api.bappStop(sha).catch(() => {}); setInstalled(await api.bappUninstall(sha)); setRunning(await api.bappRunning()); props.onChanged(); }
    catch (e) { setMsg(String(e)); }
  }
  async function toggleRun(b: InstalledBapp) {
    setMsg("");
    try {
      if (running.includes(b.sha256)) { setRunning(await api.bappStop(b.sha256)); }
      else { setRunning(await api.bappRun(b.sha256)); props.onChanged(); props.onOpenConsole(b.sha256); }
    } catch (e) { setMsg(String(e)); }
  }

  const jvmReady = jvm?.available;
  return (
    <>
      <div className={jvmReady ? "bapp-jvm ok" : "bapp-jvm"}>
        <div className="bapp-jvm-head">
          <b>Java runtime (BApp host)</b>
          <span className={"pill " + (jvmReady ? "live" : "idle")}>{jvmReady ? "ready" : "not set up"}</span>
          <span className="spacer" />
          <button className="btn" disabled={!!setup} onClick={runJvmSetup}>{jvmReady ? "Re-run setup" : "Set up Java"}</button>
          <button className="btn" disabled={!!setup} onClick={runJythonSetup}>{jvm?.jython ? "Reinstall Jython" : "Install Jython"}</button>
          <button className="btn" disabled={!!setup} onClick={refresh}>Re-check</button>
        </div>
        <div className="mut bapp-jvm-detail">
          {setup
            ? setup
            : jvm
              ? <>java: {jvm.version ?? "not found"} · host jars: {jvm.host_jar ? "yes" : "no"} · Jython (Python): {jvm.jython ? "installed" : "not installed"}</>
              : "checking…"}
        </div>
        {!jvmReady && !setup && (
          <div className="bapp-jvm-help">
            One-click: <b>Set up Java</b> stages the host + Montoya jars (needs a <code>java</code> on PATH or a bundled
            JRE). <b>Install Jython</b> adds Jython + the legacy API so Python extensions run.
          </div>
        )}
      </div>

      <h3 className="bapp-h3">Install from a file</h3>
      <div className="bapp-import">
        <input placeholder="/path/to/extension.jar (or .bapp / .py)" value={importPath}
          onChange={(e) => setImportPath(e.target.value)} onKeyDown={(e) => e.key === "Enter" && runInstall()} />
        <button className="btn start" disabled={busy} onClick={runInstall}>{busy ? "Installing…" : "Install"}</button>
      </div>
      {msg && <div className="msg">{msg}</div>}

      <h3 className="bapp-h3">Installed extensions</h3>
      <div className="bapp-imports">
        {installed.length === 0 && <div className="hint">nothing installed yet — add from the BApp Store tab</div>}
        {installed.map((b) => (
          <div className={"bapp-pkg" + (b.enabled ? " on" : "")} key={b.sha256}>
            <div className="bapp-pkg-top">
              <span className="bapp-name">{b.name || b.filename}</span>
              <span className="bapp-fmt">{b.format}</span>
              <span className={"pill " + (running.includes(b.sha256) ? "live" : "idle")}>
                {running.includes(b.sha256) ? "running" : (b.enabled ? "loaded" : "not loaded")}
              </span>
              <span className="spacer" />
              {(b.format === "jar" || b.format === "bapp" || b.format === "python") && (
                <button className="btn" onClick={() => toggleRun(b)}>
                  {running.includes(b.sha256) ? "■ Stop" : "▶ Run"}
                </button>
              )}
              {running.includes(b.sha256) && <button className="link" onClick={() => props.onOpenConsole(b.sha256)}>console →</button>}
              <button className="link" onClick={() => uninstall(b.sha256)}>remove</button>
            </div>
            <div className="bapp-pkg-row"><span className="mut">status</span> {b.status}</div>
            {b.registered.length > 0 &&
              <div className="bapp-pkg-row"><span className="mut">registered</span> {b.registered.filter((r) => !r.startsWith("suiteTab:")).join(", ") || "—"}</div>}
            {b.errors.map((e, i) => <div className="bapp-warn" key={"e" + i}>⚠ {e}</div>)}
          </div>
        ))}
      </div>
    </>
  );
}

/* -------------------------------------------------------------------------- */
/* Native plugin registry (foundation)                                        */
/* -------------------------------------------------------------------------- */

function NativePlugins() {
  const [plugins, setPlugins] = useState<PluginManifest[]>([]);
  const [draft, setDraft] = useState("");
  const [msg, setMsg] = useState("");
  const [adding, setAdding] = useState(false);

  useEffect(() => { api.pluginsList().then(setPlugins).catch((e) => setMsg(String(e))); }, []);

  async function install() {
    setMsg("");
    let manifest: PluginManifest;
    try {
      const parsed = JSON.parse(draft);
      if (!parsed.id || !parsed.name) throw new Error("manifest needs at least an id and a name");
      manifest = { version: "", description: "", author: "", permissions: [], hooks: [], enabled: true, ...parsed };
    } catch (e) { setMsg("Invalid manifest: " + String(e)); return; }
    try { setPlugins(await api.pluginAdd(manifest)); setDraft(""); setAdding(false); }
    catch (e) { setMsg("Rejected: " + String(e)); }
  }
  async function toggle(p: PluginManifest) {
    try { setPlugins(await api.pluginSetEnabled(p.id, !p.enabled)); } catch (e) { setMsg(String(e)); }
  }
  async function remove(p: PluginManifest) {
    try { setPlugins(await api.pluginRemove(p.id)); } catch (e) { setMsg(String(e)); }
  }

  return (
    <>
      <div className="ext-head">
        <span className="mut">Shrike's own plugin API — install, enable and manage native plugins.</span>
        <span className="spacer" />
        <button className="btn start" onClick={() => setAdding((v) => !v)}>{adding ? "Cancel" : "+ Install plugin"}</button>
      </div>
      <div className="warnbar">
        Foundation: the registry, permission and hook model are live and persisted. The sandboxed runtime that
        executes enabled plugins against traffic is the next milestone — installing records a manifest; it does
        not yet run.
      </div>
      {adding && (
        <div className="ext-add">
          <div className="mut">Paste a plugin manifest (JSON):</div>
          <textarea className="ext-ta" value={draft} spellCheck={false} placeholder={SAMPLE}
            onChange={(e) => setDraft(e.target.value)} />
          <div className="row">
            <button className="link" onClick={() => setDraft(SAMPLE)}>use sample</button>
            <span className="spacer" />
            <button className="btn start" onClick={install}>Install</button>
          </div>
        </div>
      )}
      {msg && <div className="msg">{msg}</div>}
      <div className="ext-list">
        {plugins.length === 0 && <div className="hint">no native plugins installed yet</div>}
        {plugins.map((p) => (
          <div className={"ext-card" + (p.enabled ? "" : " off")} key={p.id}>
            <div className="ext-card-top">
              <label className="ext-on"><input type="checkbox" checked={p.enabled} onChange={() => toggle(p)} /></label>
              <span className="ext-name">{p.name}</span>
              {p.version && <span className="mut">v{p.version}</span>}
              {p.author && <span className="mut">· {p.author}</span>}
              <span className="spacer" />
              <button className="link" onClick={() => remove(p)} title="remove">✕</button>
            </div>
            {p.description && <div className="ext-desc">{p.description}</div>}
            <div className="ext-tags">
              {p.permissions.map((perm) => <span className="ext-perm" key={perm}>{perm.replace("_", " ")}</span>)}
              {p.hooks.map((h) => <span className="ext-hook" key={h}>{h.replace("_", " ")}</span>)}
            </div>
            <div className="mut ext-id">{p.id}</div>
          </div>
        ))}
      </div>
    </>
  );
}
