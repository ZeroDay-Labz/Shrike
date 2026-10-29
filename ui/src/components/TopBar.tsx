import { useEffect, useRef, useState } from "react";
import type { CaInfo, ProjectMeta, ProxyStatus } from "../types";
import type { Theme } from "../theme";
import { api, events } from "../api";
import { Icon } from "./Icon";
import { ContextMenu, type MenuItem } from "./ContextMenu";
import { toast } from "./Overlay";

export function TopBar(props: {
  status: ProxyStatus;
  ca?: CaInfo;
  dataDir?: string;
  project?: ProjectMeta;
  intercepting: boolean;
  heldCount: number;
  theme: Theme;
  onToggleIntercept: () => void;
  onToggleTheme: () => void;
  onOpenPalette: () => void;
  onProjectChange: (m: ProjectMeta) => void;
  onStatus: (s: ProxyStatus) => void;
  onClear: () => void;
}) {
  const { status, ca } = props;
  const [busy, setBusy] = useState(false);
  const [browserOn, setBrowserOn] = useState(false);
  const [menu, setMenu] = useState<{ x: number; y: number } | null>(null);
  const moreRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const un = events.onBrowserClosed(() => setBrowserOn(false));
    return () => { un.then((f) => f()); };
  }, []);

  async function toggleProxy() {
    setBusy(true);
    try {
      const s = status.running ? await api.proxyStop() : await api.proxyStart();
      props.onStatus(s);
    } catch (e) { toast(String(e), "error"); }
    finally { setBusy(false); }
  }

  async function openBrowser() {
    try {
      const s = await api.launchBrowser();
      const name = s.chromium.split(/[\\/]/).pop() || "Chromium";
      setBrowserOn(true);
      toast(`Browser launched (${name}), proxying through ${s.proxy}`, "success");
    } catch (e) { toast(String(e), "error"); }
  }

  async function exportCa() {
    try {
      const target = (props.dataDir ? props.dataDir + "/" : "") + "shrike-ca.crt";
      toast("CA certificate written to " + await api.caExport(target), "success");
    } catch (e) { toast(String(e), "error"); }
  }

  async function saveCopy() {
    try {
      const ts = new Date().toISOString().replace(/[:.]/g, "-");
      const path = (props.dataDir ? props.dataDir + "/" : "") + "backups/shrike-" + ts + ".sqlite";
      toast("Project copy saved to " + await api.projectBackup(path), "success");
    } catch (e) { toast("Backup failed: " + String(e), "error"); }
  }

  function openMenu() {
    const r = moreRef.current?.getBoundingClientRect();
    if (r) setMenu({ x: r.right - 240, y: r.bottom + 6 });
  }

  const menuItems: MenuItem[] = [
    { label: "Save a copy of the project", onClick: saveCopy },
    {
      label: ca ? `Export CA certificate · ${ca.fingerprint.slice(0, 11)}…` : "Export CA certificate",
      onClick: exportCa, disabled: !ca,
    },
    { label: "Clear history…", onClick: props.onClear, danger: true, separatorBefore: true },
  ];

  const held = props.heldCount;
  return (
    <header className="topbar">
      <div className="brand"><span className="mark"><Icon name="bolt" size={13} /></span> Shrike</div>
      {props.project && <ProjectChip project={props.project} onChange={props.onProjectChange} />}
      <span className="topbar-sep" />

      <div className={"proxy-ctl" + (status.running ? " live" : "")}
        title={status.running ? "The proxy is listening" : "The proxy is stopped"}>
        <span className="dot" aria-hidden="true" />
        <span className="proxy-ctl-label">{status.running ? "Proxy" : "Proxy off"}</span>
        <span className="proxy-ctl-addr">{status.listen}</span>
        <button className="proxy-ctl-btn" disabled={busy} onClick={toggleProxy}>
          {busy ? "…" : status.running ? "Stop" : "Start"}
        </button>
      </div>

      <button
        role="switch" aria-checked={props.intercepting}
        className={"switch-btn" + (props.intercepting ? " on" : "") + (held > 0 ? " held" : "")}
        onClick={props.onToggleIntercept}
        title={props.intercepting
          ? "Intercept is on: requests are held so you can edit, forward or drop them"
          : "Intercept is off: requests pass straight through"}
      >
        <span className="switch" aria-hidden="true"><i /></span>
        Intercept
        {props.intercepting && held > 0 && <span className="count">{held} held</span>}
      </button>

      <button className={"btn" + (browserOn ? " active" : "")} onClick={openBrowser}
        title="Open a Chromium pre-configured to proxy through Shrike (CA trusted, isolated profile)">
        <Icon name="globe" size={14} /> {browserOn ? "Browser open" : "Browser"}
      </button>

      <div className="spacer" />

      <button className="icon-btn" onClick={props.onOpenPalette} title="Command palette (Ctrl/⌘ K)">
        <Icon name="command" size={16} />
      </button>
      <button className="icon-btn" onClick={props.onToggleTheme}
        title={props.theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}>
        <Icon name={props.theme === "dark" ? "sun" : "moon"} size={16} />
      </button>
      <button ref={moreRef} className={"icon-btn" + (menu ? " on" : "")} onClick={openMenu}
        title="Project, certificate and history actions" aria-haspopup="menu">
        <Icon name="more" size={16} />
      </button>
      {menu && <ContextMenu x={menu.x} y={menu.y} items={menuItems} onClose={() => setMenu(null)} />}
    </header>
  );
}

function ProjectChip(props: { project: ProjectMeta; onChange: (m: ProjectMeta) => void }) {
  const { project } = props;
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(project.name);
  useEffect(() => setName(project.name), [project.name]);

  async function saveName() {
    setEditing(false);
    if (name.trim() && name.trim() !== project.name) {
      try { props.onChange(await api.projectSetName(name.trim())); }
      catch (e) { toast(String(e), "error"); }
    }
  }

  const sizeKb = Math.max(1, Math.round(project.size_bytes / 1024));
  const title = `${project.path}\nschema v${project.schema_version} · ${sizeKb} kB${project.temporary ? "\n⚠ temporary — data is discarded on close" : ""}\nClick the name to rename`;

  return (
    <div className="proj" title={title}>
      <Icon name="database" size={14} />
      {editing
        ? <input className="proj-name-edit" value={name} autoFocus aria-label="Project name"
            onChange={(e) => setName(e.target.value)} onBlur={saveName}
            onKeyDown={(e) => { if (e.key === "Enter") saveName(); if (e.key === "Escape") { setName(project.name); setEditing(false); } }} />
        : <button className="proj-name" onClick={() => setEditing(true)}>{project.name}</button>}
      {project.temporary && <span className="proj-temp">temp</span>}
    </div>
  );
}
