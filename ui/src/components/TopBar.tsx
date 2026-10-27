import { useEffect, useState } from "react";
import type { CaInfo, ProjectMeta, ProxyStatus } from "../types";
import type { Theme } from "../theme";
import { api } from "../api";
import { Icon } from "./Icon";

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
  const [msg, setMsg] = useState<string>("");

  async function toggle() {
    setBusy(true); setMsg("");
    try {
      const s = status.running ? await api.proxyStop() : await api.proxyStart();
      props.onStatus(s);
    } catch (e) { setMsg(String(e)); }
    finally { setBusy(false); }
  }

  async function openBrowser() {
    setMsg("");
    try {
      const s = await api.launchBrowser();
      const name = s.chromium.split(/[\\/]/).pop() || "Chromium";
      setMsg(`Browser launched via ${name} → proxying ${s.proxy}`);
    } catch (e) { setMsg(String(e)); }
  }

  async function exportCa() {
    setMsg("");
    try {
      const target = (props.dataDir ? props.dataDir + "/" : "") + "shrike-ca.crt";
      const written = await api.caExport(target);
      setMsg("CA written to " + written);
    } catch (e) { setMsg(String(e)); }
  }

  return (
    <div className="topbar">
      <div className="brand"><span className="mark"><Icon name="bolt" size={13} /></span> Shrike</div>
      {props.project && <ProjectChip project={props.project} dataDir={props.dataDir} onChange={props.onProjectChange} />}
      <span className="topbar-sep" />

      <button className={"btn " + (status.running ? "stop" : "start")} disabled={busy} onClick={toggle}>
        {status.running ? "■ Stop proxy" : "▶ Start proxy"}
      </button>
      <span className={"pill " + (status.running ? "live" : "idle")}>
        {status.running ? "listening " + status.listen : "stopped · " + status.listen}
      </span>
      <button
        className={"btn intercept-toggle" + (props.intercepting ? " on" : "")}
        onClick={props.onToggleIntercept}
        title="Hold requests at the proxy so you can edit, forward or drop them"
      >
        {props.intercepting ? "⏸ Intercept on" : "▷ Intercept off"}
        {props.intercepting && props.heldCount > 0 && <span className="n">{props.heldCount}</span>}
      </button>
      <button className="btn" onClick={openBrowser}
        title="Open an integrated Chromium pre-configured to proxy through Shrike (CA trusted, isolated profile)">
        <Icon name="globe" size={14} /> Browser
      </button>

      <div className="spacer" />

      <button className="icon-btn" onClick={props.onOpenPalette} title="Command palette (Ctrl/⌘ K)">
        <Icon name="command" size={16} />
      </button>
      <button className="icon-btn" onClick={props.onToggleTheme} title={props.theme === "dark" ? "Switch to light" : "Switch to dark"}>
        <Icon name={props.theme === "dark" ? "sun" : "moon"} size={16} />
      </button>
      <span className="topbar-sep" />
      {ca && (
        <span className="ca" title={ca.cert_path}>
          CA {ca.fingerprint.slice(0, 14)}…
          <button className="link" onClick={exportCa}>export</button>
        </span>
      )}
      <button className="link" onClick={props.onClear}>clear history</button>
      {msg && <span className="msg">{msg}</span>}
    </div>
  );
}

function ProjectChip(props: { project: ProjectMeta; dataDir?: string; onChange: (m: ProjectMeta) => void }) {
  const { project } = props;
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(project.name);
  const [msg, setMsg] = useState("");
  useEffect(() => setName(project.name), [project.name]);

  async function saveName() {
    setEditing(false);
    if (name.trim() && name.trim() !== project.name) {
      try { props.onChange(await api.projectSetName(name.trim())); }
      catch (e) { setMsg(String(e)); }
    }
  }

  async function saveCopy() {
    setMsg("");
    try {
      const ts = new Date().toISOString().replace(/[:.]/g, "-");
      const path = (props.dataDir ? props.dataDir + "/" : "") + "backups/shrike-" + ts + ".sqlite";
      const written = await api.projectBackup(path);
      setMsg("Saved copy → " + written);
    } catch (e) { setMsg("Backup failed: " + String(e)); }
  }

  const sizeKb = Math.max(1, Math.round(project.size_bytes / 1024));
  const title = `${project.path}\nschema v${project.schema_version} · ${sizeKb} kB${project.temporary ? "\n⚠ temporary — data is discarded on close" : ""}`;

  return (
    <div className="proj" title={title}>
      <Icon name="database" size={14} />
      {editing
        ? <input className="proj-name-edit" value={name} autoFocus
            onChange={(e) => setName(e.target.value)} onBlur={saveName}
            onKeyDown={(e) => { if (e.key === "Enter") saveName(); if (e.key === "Escape") { setName(project.name); setEditing(false); } }} />
        : <button className="proj-name" onClick={() => setEditing(true)} title="Rename project">{project.name}</button>}
      {project.temporary && <span className="proj-temp">temp</span>}
      <button className="link" onClick={saveCopy} title="Save a consistent copy of the project">save copy</button>
      {msg && <span className="msg proj-msg" title={msg}>{msg}</span>}
    </div>
  );
}
