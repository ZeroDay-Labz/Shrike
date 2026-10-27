import { useEffect, useRef } from "react";
import type { BappOutput, InstalledBapp, RunningBapp } from "../types";

/**
 * Console tab for one running BApp. A Java extension's own Swing UI opens in its
 * own OS window (it cannot be painted inside this web UI); this tab is its
 * control panel: what it registered, its live log output, and Run/Stop controls.
 */
export function ExtensionTab(props: {
  meta?: RunningBapp;
  /// The installed record, so a stopped addon still shows its name/status.
  installed?: InstalledBapp;
  logs: BappOutput[];
  running: boolean;
  onRun?: () => void;
  onStop: () => void;
  onUninstall: () => void;
}) {
  const { meta, installed, logs, running } = props;
  const logRef = useRef<HTMLDivElement>(null);

  // Keep the log pinned to the newest line as it streams in.
  useEffect(() => {
    const el = logRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [logs.length]);

  const name = meta?.name || installed?.name || installed?.filename || "Extension";
  const registered = meta?.registered ?? installed?.registered ?? [];
  const hooks = registered.filter((r) => !r.startsWith("suiteTab:"));
  const tabs = meta?.suite_tabs
    ?? registered.filter((r) => r.startsWith("suiteTab:")).map((r) => r.slice("suiteTab:".length));

  return (
    <div className="exttab">
      <div className="exttab-head">
        <div className="exttab-title">
          <span className="ext-name">{name}</span>
          <span className={"pill " + (running ? "live" : "idle")}>{running ? "running" : "stopped"}</span>
          {meta && meta.windows > 0 && (
            <span className="mut small">{meta.windows} UI window{meta.windows === 1 ? "" : "s"} open</span>
          )}
        </div>
        <span className="spacer" />
        {running
          ? <button className="btn stop" onClick={props.onStop}>■ Stop</button>
          : props.onRun
            ? <button className="btn start" onClick={props.onRun}>▶ Run</button>
            : <button className="btn" disabled>stopped</button>}
        <button className="btn uninstall" onClick={props.onUninstall}>Uninstall</button>
      </div>

      {!running && installed && (
        <div className="exttab-note">Not running · {installed.status}. Press <b>Run</b> to start it in the JVM host.</div>
      )}
      {tabs.length > 0 && (
        <div className="exttab-note">
          Registered UI tab{tabs.length === 1 ? "" : "s"}: <b>{tabs.join(", ")}</b>. Java Swing UIs
          open in their own window — bring it forward from your window switcher.
        </div>
      )}

      <div className="exttab-meta">
        <div className="exttab-section">
          <div className="exttab-label">Registered</div>
          <div className="exttab-chips">
            {hooks.length === 0 && tabs.length === 0 && <span className="mut">nothing registered yet</span>}
            {hooks.map((h) => <span className="ext-hook" key={h}>{h.replace(/^register/, "")}</span>)}
            {tabs.map((t) => <span className="ext-perm" key={"t" + t}>tab: {t}</span>)}
          </div>
        </div>
      </div>

      <div className="exttab-label">Output</div>
      <div className="exttab-log" ref={logRef}>
        {logs.length === 0 && <div className="hint">no output yet — logs stream here while the extension runs</div>}
        {logs.map((l, i) => (
          <div key={i} className={"exttab-line" + (l.stream === "err" ? " err" : "")}>{l.line}</div>
        ))}
      </div>
    </div>
  );
}
