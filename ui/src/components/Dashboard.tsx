import { useEffect, useState } from "react";
import type { TrafficStats } from "../types";
import { api } from "../api";

const CLASS_LABEL: Record<number, string> = { 1: "1xx", 2: "2xx", 3: "3xx", 4: "4xx", 5: "5xx" };
const CLASS_CSS: Record<number, string> = { 1: "s-1xx", 2: "s-2xx", 3: "s-3xx", 4: "s-4xx", 5: "s-5xx" };

/** Traffic overview. Scan/issue panels arrive with the active scanner (M7). */
export function Dashboard(props: { running: boolean; listen: string }) {
  const [stats, setStats] = useState<TrafficStats>();
  const [msg, setMsg] = useState("");

  const load = async () => {
    try { setStats(await api.trafficStats()); setMsg(""); }
    catch (e) { setMsg(String(e)); }
  };
  useEffect(() => { load(); }, []);

  const maxHost = Math.max(1, ...(stats?.top_hosts.map(([, n]) => n) ?? [1]));
  const statusTotal = stats?.by_status_class.reduce((a, [, n]) => a + n, 0) ?? 0;

  return (
    <div className="dash">
      <div className="dash-head">
        <h2>Dashboard</h2>
        <span className={"pill " + (props.running ? "live" : "idle")}>
          {props.running ? "proxy listening " + props.listen : "proxy stopped"}
        </span>
        <span className="spacer" />
        <button className="btn" onClick={load}>Refresh</button>
      </div>
      {msg && <div className="errbar">{msg}</div>}

      <div className="dash-tiles">
        <Tile label="Requests" value={fmt(stats?.total)} />
        <Tile label="Distinct hosts" value={fmt(stats?.distinct_hosts)} />
        <Tile label="Errors" value={fmt(stats?.errors)} tone={stats && stats.errors > 0 ? "bad" : undefined} />
        <Tile label="WebSocket msgs" value={fmt(stats?.websockets)} />
      </div>

      <div className="dash-cols">
        <section className="dash-card">
          <h3>Status codes</h3>
          {statusTotal === 0 ? <div className="hint">no responses yet</div> : (
            <div className="dash-bars">
              {stats!.by_status_class.map(([cls, n]) => (
                <div className="dash-bar-row" key={cls}>
                  <span className={"dash-bar-key " + (CLASS_CSS[cls] ?? "s-none")}>{CLASS_LABEL[cls] ?? cls + "xx"}</span>
                  <div className="dash-bar-track">
                    <div className={"dash-bar-fill " + (CLASS_CSS[cls] ?? "s-none")} style={{ width: `${(n / statusTotal) * 100}%` }} />
                  </div>
                  <span className="dash-bar-n">{n}</span>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="dash-card">
          <h3>Methods</h3>
          {(stats?.by_method.length ?? 0) === 0 ? <div className="hint">no traffic yet</div> : (
            <div className="dash-chips">
              {stats!.by_method.map(([m, n]) => (
                <span className="dash-chip" key={m}><b>{m}</b> {n}</span>
              ))}
            </div>
          )}
        </section>

        <section className="dash-card wide">
          <h3>Top hosts</h3>
          {(stats?.top_hosts.length ?? 0) === 0 ? <div className="hint">no traffic yet</div> : (
            <div className="dash-bars">
              {stats!.top_hosts.map(([host, n]) => (
                <div className="dash-bar-row" key={host}>
                  <span className="dash-bar-key host" title={host}>{host}</span>
                  <div className="dash-bar-track">
                    <div className="dash-bar-fill accent" style={{ width: `${(n / maxHost) * 100}%` }} />
                  </div>
                  <span className="dash-bar-n">{n}</span>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

function Tile(props: { label: string; value: string; tone?: "bad" }) {
  return (
    <div className={"dash-tile" + (props.tone === "bad" ? " bad" : "")}>
      <div className="dash-tile-v">{props.value}</div>
      <div className="dash-tile-l">{props.label}</div>
    </div>
  );
}

function fmt(n?: number): string {
  return n == null ? "—" : n.toLocaleString();
}
