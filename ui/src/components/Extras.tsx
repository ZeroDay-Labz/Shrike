import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { ExtraStatus } from "../types";
import { Icon } from "./Icon";
import { toast } from "./Overlay";

/**
 * The native Extras surface. The organising principle is the passive/active
 * split, shown explicitly so there's never any doubt what runs on its own:
 *
 *  - Passive extras observe captured traffic and never send a request, so they
 *    run automatically and can be toggled on/off.
 *  - Active extras send requests to the target, so they are run deliberately
 *    (from a request's context menu), never on a timer or toggle.
 */
export function Extras(props: { onGoToProxy: () => void }) {
  const [extras, setExtras] = useState<ExtraStatus[]>([]);
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    api.extrasList().then(setExtras).catch((e) => toast(String(e), "error"));
  }, []);

  const groups = useMemo(() => {
    const passive = extras.filter((e) => e.kind === "passive");
    const active = extras.filter((e) => e.kind === "active");
    return { passive, active };
  }, [extras]);

  async function toggle(id: string, on: boolean) {
    setBusy(id);
    try {
      setExtras(await api.extraSetEnabled(id, on));
    } catch (e) {
      toast(String(e), "error");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="extras">
      <div className="extras-head">
        <h2>Extras</h2>
        <span className="mut">Shrike's native capabilities — all built in, no runtime required.</span>
      </div>

      <section className="extras-group">
        <div className="extras-group-head">
          <span className="extras-badge passive"><Icon name="finding" size={13} /> Passive</span>
          <span className="mut">Observe captured traffic automatically. These never send a request.</span>
        </div>
        <div className="extras-grid">
          {groups.passive.map((e) => (
            <div key={e.id} className={"extra-card" + (e.enabled ? "" : " off")}>
              <div className="extra-card-top">
                <span className="extra-name">{e.name}</span>
                <label className="switch-btn sm" title={e.enabled ? "Enabled — running on captured traffic" : "Disabled"}>
                  <input type="checkbox" checked={e.enabled} disabled={busy === e.id}
                    onChange={(ev) => toggle(e.id, ev.target.checked)} />
                  <span className="switch" aria-hidden="true"><i /></span>
                </label>
              </div>
              <div className="extra-cat">{e.category}</div>
              <p className="extra-desc">{e.description}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="extras-group">
        <div className="extras-group-head">
          <span className="extras-badge active"><Icon name="bolt" size={13} /> Active</span>
          <span className="mut">
            These send crafted requests to the target, so you run them deliberately — never automatically.
          </span>
        </div>
        <div className="extras-grid">
          {groups.active.map((e) => (
            <div key={e.id} className="extra-card active">
              <div className="extra-card-top">
                <span className="extra-name">{e.name}</span>
                <span className="extra-sends" title="Running this puts requests on the wire">sends requests</span>
              </div>
              <div className="extra-cat">{e.category}</div>
              <p className="extra-desc">{e.description}</p>
              <div className="extra-run-hint">
                Right-click a request in <button className="link" onClick={props.onGoToProxy}>Proxy</button> history and
                choose <b>Active scan this request</b>.
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
