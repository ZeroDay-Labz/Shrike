import { useEffect, useState } from "react";
import type { DiffMode, DiffSeg } from "../types";
import { api } from "../api";

/** Comparer: diff two texts (requests, responses, anything) word- or char-wise. */
export function Comparer(props: { seed?: { a: string; b: string } }) {
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [mode, setMode] = useState<DiffMode>("words");
  const [segs, setSegs] = useState<DiffSeg[]>();
  const [msg, setMsg] = useState("");

  // Pick up text sent from a history row (preserving whatever the other slot has).
  useEffect(() => {
    if (!props.seed) return;
    setA(props.seed.a);
    setB(props.seed.b);
    setSegs(undefined);
  }, [props.seed]);

  async function run() {
    setMsg("");
    try { setSegs(await api.compare(a, b, mode)); }
    catch (e) { setMsg(String(e)); setSegs(undefined); }
  }

  const changes = segs?.filter((s) => s.kind !== "equal").length ?? 0;

  return (
    <div className="comparer">
      <div className="cmp-inputs">
        <div className="cmp-pane">
          <div className="cmp-label">A <span className="mut">{a.length} chars</span></div>
          <textarea className="cmp-ta" value={a} onChange={(e) => setA(e.target.value)} placeholder="paste or send text here…" />
        </div>
        <div className="cmp-pane">
          <div className="cmp-label">B <span className="mut">{b.length} chars</span></div>
          <textarea className="cmp-ta" value={b} onChange={(e) => setB(e.target.value)} placeholder="paste or send text here…" />
        </div>
      </div>
      <div className="cmp-controls">
        <div className="seg">
          {(["words", "chars"] as DiffMode[]).map((m) => (
            <button key={m} className={mode === m ? "on" : ""} onClick={() => setMode(m)}>{m}</button>
          ))}
        </div>
        <button className="btn start" onClick={run}>Compare</button>
        {segs && <span className="mut">{changes === 0 ? "identical" : `${changes} difference${changes === 1 ? "" : "s"}`}</span>}
        {msg && <span className="msg">{msg}</span>}
      </div>
      <div className="cmp-result">
        {segs ? (
          <pre className="cmp-diff">
            {segs.map((s, i) => (
              <span key={i} className={"d-" + s.kind}>{s.text}</span>
            ))}
          </pre>
        ) : (
          <div className="hint">enter two texts and press Compare — deletions (only in A) and insertions (only in B) are highlighted</div>
        )}
      </div>
    </div>
  );
}
