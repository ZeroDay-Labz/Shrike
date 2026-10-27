import { useEffect, useState } from "react";
import type { DecodeOp, StepResult } from "../types";
import { api } from "../api";
import { copyText } from "../repeater";

const OPS: { v: DecodeOp; label: string }[] = [
  { v: "url_encode", label: "URL encode" },
  { v: "url_decode", label: "URL decode" },
  { v: "base64_encode", label: "Base64 encode" },
  { v: "base64_decode", label: "Base64 decode" },
  { v: "hex_encode", label: "Hex encode" },
  { v: "hex_decode", label: "Hex decode" },
  { v: "html_encode", label: "HTML encode" },
  { v: "html_decode", label: "HTML decode" },
  { v: "upper", label: "Upper case" },
  { v: "lower", label: "Lower case" },
];

export function Decoder(props: { seed?: { text: string } }) {
  const [input, setInput] = useState("");
  const [ops, setOps] = useState<DecodeOp[]>([]);
  const [results, setResults] = useState<StepResult[]>([]);

  // Pick up text sent from another tool (e.g. a request body from Proxy).
  useEffect(() => {
    if (props.seed) { setInput(props.seed.text); setOps([]); }
  }, [props.seed]);

  useEffect(() => {
    if (ops.length === 0) { setResults([]); return; }
    let live = true;
    const id = setTimeout(async () => {
      try { const r = await api.decodeChain(input, ops); if (live) setResults(r); }
      catch { if (live) setResults([]); }
    }, 150);
    return () => { live = false; clearTimeout(id); };
  }, [input, ops]);

  const addStep = (v: DecodeOp) => setOps((p) => [...p, v]);
  const setStep = (i: number, v: DecodeOp) => setOps((p) => p.map((o, j) => (j === i ? v : o)));
  const removeStep = (i: number) => setOps((p) => p.filter((_, j) => j !== i));
  const final = results.length ? results[results.length - 1] : undefined;

  return (
    <div className="decoder">
      <div className="dec-head">
        <h2>Decoder</h2>
        <span className="mut small">chain transforms top to bottom; each step feeds the next</span>
        <span className="spacer" />
        <select value="" onChange={(e) => { if (e.target.value) addStep(e.target.value as DecodeOp); }}>
          <option value="">+ add transform…</option>
          {OPS.map((o) => <option key={o.v} value={o.v}>{o.label}</option>)}
        </select>
        {final?.output != null && <button className="btn" onClick={() => copyText(final.output!)}>Copy result</button>}
      </div>

      <div className="dec-stack">
        <div className="dec-block">
          <div className="dec-label">Input</div>
          <textarea value={input} onChange={(e) => setInput(e.target.value)} placeholder="paste or type data here…" spellCheck={false} />
        </div>

        {ops.map((op, i) => {
          const res = results[i];
          return (
            <div className="dec-block" key={i}>
              <div className="dec-label">
                <select value={op} onChange={(e) => setStep(i, e.target.value as DecodeOp)}>
                  {OPS.map((o) => <option key={o.v} value={o.v}>{o.label}</option>)}
                </select>
                <button className="link" onClick={() => removeStep(i)}>remove</button>
              </div>
              {res?.error
                ? <div className="dec-error">{res.error}</div>
                : <textarea readOnly value={res?.output ?? ""} spellCheck={false} />}
            </div>
          );
        })}
      </div>
    </div>
  );
}
