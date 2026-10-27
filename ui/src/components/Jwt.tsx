import { useState } from "react";
import { api } from "../api";
import { copyText } from "../repeater";

const ALGS = ["HS256", "HS384", "HS512", "none"];

/**
 * Native JWT tool (no JVM): decode a token, edit the header/payload, and
 * sign/re-sign with HMAC or the unsecured `none` algorithm. A clean-room,
 * in-app reimplementation of the common "JWT editor" extension workflow.
 */
export function Jwt() {
  const [token, setToken] = useState("");
  const [header, setHeader] = useState('{\n  "alg": "HS256",\n  "typ": "JWT"\n}');
  const [payload, setPayload] = useState('{\n  "sub": "1234567890",\n  "name": "Shrike",\n  "admin": false\n}');
  const [alg, setAlg] = useState("HS256");
  const [secret, setSecret] = useState("");
  const [warnings, setWarnings] = useState<string[]>([]);
  const [verify, setVerify] = useState<null | boolean>(null);
  const [msg, setMsg] = useState("");

  async function decode() {
    setMsg(""); setVerify(null);
    try {
      const d = await api.jwtDecode(token);
      setHeader(d.header);
      setPayload(d.payload);
      if (d.alg) setAlg(ALGS.includes(d.alg) ? d.alg : d.alg);
      setWarnings(d.warnings);
    } catch (e) { setMsg(String(e)); }
  }

  async function sign() {
    setMsg(""); setVerify(null);
    try {
      const t = await api.jwtSign(header, payload, alg, secret);
      setToken(t);
      setWarnings([]);
    } catch (e) { setMsg(String(e)); }
  }

  async function runVerify() {
    setMsg("");
    try { setVerify(await api.jwtVerify(token, secret)); }
    catch (e) { setMsg(String(e)); setVerify(null); }
  }

  return (
    <div className="jwt">
      <div className="jwt-head">
        <h2>JWT</h2>
        <span className="mut small">decode, edit and re-sign JSON Web Tokens — HMAC (HS256/384/512) and none</span>
      </div>

      <label className="jwt-label">Encoded token</label>
      <textarea className="jwt-token" rows={4} spellCheck={false} value={token}
        placeholder="paste a JWT here, then Decode — or build one below and Sign"
        onChange={(e) => setToken(e.target.value)} />
      <div className="jwt-row">
        <button className="btn" onClick={decode} disabled={!token.trim()}>Decode ↓</button>
        <button className="btn" onClick={() => copyText(token)} disabled={!token}>Copy</button>
        <span className="spacer" />
        <label className="jwt-inline">Secret
          <input type="text" value={secret} placeholder="HMAC key" onChange={(e) => setSecret(e.target.value)} />
        </label>
        <button className="btn" onClick={runVerify} disabled={!token || alg === "none"}>Verify</button>
        {verify !== null && (
          <span className={"pill " + (verify ? "live" : "idle")}>{verify ? "signature valid" : "signature invalid"}</span>
        )}
      </div>

      {warnings.length > 0 && (
        <div className="warnbar">{warnings.join(" · ")}</div>
      )}

      <div className="jwt-grid">
        <div className="jwt-col">
          <label className="jwt-label">Header</label>
          <textarea className="jwt-json" rows={8} spellCheck={false} value={header}
            onChange={(e) => setHeader(e.target.value)} />
        </div>
        <div className="jwt-col">
          <label className="jwt-label">Payload</label>
          <textarea className="jwt-json" rows={8} spellCheck={false} value={payload}
            onChange={(e) => setPayload(e.target.value)} />
        </div>
      </div>

      <div className="jwt-row">
        <label className="jwt-inline">Algorithm
          <select value={alg} onChange={(e) => setAlg(e.target.value)}>
            {ALGS.map((a) => <option key={a} value={a}>{a}</option>)}
          </select>
        </label>
        <button className="btn start" onClick={sign}>Sign / re-sign →</button>
        {alg === "none" && <span className="mut small">unsecured: an empty signature</span>}
        {msg && <span className="msg">{msg}</span>}
      </div>
    </div>
  );
}
