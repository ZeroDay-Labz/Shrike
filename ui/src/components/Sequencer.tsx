import { useState } from "react";
import type { SequencerReport } from "../types";
import { api } from "../api";

/** Token randomness analysis: paste a sample of tokens, get entropy + shape stats. */
export function Sequencer() {
  const [input, setInput] = useState("");
  const [report, setReport] = useState<SequencerReport>();
  const [msg, setMsg] = useState("");

  async function analyze() {
    setMsg("");
    const tokens = input.split(/\r?\n/).map((t) => t.trim()).filter((t) => t.length > 0);
    if (tokens.length === 0) { setMsg("paste at least one token (one per line)"); setReport(undefined); return; }
    try { setReport(await api.sequencerAnalyze(tokens)); }
    catch (e) { setMsg(String(e)); setReport(undefined); }
  }

  const verdictClass = report
    ? report.verdict.startsWith("WEAK") ? "s-5xx"
      : report.verdict.startsWith("MODERATE") ? "s-3xx"
      : report.verdict.startsWith("STRONG") ? "s-2xx" : "mut"
    : "mut";

  return (
    <div className="seq">
      <div className="seq-input">
        <div className="seq-label">
          Tokens <span className="mut">one per line — session ids, CSRF tokens, etc. (20+ for a confident verdict)</span>
          <span className="spacer" />
          <button className="btn start" onClick={analyze}>Analyze</button>
        </div>
        <textarea className="seq-ta" value={input} spellCheck={false}
          placeholder={"a1b2c3d4e5\n9f8e7d6c5b\n…"}
          onChange={(e) => setInput(e.target.value)} />
        {msg && <div className="msg">{msg}</div>}
      </div>
      <div className="seq-report">
        {report ? (
          <>
            <div className={"seq-verdict " + verdictClass}>{report.verdict}</div>
            <div className="seq-grid">
              <Stat label="Samples" value={report.count} />
              <Stat label="Unique" value={report.unique} />
              <Stat label="Alphabet size" value={report.alphabet} />
              <Stat label="Length min–max" value={`${report.min_len}–${report.max_len}`} />
              <Stat label="Mean length" value={report.mean_len.toFixed(1)} />
              <Stat label="Entropy / char" value={`${report.bits_per_char.toFixed(2)} bits`} />
              <Stat label="Entropy / token" value={`≈ ${report.bits_per_token.toFixed(0)} bits`} />
              <Stat label="Duplicates" value={report.count - report.unique} />
            </div>
            <p className="mut seq-note">
              Entropy per character is the Shannon entropy of the observed character distribution;
              entropy per token estimates it across the mean token length. This is a quick screen,
              not a full randomness battery.
            </p>
          </>
        ) : (
          <div className="hint">paste tokens and press Analyze</div>
        )}
      </div>
    </div>
  );
}

function Stat(props: { label: string; value: string | number }) {
  return (
    <div className="seq-stat">
      <div className="seq-stat-v">{props.value}</div>
      <div className="seq-stat-l">{props.label}</div>
    </div>
  );
}
