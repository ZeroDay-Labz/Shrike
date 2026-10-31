import { useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import CodeMirror from "@uiw/react-codemirror";
import { EditorView } from "@codemirror/view";
import type { AttackResult, AttackType, Generator, IntruderConfig, PreviewResult, Processor, Service } from "../types";
import { api, events } from "../api";
import { statusClass, humanBytes } from "../util";
import { SplitPane } from "./SplitPane";
import { confirmAction, toast } from "./Overlay";
import { markerHighlight } from "../cm-markers";
import { shrikeEditorTheme } from "../cm-theme";

const MARK = "§"; // §
const MAX_THREADS = 512; // mirrors the engine's MAX_CONCURRENCY ceiling

const clampThreads = (v: string) => Math.max(1, Math.min(MAX_THREADS, Number(v) || 1));
const clampDelay = (v: string) => Math.max(0, Number(v) || 0);
const clampRetries = (v: string) => Math.max(0, Math.min(10, Number(v) || 0));
const clampTimeout = (v: string) => Math.max(1, Math.min(120, Number(v) || 10)); // seconds

const ATTACKS: { v: AttackType; label: string; hint: string }[] = [
  { v: "sniper", label: "Sniper", hint: "one set; fuzz each position in turn" },
  { v: "battering_ram", label: "Battering ram", hint: "one set; same payload in all positions" },
  { v: "pitchfork", label: "Pitchfork", hint: "one set per position; advance together" },
  { v: "cluster_bomb", label: "Cluster bomb", hint: "one set per position; all combinations" },
];

export function Intruder(props: { seed?: { service: Service; raw: string } }) {
  const [service, setService] = useState<Service>({ host: "example.com", port: 443, secure: true });
  const [template, setTemplate] = useState<string>("GET / HTTP/1.1\nHost: example.com\n\n");
  const [attack, setAttack] = useState<AttackType>("sniper");
  const [sets, setSets] = useState<string[]>([""]);
  // Threads/Delay are held as the raw text the user typed so the field can be
  // cleared to empty (to type a fresh number) instead of snapping to a floor on
  // every keystroke. They're coerced to valid numbers only where used.
  const [concurrency, setConcurrency] = useState("10");
  const [delay, setDelay] = useState("0");
  // Resilience: retry transient failures and cap per-request wait so a target
  // that stalls under load doesn't lose results or wedge the whole attack.
  const [retries, setRetries] = useState("3");
  const [timeoutS, setTimeoutS] = useState("10");
  const [proc, setProc] = useState({ url: false, b64: false, hex: false, upper: false, lower: false });
  const [prefix, setPrefix] = useState("");
  const [suffix, setSuffix] = useState("");
  const [preview, setPreview] = useState<PreviewResult>();
  const [showPreview, setShowPreview] = useState(false);
  const [results, setResults] = useState<AttackResult[]>([]);
  const [running, setRunning] = useState(false);
  const [total, setTotal] = useState(0);
  const [capped, setCapped] = useState(false);
  const [sortKey, setSortKey] = useState<"index" | "status" | "length" | "duration_ms">("index");
  const [sortDir, setSortDir] = useState<1 | -1>(1);
  // Intruder enforces target scope by default (active tools are deliberate and
  // must not touch anything out of scope). If the target isn't in scope the
  // engine refuses the attack, so we surface that here before Start is pressed.
  const [requireScope, setRequireScope] = useState(false);
  const [scopeOk, setScopeOk] = useState<boolean | null>(null);
  // Race-condition attack: number of synchronised copies to fire at once.
  const [raceCount, setRaceCount] = useState("20");
  const [raceVariant, setRaceVariant] = useState<"last_byte" | "h2_single_packet">("last_byte");

  const viewRef = useRef<EditorView | null>(null);
  const attackIdRef = useRef<number | undefined>(undefined);

  useEffect(() => {
    if (props.seed) { setService(props.seed.service); setTemplate(props.seed.raw); }
  }, [props.seed]);

  // Learn whether Intruder requires scope (the default). Only then do we check
  // the current target and warn, so a user who turned the requirement off never
  // sees scope friction.
  useEffect(() => {
    api.configGet().then((c) => setRequireScope(!!c.intruder_require_scope)).catch(() => {});
  }, []);

  const targetUrl = useMemo(
    () => `${service.secure ? "https" : "http"}://${service.host}:${service.port}/`,
    [service.secure, service.host, service.port],
  );

  useEffect(() => {
    if (!requireScope || !service.host) { setScopeOk(null); return; }
    let live = true;
    api.scopeCheck(targetUrl).then((ok) => { if (live) setScopeOk(ok); }).catch(() => { if (live) setScopeOk(null); });
    return () => { live = false; };
  }, [requireScope, targetUrl, service.host]);

  async function addTargetToScope() {
    try {
      const rules = await api.scopeGet();
      await api.scopeSet([
        ...rules,
        { enabled: true, kind: "include" as const, host: service.host, port: null, path: null, is_regex: false },
      ]);
      const ok = await api.scopeCheck(targetUrl);
      setScopeOk(ok);
      toast(ok ? `Added ${service.host} to target scope` : "Added rule, but target still isn't in scope", ok ? "success" : "error");
    } catch (e) { toast(String(e), "error"); }
  }

  const scopeBlocked = requireScope && scopeOk === false;

  useEffect(() => {
    const un = events.onIntruder((ev) => {
      if (ev.kind === "started") {
        if (ev.attack_id === attackIdRef.current) { setTotal(ev.total); setCapped(ev.capped); }
      } else if (ev.kind === "done") {
        if (ev.attack_id === attackIdRef.current) setRunning(false);
      } else if (ev.kind === "results") {
        // coalesced batch — append in one update to avoid per-request re-renders.
        // Batches carry no attack id; they only arrive while an attack of ours runs.
        if (attackIdRef.current != null && ev.results.length) {
          setResults((prev) => prev.concat(ev.results));
        }
      } else if (ev.kind === "result") {
        // single-result fallback (compat); the engine normally sends batches
        if (attackIdRef.current != null) setResults((prev) => [...prev, ev]);
      }
    });
    return () => { un.then((f) => f()); };
  }, []);

  const posCount = useMemo(() => Math.floor((template.split(MARK).length - 1) / 2), [template]);
  const neededSets = attack === "sniper" || attack === "battering_ram" ? 1 : Math.max(posCount, 1);

  useEffect(() => {
    setSets((prev) => {
      const next = prev.slice(0, neededSets);
      while (next.length < neededSets) next.push("");
      return next;
    });
  }, [neededSets]);

  const buildProcessors = (): Processor[] => {
    const p: Processor[] = [];
    if (prefix) p.push({ type: "prefix", text: prefix });
    if (suffix) p.push({ type: "suffix", text: suffix });
    if (proc.url) p.push({ type: "url_encode" });
    if (proc.b64) p.push({ type: "base64_encode" });
    if (proc.hex) p.push({ type: "hex_encode" });
    if (proc.upper) p.push({ type: "upper" });
    if (proc.lower) p.push({ type: "lower" });
    return p;
  };

  const buildConfig = (): IntruderConfig => ({
    service, template, attack,
    payload_sets: sets.map((s) => s.split("\n").filter((x) => x.length > 0)),
    concurrency: clampThreads(concurrency), delay_ms: clampDelay(delay),
    max_retries: clampRetries(retries), request_timeout_ms: clampTimeout(timeoutS) * 1000,
    processors: buildProcessors(),
  });

  useEffect(() => {
    const id = setTimeout(async () => {
      try { setPreview(await api.intruderPreview(buildConfig())); } catch { setPreview(undefined); }
    }, 300);
    return () => clearTimeout(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [template, attack, JSON.stringify(sets), concurrency, delay, JSON.stringify(proc), prefix, suffix, service]);

  function wrapSelection() {
    const view = viewRef.current;
    if (!view) return;
    const { from, to } = view.state.selection.main;
    view.dispatch({
      changes: [{ from, insert: MARK }, { from: to, insert: MARK }],
      selection: { anchor: from + 1, head: to + 1 },
    });
    view.focus();
  }

  async function start() {
    if (posCount === 0) return;
    const planned = preview?.total ?? 0;
    if (planned > 5000 && !(await confirmAction({
      title: `Send about ${planned.toLocaleString()} requests?`,
      body: "This is a large attack. Make sure the target is in scope and can take the load.",
      confirmLabel: "Start attack",
    }))) return;
    setResults([]); setTotal(0); setCapped(false); setRunning(true);
    try {
      const id = await api.intruderStart(buildConfig());
      attackIdRef.current = id;
    } catch (e) { setRunning(false); attackIdRef.current = undefined; toast(String(e), "error"); }
  }
  function stop() { if (attackIdRef.current != null) api.intruderStop(attackIdRef.current); }

  // Race condition: fire N last-byte-synchronised copies of the request (markers
  // stripped — a race sends the literal request, not a fuzzed one) so they arrive
  // together. Results stream into the same grid via the shared event handler.
  async function race() {
    const count = Math.max(2, Math.min(256, Math.floor(Number(raceCount)) || 20));
    setResults([]); setTotal(0); setCapped(false); setRunning(true);
    try {
      const id = await api.raceStart({ service, request: template.split(MARK).join(""), count, variant: raceVariant });
      attackIdRef.current = id;
    } catch (e) { setRunning(false); attackIdRef.current = undefined; toast(String(e), "error"); }
  }

  const sorted = useMemo(() => {
    const r = [...results];
    r.sort((a, b) => {
      const av = (a[sortKey] ?? 0) as number, bv = (b[sortKey] ?? 0) as number;
      return (av - bv) * sortDir;
    });
    return r;
  }, [results, sortKey, sortDir]);

  const errorCount = useMemo(() => results.reduce((a, r) => a + (r.error ? 1 : 0), 0), [results]);

  const resultsParentRef = useRef<HTMLDivElement>(null);
  const rowVirt = useVirtualizer({
    count: sorted.length,
    getScrollElement: () => resultsParentRef.current,
    estimateSize: () => 25,
    overscan: 20,
  });

  function sortBy(k: typeof sortKey) {
    if (sortKey === k) setSortDir((d) => (d === 1 ? -1 : 1)); else { setSortKey(k); setSortDir(1); }
  }
  const arrow = (k: typeof sortKey) => (sortKey === k ? (sortDir === 1 ? " ▲" : " ▼") : "");

  const predicted = preview?.total == null ? "very large" : preview.total;

  const editorPane = (
    <div className="intr-editor-pane">
      <div className="intr-head">
        <span>Request template</span>
        <span className="mut">Positions <b className="n">{posCount}</b></span>
        <button className="btn" onClick={wrapSelection} title="Wrap the selected text as a payload position">Add §</button>
        <span className="mut small">wrap each spot in § §</span>
      </div>
      <div className="intr-editor">
        <CodeMirror value={template} height="100%" theme="none"
          extensions={[shrikeEditorTheme, EditorView.lineWrapping, markerHighlight]}
          basicSetup={{ lineNumbers: true, foldGutter: false, highlightActiveLine: false }}
          onChange={setTemplate}
          onCreateEditor={(v) => (viewRef.current = v)} />
      </div>
    </div>
  );

  const configPane = (
    <div className="intr-side">
      <div className="intr-target">
        <input className="t-host" value={service.host} onChange={(e) => setService({ ...service, host: e.target.value })} />
        <span className="t-colon">:</span>
        <input className="t-port" value={service.port} inputMode="numeric"
          onChange={(e) => setService({ ...service, port: Number(e.target.value) || service.port })} />
        <label className="t-tls"><input type="checkbox" checked={service.secure}
          onChange={(e) => setService({ ...service, secure: e.target.checked })} /> TLS</label>
      </div>
      <div className="intr-nums">
        <label className="fld">Threads<input value={concurrency} inputMode="numeric"
          onChange={(e) => setConcurrency(e.target.value.replace(/[^0-9]/g, ""))}
          onBlur={() => setConcurrency((v) => String(clampThreads(v)))} /></label>
        <label className="fld">Delay ms<input value={delay} inputMode="numeric"
          onChange={(e) => setDelay(e.target.value.replace(/[^0-9]/g, ""))}
          onBlur={() => setDelay((v) => String(clampDelay(v)))} /></label>
        <label className="fld" title="Re-send a request that fails with a transient error (timeout, connection reset). 0 = never retry.">
          Retries<input value={retries} inputMode="numeric"
          onChange={(e) => setRetries(e.target.value.replace(/[^0-9]/g, ""))}
          onBlur={() => setRetries((v) => String(clampRetries(v)))} /></label>
        <label className="fld" title="Per-request timeout. A stalled request frees its slot after this and (if retries remain) is retried.">
          Timeout s<input value={timeoutS} inputMode="numeric"
          onChange={(e) => setTimeoutS(e.target.value.replace(/[^0-9]/g, ""))}
          onBlur={() => setTimeoutS((v) => String(clampTimeout(v)))} /></label>
      </div>
      <div className="mut small intr-resil">
        Resilient pacing is automatic: runs at full speed when the target is healthy and backs off when it starts timing out, then recovers.
      </div>
      <div className="fld">Payload processing (applied top to bottom)
        <div className="proc-row">
          {([["url","URL"],["b64","Base64"],["hex","Hex"],["upper","Upper"],["lower","Lower"]] as const).map(([k,l]) => (
            <label key={k} className="proc-chk"><input type="checkbox" checked={(proc as any)[k]}
              onChange={(e) => setProc({ ...proc, [k]: e.target.checked })} /> {l}</label>
          ))}
        </div>
        <div className="proc-row">
          <input placeholder="prefix" value={prefix} onChange={(e) => setPrefix(e.target.value)} />
          <input placeholder="suffix" value={suffix} onChange={(e) => setSuffix(e.target.value)} />
        </div>
      </div>
      {sets.map((val, i) => {
        const lineCount = val.split("\n").filter((x) => x.length > 0).length;
        return (
          <div className="fld" key={i}>
            <div className="set-head">
              <span>Payload set {neededSets > 1 ? `#${i + 1} (position ${i + 1})` : ""} <b className="n">{lineCount}</b></span>
              <span className="spacer" />
              <label className="link file-btn">load file
                <input type="file" accept=".txt,.csv,.lst,.list,text/plain" style={{ display: "none" }}
                  onChange={async (e) => {
                    const f = e.target.files?.[0]; if (!f) return;
                    const text = await f.text();
                    const lines = text.split(/\r?\n/).map((l) => (f.name.toLowerCase().endsWith(".csv") ? (l.split(",")[0] ?? l) : l)).filter((l) => l.length > 0);
                    setSets((pp) => pp.map((v, j) => j === i ? (v.trim() ? v + "\n" : "") + lines.join("\n") : v));
                    e.target.value = "";
                  }} />
              </label>
              <button className="link" onClick={async () => {
                try { const t = await navigator.clipboard.readText(); setSets((pp) => pp.map((v, j) => j === i ? (v.trim() ? v + "\n" : "") + t : v)); } catch { /* ignore */ }
              }}>paste</button>
              <button className="link" onClick={() => setSets((pp) => pp.map((v, j) => j === i ? "" : v))}>clear</button>
            </div>
            <textarea rows={5} value={val} spellCheck={false}
              onChange={(e) => setSets((pp) => pp.map((v, j) => j === i ? e.target.value : v))} />
            <PayloadGenerator onAdd={(lines) => setSets((pp) => pp.map((v, j) => j === i ? (v.trim() ? v + "\n" : "") + lines.join("\n") : v))} />
          </div>
        );
      })}
      {showPreview && preview && (
        <pre className="preview-box">{preview.requests.length
          ? preview.requests.map((r, i) => `#${i} ${r.split("\n")[0]}`).join("\n")
          : "no requests generated (add payloads and positions)"}</pre>
      )}
      {posCount === 0 && <div className="warnbar">Mark at least one payload position with § § in the request.</div>}
    </div>
  );

  const resultsPane = (
    <div className="intr-results table">
      <div className="thead">
        <div className="th" style={{ flex: "0 0 56px", cursor: "pointer" }} onClick={() => sortBy("index")}>#{arrow("index")}</div>
        <div className="th" style={{ flex: "2 1 220px" }}>Payload</div>
        <div className="th" style={{ flex: "0 0 70px", cursor: "pointer" }} onClick={() => sortBy("status")}>Status{arrow("status")}</div>
        <div className="th" style={{ flex: "0 0 90px", cursor: "pointer" }} onClick={() => sortBy("length")}>Length{arrow("length")}</div>
        <div className="th" style={{ flex: "0 0 80px", cursor: "pointer" }} onClick={() => sortBy("duration_ms")}>Time{arrow("duration_ms")}</div>
      </div>
      <div className="tbody" ref={resultsParentRef}>
        {sorted.length === 0 && (
          <div className="hint">
            {running
              ? `Sending ${total ? total.toLocaleString() + " " : ""}requests — waiting for the first response. If nothing arrives, the target may be unreachable; each request times out after 30s and will show as ERR.`
              : "results appear here when an attack runs"}
          </div>
        )}
        <div style={{ height: rowVirt.getTotalSize(), width: "100%", position: "relative" }}>
          {rowVirt.getVirtualItems().map((item) => {
            const r = sorted[item.index];
            return (
              <div className={"tr" + (r.error ? " err" : "")} key={r.index} title={r.error ?? undefined}
                style={{ transform: `translateY(${item.start}px)` }}>
                <div className="td num" style={{ flex: "0 0 56px" }}>{r.index}</div>
                <div className="td" style={{ flex: "2 1 220px" }} title={r.error ?? r.payloads.join(" | ")}>{r.payloads.join(" | ")}</div>
                <div className={"td " + statusClass(r.status)} style={{ flex: "0 0 70px" }} title={r.error ?? undefined}>{r.error ? "ERR" : r.status}</div>
                <div className="td num" style={{ flex: "0 0 90px" }}>{r.error ? "" : humanBytes(r.length)}</div>
                <div className="td num" style={{ flex: "0 0 80px" }}>{r.error ? "" : r.duration_ms + " ms"}</div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );

  return (
    <div className="intruder">
      <div className="intr-toolbar">
        <label className="tb-attack">Attack
          <select value={attack} onChange={(e) => setAttack(e.target.value as AttackType)}>
            {ATTACKS.map((a) => <option key={a.v} value={a.v}>{a.label}</option>)}
          </select>
        </label>
        <span className="mut small">{ATTACKS.find((a) => a.v === attack)?.hint}</span>
        <span className="spacer" />
        <span className="preflight"><b>{predicted}</b> requests
          <span className="mut"> · {posCount} pos</span>
          {(preview?.total ?? 0) > 5000 && <span className="warn-inline"> · confirm</span>}
        </span>
        <button className="link" onClick={() => setShowPreview((v) => !v)}>{showPreview ? "hide preview" : "preview"}</button>
        {running
          ? <button className="btn stop" onClick={stop}>■ Stop</button>
          : <>
              <label className="race-ctl" title="Fire this many copies of the request, synchronised to arrive together (race-condition testing)">
                <span className="mut small">race ×</span>
                <input className="num race-num" type="number" min={2} max={256} value={raceCount}
                  onChange={(e) => setRaceCount(e.target.value)} />
                <select className="race-var" value={raceVariant}
                  onChange={(e) => setRaceVariant(e.target.value as typeof raceVariant)}
                  title="last-byte: one connection per copy (works everywhere). HTTP/2: one connection, tighter window (needs an HTTP/2 target)">
                  <option value="last_byte">last-byte</option>
                  <option value="h2_single_packet">HTTP/2</option>
                </select>
              </label>
              <button className="btn" disabled={scopeBlocked} onClick={race}
                title="Race condition: send N synchronised copies at once">⇉ Race</button>
              <button className="btn start" disabled={posCount === 0 || scopeBlocked} onClick={start}>▶ Start</button>
            </>}
        <span className="mut small">{results.length}{total ? `/${total}` : ""}{errorCount ? ` · ${errorCount} err` : ""}{running ? " · running" : ""}{capped ? " · capped" : ""}</span>
      </div>
      {scopeBlocked && (
        <div className="warnbar intr-scopebar">
          <span><b>{service.host}</b> isn’t in your target scope, so Intruder will refuse this attack.</span>
          <button className="link" onClick={addTargetToScope}>Add {service.host} to scope</button>
          <span className="mut small">or turn off “require scope for Intruder” in Settings.</span>
        </div>
      )}
      <SplitPane direction="vertical" storageKey="shrike.intr.v" defaultSize={64}
        first={
          <SplitPane direction="horizontal" storageKey="shrike.intr.h" defaultSize={58}
            first={editorPane} second={configPane} />
        }
        second={resultsPane}
      />
    </div>
  );
}

type GenKind = "numbers" | "brute_force" | "case_variations" | "null_payloads";

/** Compact payload-generator disclosure attached to a payload set. */
function PayloadGenerator(props: { onAdd: (lines: string[]) => void }) {
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState<GenKind>("numbers");
  const [from, setFrom] = useState("1");
  const [to, setTo] = useState("100");
  const [step, setStep] = useState("1");
  const [charset, setCharset] = useState("abc123");
  const [minLen, setMinLen] = useState("1");
  const [maxLen, setMaxLen] = useState("3");
  const [word, setWord] = useState("admin");
  const [count, setCount] = useState("10");
  const [err, setErr] = useState("");

  async function run() {
    setErr("");
    let g: Generator;
    if (kind === "numbers") g = { kind, from: Number(from) || 0, to: Number(to) || 0, step: Number(step) || 1 };
    else if (kind === "brute_force") g = { kind, charset, min_len: Number(minLen) || 1, max_len: Number(maxLen) || 1 };
    else if (kind === "case_variations") g = { kind, word };
    else g = { kind: "null_payloads", count: Number(count) || 0 };
    try {
      const lines = await api.intruderGenerate(g);
      props.onAdd(lines);
      if (lines.length === 0) setErr("generated 0 payloads");
    } catch (e) { setErr(String(e)); }
  }

  return (
    <div className="pl-gen">
      <button className="link" onClick={() => setOpen((o) => !o)}>{open ? "− generator" : "+ generator"}</button>
      {open && (
        <div className="pl-gen-form">
          <select value={kind} onChange={(e) => setKind(e.target.value as GenKind)}>
            <option value="numbers">Numbers</option>
            <option value="brute_force">Brute force</option>
            <option value="case_variations">Case variations</option>
            <option value="null_payloads">Null payloads</option>
          </select>
          {kind === "numbers" && <>
            <input value={from} onChange={(e) => setFrom(e.target.value)} placeholder="from" title="from" />
            <input value={to} onChange={(e) => setTo(e.target.value)} placeholder="to" title="to" />
            <input value={step} onChange={(e) => setStep(e.target.value)} placeholder="step" title="step" />
          </>}
          {kind === "brute_force" && <>
            <input value={charset} onChange={(e) => setCharset(e.target.value)} placeholder="charset" title="charset" />
            <input value={minLen} onChange={(e) => setMinLen(e.target.value)} placeholder="min" title="min length" />
            <input value={maxLen} onChange={(e) => setMaxLen(e.target.value)} placeholder="max" title="max length" />
          </>}
          {kind === "case_variations" && <input value={word} onChange={(e) => setWord(e.target.value)} placeholder="word" />}
          {kind === "null_payloads" && <input value={count} onChange={(e) => setCount(e.target.value)} placeholder="count" />}
          <button className="btn" onClick={run}>Add</button>
          {err && <span className="warn-inline small">{err}</span>}
        </div>
      )}
    </div>
  );
}
