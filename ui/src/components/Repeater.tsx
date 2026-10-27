import CodeMirror from "@uiw/react-codemirror";
import { EditorView } from "@codemirror/view";
import type { RepeaterTab } from "../repeater";
import { MessageViewer } from "./MessageViewer";
import { humanBytes, statusClass } from "../util";
import { SplitPane } from "./SplitPane";
import { shrikeEditorTheme } from "../cm-theme";

export function Repeater(props: {
  tabs: RepeaterTab[];
  activeId?: number;
  onActivate: (id: number) => void;
  onClose: (id: number) => void;
  onEditRaw: (id: number, raw: string) => void;
  onEditService: (id: number, patch: Partial<RepeaterTab["service"]>) => void;
  onSend: (id: number) => void;
  onNew: () => void;
}) {
  const tab = props.tabs.find((t) => t.id === props.activeId) ?? props.tabs[0];

  if (props.tabs.length === 0) {
    return (
      <div className="placeholder">
        <h2>Repeater</h2>
        <p>Send a captured request here from Proxy history (select it, then <b>⤷ Send to Repeater</b>),
          or start one from scratch.</p>
        <button className="btn start" onClick={props.onNew}>+ New request</button>
      </div>
    );
  }

  return (
    <div className="repeater">
      <div className="rep-tabs">
        <button className="rep-new" title="New request" onClick={props.onNew}>+</button>
        {props.tabs.map((t) => (
          <div key={t.id} className={"rep-tab" + (t.id === tab.id ? " on" : "")} onClick={() => props.onActivate(t.id)}>
            <span className="rep-tab-name">{t.name}</span>
            <button className="rep-tab-x" onClick={(e) => { e.stopPropagation(); props.onClose(t.id); }}>✕</button>
          </div>
        ))}
      </div>

      {tab && (
        <div className="rep-body">
          <SplitPane direction="horizontal" storageKey="shrike.rep.h" defaultSize={50} first={
          <div className="rep-left">
            <div className="rep-target">
              <input className="t-host" value={tab.service.host}
                onChange={(e) => props.onEditService(tab.id, { host: e.target.value })} />
              <span className="t-colon">:</span>
              <input className="t-port" value={tab.service.port} inputMode="numeric"
                onChange={(e) => props.onEditService(tab.id, { port: Number(e.target.value) || tab.service.port })} />
              <label className="t-tls">
                <input type="checkbox" checked={tab.service.secure}
                  onChange={(e) => props.onEditService(tab.id, { secure: e.target.checked })} /> TLS
              </label>
              <button className="btn start rep-send" disabled={tab.sending} onClick={() => props.onSend(tab.id)}>
                {tab.sending ? "Sending…" : "▶ Send"}
              </button>
            </div>
            <div className="rep-editor">
              <CodeMirror
                value={tab.raw}
                height="100%"
                theme="none"
                extensions={[shrikeEditorTheme, EditorView.lineWrapping]}
                basicSetup={{ lineNumbers: true, foldGutter: false, highlightActiveLine: false }}
                onChange={(v) => props.onEditRaw(tab.id, v)}
              />
            </div>
          </div>
          } second={
          <div className="rep-right">
            <div className="rep-status">
              {tab.error ? (
                <span className="s-5xx">error: {tab.error}</span>
              ) : tab.responseView ? (
                <>
                  <span className={statusClass(tab.status)}>{tab.status} {tab.responseView.reason}</span>
                  <span className="mut">{humanBytes(tab.responseView.body.wire_len)}</span>
                  <span className="mut">{tab.durationMs} ms</span>
                </>
              ) : (
                <span className="mut">no response yet — press Send</span>
              )}
            </div>
            <div className="rep-response">
              {tab.responseView
                ? <MessageViewer title="Response" response={tab.responseView} />
                : <div className="hint">response appears here</div>}
            </div>
          </div>
          } />
        </div>
      )}
    </div>
  );
}
