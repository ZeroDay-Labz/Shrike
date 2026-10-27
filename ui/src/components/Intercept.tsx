import { useEffect, useState } from "react";
import CodeMirror from "@uiw/react-codemirror";
import { EditorView } from "@codemirror/view";
import type { InterceptItem } from "../types";
import { shrikeEditorTheme } from "../cm-theme";

/** The panel shown while a request is held at the proxy, awaiting a decision. */
export function Intercept(props: {
  item: InterceptItem;
  queued: number;
  onForward: (id: number, raw: string) => void;
  onDrop: (id: number) => void;
  onForwardAll: (id: number, raw: string) => void;
  onDropAll: () => void;
}) {
  const [raw, setRaw] = useState(props.item.raw);
  // Reset the editor whenever a different held request becomes the active one.
  useEffect(() => setRaw(props.item.raw), [props.item.id, props.item.raw]);

  const origin = `${props.item.secure ? "https" : "http"}://${props.item.host}:${props.item.port}`;

  return (
    <div className="intercept">
      <div className="intercept-bar">
        <span className="s-5xx">⏸ Request intercepted</span>
        <span className="mut">{origin}</span>
        {props.queued > 1 && <span className="mut">· {props.queued - 1} more queued</span>}
        <span className="spacer" />
        <button className="btn start" onClick={() => props.onForward(props.item.id, raw)}>▶ Forward</button>
        <button className="btn stop" onClick={() => props.onDrop(props.item.id)}>✕ Drop</button>
        {props.queued > 1 && (
          <>
            <button className="btn" onClick={() => props.onForwardAll(props.item.id, raw)} title="Forward this (with edits) and all queued requests">▶▶ Forward all</button>
            <button className="btn" onClick={props.onDropAll} title="Drop every queued request">✕✕ Drop all</button>
          </>
        )}
      </div>
      <div className="intercept-editor">
        <CodeMirror
          value={raw}
          height="100%"
          theme="none"
          extensions={[shrikeEditorTheme, EditorView.lineWrapping]}
          basicSetup={{ lineNumbers: true, foldGutter: false, highlightActiveLine: false }}
          onChange={setRaw}
        />
      </div>
    </div>
  );
}
