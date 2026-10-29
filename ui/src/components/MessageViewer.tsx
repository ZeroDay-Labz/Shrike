import { useMemo, useState } from "react";
import CodeMirror from "@uiw/react-codemirror";
import { EditorView } from "@codemirror/view";
import { json } from "@codemirror/lang-json";
import { html } from "@codemirror/lang-html";
import type { BodyView, RequestView, ResponseView } from "../types";
import { bodyBytes, hexDump, humanBytes, prettyBody, rawRequest, rawResponse } from "../util";
import { shrikeEditorTheme } from "../cm-theme";

type View = "raw" | "pretty" | "hex";

export function MessageViewer(props: {
  title: string;
  request?: RequestView;
  response?: ResponseView;
}) {
  const { request, response } = props;
  const [view, setView] = useState<View>("pretty");
  const body = request?.body ?? response?.body;
  const mime = response?.mime;

  const { text, lang } = useMemo(() => {
    if (!request && !response) return { text: "", lang: undefined as any };
    if (view === "raw") {
      return { text: request ? rawRequest(request) : rawResponse(response!), lang: undefined };
    }
    if (view === "hex") {
      const body = request ? request.body : response!.body;
      return { text: hexDump(bodyBytes(body)), lang: undefined };
    }
    // pretty
    const body = request ? request.body : response!.body;
    const head = request ? rawRequest(request).split("\r\n\r\n")[0] : rawResponse(response!).split("\r\n\r\n")[0];
    return { text: head + "\n\n" + prettyBody(body, mime), lang: langFor(mime) };
  }, [request, response, view, mime]);

  const extensions = lang
    ? [shrikeEditorTheme, EditorView.lineWrapping, lang]
    : [shrikeEditorTheme, EditorView.lineWrapping];

  return (
    <div className="viewer">
      <div className="viewer-head">
        <span className="viewer-title">{props.title}</span>
        {body && <BodyBadge body={body} />}
        <span className="spacer" />
        <div className="seg">
          {(["pretty", "raw", "hex"] as View[]).map((v) => (
            <button key={v} className={view === v ? "on" : ""} onClick={() => setView(v)}>{v}</button>
          ))}
        </div>
      </div>
      <div className="viewer-body">
        <CodeMirror
          value={text}
          height="100%"
          readOnly
          theme="none"
          extensions={extensions}
          basicSetup={{ lineNumbers: true, foldGutter: false, highlightActiveLine: false }}
        />
      </div>
    </div>
  );
}

/**
 * Body size, and — when the capture is partial — an explicit warning so a
 * truncated or streamed body is never mistaken for the whole message.
 */
export function BodyBadge(props: { body: BodyView }) {
  const { len, wire_len, complete } = props.body;
  if (complete) {
    return <span className="body-badge" title="The complete body was captured">{humanBytes(len)}</span>;
  }
  if (len === 0) {
    return (
      <span className="body-badge partial"
        title="The body was too large to capture, so it was streamed through without being recorded. It was forwarded in full.">
        body not captured · {humanBytes(wire_len)} streamed
      </span>
    );
  }
  return (
    <span className="body-badge partial"
      title={`Only the first ${humanBytes(len)} of this body was recorded (the capture limit). The full body was forwarded unchanged; for very large streamed bodies the total size is a lower bound.`}>
      partial · first {humanBytes(len)} of ≥ {humanBytes(wire_len)}
    </span>
  );
}

function langFor(mime?: string) {
  const m = (mime ?? "").toLowerCase();
  if (m.includes("json")) return json();
  if (m.includes("html") || m.includes("xml")) return html();
  return undefined;
}
