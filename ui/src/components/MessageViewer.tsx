import { useMemo, useState } from "react";
import CodeMirror from "@uiw/react-codemirror";
import { EditorView } from "@codemirror/view";
import { json } from "@codemirror/lang-json";
import { html } from "@codemirror/lang-html";
import type { RequestView, ResponseView } from "../types";
import { bodyBytes, hexDump, prettyBody, rawRequest, rawResponse } from "../util";
import { shrikeEditorTheme } from "../cm-theme";

type View = "raw" | "pretty" | "hex";

export function MessageViewer(props: {
  title: string;
  request?: RequestView;
  response?: ResponseView;
}) {
  const { request, response } = props;
  const [view, setView] = useState<View>("pretty");
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

function langFor(mime?: string) {
  const m = (mime ?? "").toLowerCase();
  if (m.includes("json")) return json();
  if (m.includes("html") || m.includes("xml")) return html();
  return undefined;
}
