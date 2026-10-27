import { Decoration, type DecorationSet, EditorView, ViewPlugin, type ViewUpdate } from "@codemirror/view";
import { RangeSetBuilder } from "@codemirror/state";

const MARK = "§"; // §

const content = Decoration.mark({ class: "cm-pos" });
const marker = Decoration.mark({ class: "cm-pos-marker" });

function build(view: EditorView): DecorationSet {
  const builder = new RangeSetBuilder<Decoration>();
  const text = view.state.doc.toString();
  const idx: number[] = [];
  for (let i = 0; i < text.length; i++) if (text[i] === MARK) idx.push(i);
  for (let k = 0; k + 1 < idx.length; k += 2) {
    const start = idx[k], end = idx[k + 1];
    builder.add(start, start + 1, marker);
    if (end > start + 1) builder.add(start + 1, end, content);
    builder.add(end, end + 1, marker);
  }
  return builder.finish();
}

/** Colors each §…§ payload position (and its markers) in a CodeMirror editor. */
export const markerHighlight = ViewPlugin.fromClass(
  class {
    decorations: DecorationSet;
    constructor(view: EditorView) { this.decorations = build(view); }
    update(u: ViewUpdate) {
      if (u.docChanged || u.viewportChanged) this.decorations = build(u.view);
    }
  },
  { decorations: (v) => v.decorations },
);
