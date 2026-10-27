import { EditorView } from "@codemirror/view";

/**
 * One editor theme shared by every CodeMirror in the app. It is driven entirely
 * by CSS custom properties, so editors follow the light/dark toggle for free.
 * Pass `theme="none"` to <CodeMirror> so @uiw does not impose its own palette.
 */
export const shrikeEditorTheme = EditorView.theme({
  "&": { backgroundColor: "var(--editor-bg)", color: "var(--editor-fg)", height: "100%" },
  ".cm-content": {
    fontFamily: "var(--mono)",
    fontSize: "12.5px",
    caretColor: "var(--editor-caret)",
    padding: "6px 0",
  },
  ".cm-gutters": {
    backgroundColor: "var(--editor-bg)",
    color: "var(--editor-gutter)",
    border: "none",
  },
  ".cm-lineNumbers .cm-gutterElement": { padding: "0 6px 0 10px" },
  ".cm-cursor, .cm-dropCursor": { borderLeftColor: "var(--editor-caret)", borderLeftWidth: "2px" },
  // Selection: a translucent highlight drawn *behind* the glyphs so the text
  // stays fully legible, covering CodeMirror's drawn-selection layer and native
  // selection alike. Text keeps its own colour on top.
  ".cm-selectionLayer .cm-selectionBackground, &.cm-focused .cm-selectionLayer .cm-selectionBackground, .cm-selectionBackground":
    { background: "var(--editor-selection) !important" },
  "&.cm-focused .cm-selectionBackground": { background: "var(--editor-selection) !important" },
  ".cm-content ::selection, .cm-line::selection": { background: "var(--editor-selection)", color: "var(--editor-fg)" },
  // Subtle current-line highlight so the cursor position reads clearly.
  ".cm-activeLine": { backgroundColor: "var(--editor-active-line)" },
  ".cm-activeLineGutter": { backgroundColor: "var(--editor-active-line)" },
  // Matching bracket + search match stay readable.
  ".cm-matchingBracket": { backgroundColor: "var(--editor-selection)", outline: "none", color: "var(--editor-fg)" },
  "&.cm-focused": { outline: "none" },
  ".cm-scroller": { fontFamily: "var(--mono)", lineHeight: "1.5" },
});
