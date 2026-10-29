import type React from "react";
import { useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { TransactionSummary } from "../types";
import { humanBytes, shortMime, statusClass, timeFull, timeShort } from "../util";
import { Icon } from "./Icon";

// Fixed-width columns are sized to content; host and URL flex to fill the window,
// so the table always fits horizontally — no left/right scrolling.
type Col = { key: string; label: string; flex: string; title?: string };
const COLS: Col[] = [
  { key: "id", label: "#", flex: "0 0 52px" },
  { key: "method", label: "Method", flex: "0 0 70px" },
  { key: "host", label: "Host", flex: "1 1 130px" },
  { key: "url", label: "Path", flex: "3 1 240px" },
  { key: "status", label: "Status", flex: "0 0 62px" },
  { key: "mime", label: "Type", flex: "0 0 64px", title: "Response media type" },
  { key: "len", label: "Size", flex: "0 0 72px", title: "Response body size" },
  { key: "time", label: "ms", flex: "0 0 56px", title: "Round-trip time" },
  { key: "when", label: "Time", flex: "0 0 72px" },
];

const ROW_H = 26;

/** Keyboard actions the table hands back to its owner for the selected row. */
export type RowAction = "repeater" | "intruder" | "menu";

export function HistoryTable(props: {
  rows: TransactionSummary[];
  selectedId?: number;
  onSelect: (id: number) => void;
  onContextMenu?: (e: React.MouseEvent, row: TransactionSummary) => void;
  onAction?: (action: RowAction, row: TransactionSummary, at: { x: number; y: number }) => void;
}) {
  const parentRef = useRef<HTMLDivElement>(null);
  const v = useVirtualizer({
    count: props.rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_H,
    overscan: 20,
  });

  const selIndex = props.rows.findIndex((r) => r.id === props.selectedId);

  function selectAt(i: number) {
    if (props.rows.length === 0) return;
    const idx = Math.max(0, Math.min(props.rows.length - 1, i));
    props.onSelect(props.rows[idx].id);
    v.scrollToIndex(idx, { align: "auto" });
  }

  function onKeyDown(e: React.KeyboardEvent) {
    const page = Math.max(1, Math.floor((parentRef.current?.clientHeight ?? ROW_H * 10) / ROW_H) - 1);
    const mod = e.ctrlKey || e.metaKey;
    const row = selIndex >= 0 ? props.rows[selIndex] : undefined;
    const at = () => {
      const box = parentRef.current?.getBoundingClientRect();
      const top = (box?.top ?? 0) + (selIndex * ROW_H - (parentRef.current?.scrollTop ?? 0));
      return { x: (box?.left ?? 0) + 120, y: top + ROW_H };
    };
    let handled = true;
    if (e.key === "ArrowDown") selectAt(selIndex < 0 ? 0 : selIndex + 1);
    else if (e.key === "ArrowUp") selectAt(selIndex < 0 ? 0 : selIndex - 1);
    else if (e.key === "PageDown") selectAt((selIndex < 0 ? 0 : selIndex) + page);
    else if (e.key === "PageUp") selectAt((selIndex < 0 ? 0 : selIndex) - page);
    else if (e.key === "Home") selectAt(0);
    else if (e.key === "End") selectAt(props.rows.length - 1);
    else if (row && (e.key === "Enter" || (mod && e.key.toLowerCase() === "r"))) props.onAction?.("repeater", row, at());
    else if (row && mod && e.key.toLowerCase() === "i") props.onAction?.("intruder", row, at());
    else if (row && (e.key === "ContextMenu" || (e.shiftKey && e.key === "F10"))) props.onAction?.("menu", row, at());
    else handled = false;
    if (handled) e.preventDefault();
  }

  const cell = (c: Col, extra: string, content: React.ReactNode, title?: string) => (
    <div className={"td " + extra} style={{ flex: c.flex }} title={title} role="gridcell">{content}</div>
  );

  return (
    <div className="table" role="grid" aria-rowcount={props.rows.length} aria-label="HTTP history">
      <div className="thead" role="row">
        {COLS.map((c) => (
          <div key={c.key} className={"th" + (["id", "len", "time"].includes(c.key) ? " num" : "")}
            style={{ flex: c.flex }} title={c.title} role="columnheader">{c.label}</div>
        ))}
      </div>
      <div className="tbody" ref={parentRef} tabIndex={0} onKeyDown={onKeyDown}
        aria-activedescendant={props.selectedId != null ? `hrow-${props.selectedId}` : undefined}>
        {props.rows.length === 0 && (
          <div className="table-empty">
            <Icon name="inbox" size={22} />
            <div>No traffic yet</div>
            <div className="mut small">Start the proxy and open the browser, or point any client at it.</div>
          </div>
        )}
        <div style={{ height: v.getTotalSize(), width: "100%", position: "relative" }}>
          {v.getVirtualItems().map((item) => {
            const r = props.rows[item.index];
            const sel = r.id === props.selectedId;
            return (
              <div
                key={r.id}
                id={`hrow-${r.id}`}
                role="row"
                aria-selected={sel}
                className={"tr" + (sel ? " sel" : "") + (r.error ? " err" : "")}
                style={{ transform: `translateY(${item.start}px)`, height: ROW_H }}
                onClick={() => { props.onSelect(r.id); parentRef.current?.focus(); }}
                onDoubleClick={(e) => props.onAction?.("repeater", r, { x: e.clientX, y: e.clientY })}
                onContextMenu={(e) => props.onContextMenu?.(e, r)}
              >
                {cell(COLS[0], "num", r.id)}
                {cell(COLS[1], "method m-" + r.method.toLowerCase(), r.method)}
                {cell(COLS[2], "mut host", (
                  <>{r.secure && <Icon name="lock" size={11} className="lock" />}{r.host}</>
                ), (r.secure ? "https://" : "http://") + r.host)}
                {cell(COLS[3], "url", pathOf(r.url), r.url)}
                {cell(COLS[4], "", r.status != null
                  ? <span className={"status " + statusClass(r.status)}>{r.status}</span>
                  : <span className={"status " + (r.error ? "s-5xx" : "s-none")}>{r.error ? "ERR" : "…"}</span>,
                  r.error ?? undefined)}
                {cell(COLS[5], "mut", shortMime(r.mime), r.mime ?? undefined)}
                {cell(COLS[6], "num", r.resp_len ? humanBytes(r.resp_len) : "—")}
                {cell(COLS[7], "num", r.duration_ms)}
                {cell(COLS[8], "mut", timeShort(r.started_at_ms), timeFull(r.started_at_ms))}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function pathOf(url: string): string {
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch { return url; }
}
