import type React from "react";
import { useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { TransactionSummary } from "../types";
import { humanBytes, statusClass, timeShort } from "../util";

// Fixed-width columns are sized to content; host and URL flex to fill the window,
// so the table always fits horizontally — no left/right scrolling.
type Col = { key: string; label: string; flex: string };
const COLS: Col[] = [
  { key: "id", label: "#", flex: "0 0 48px" },
  { key: "method", label: "Method", flex: "0 0 66px" },
  { key: "host", label: "Host", flex: "1 1 150px" },
  { key: "url", label: "URL", flex: "2 1 220px" },
  { key: "status", label: "St", flex: "0 0 50px" },
  { key: "mime", label: "Type", flex: "0 1 110px" },
  { key: "len", label: "Len", flex: "0 0 68px" },
  { key: "time", label: "ms", flex: "0 0 58px" },
  { key: "when", label: "Time", flex: "0 0 96px" },
];

export function HistoryTable(props: {
  rows: TransactionSummary[];
  selectedId?: number;
  onSelect: (id: number) => void;
  onContextMenu?: (e: React.MouseEvent, row: TransactionSummary) => void;
}) {
  const parentRef = useRef<HTMLDivElement>(null);
  const v = useVirtualizer({
    count: props.rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 24,
    overscan: 20,
  });

  const cell = (c: Col, extra: string, content: React.ReactNode, title?: string) => (
    <div className={"td " + extra} style={{ flex: c.flex }} title={title}>{content}</div>
  );

  return (
    <div className="table">
      <div className="thead">
        {COLS.map((c) => (
          <div key={c.key} className="th" style={{ flex: c.flex }}>{c.label}</div>
        ))}
      </div>
      <div className="tbody" ref={parentRef}>
        <div style={{ height: v.getTotalSize(), width: "100%", position: "relative" }}>
          {v.getVirtualItems().map((item) => {
            const r = props.rows[item.index];
            const sel = r.id === props.selectedId;
            return (
              <div
                key={r.id}
                className={"tr" + (sel ? " sel" : "") + (r.error ? " err" : "")}
                style={{ transform: `translateY(${item.start}px)` }}
                onClick={() => props.onSelect(r.id)}
                onContextMenu={(e) => props.onContextMenu?.(e, r)}
              >
                {cell(COLS[0], "num", r.id)}
                {cell(COLS[1], "", r.method)}
                {cell(COLS[2], "mut", `${r.secure ? "🔒 " : ""}${r.host}`, r.host)}
                {cell(COLS[3], "url", pathOf(r.url), r.url)}
                {cell(COLS[4], statusClass(r.status), r.status ?? (r.error ? "ERR" : "…"))}
                {cell(COLS[5], "mut", r.mime ?? "", r.mime ?? undefined)}
                {cell(COLS[6], "num", humanBytes(r.resp_len))}
                {cell(COLS[7], "num", r.duration_ms)}
                {cell(COLS[8], "mut", timeShort(r.started_at_ms))}
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
