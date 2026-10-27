import { useEffect, useState } from "react";
import type { TransactionSummary, TransactionView } from "../types";
import { api } from "../api";
import { HistoryTable } from "./HistoryTable";
import { MessageViewer } from "./MessageViewer";
import { SplitPane } from "./SplitPane";

/** A unified chronological log of all HTTP traffic, with a request/response viewer. */
export function Logger(props: {
  rows: TransactionSummary[];
  onContextMenu: (e: React.MouseEvent, row: TransactionSummary) => void;
}) {
  const [selId, setSelId] = useState<number>();
  const [detail, setDetail] = useState<TransactionView>();
  const [q, setQ] = useState("");

  useEffect(() => {
    if (selId == null) { setDetail(undefined); return; }
    api.historyGet(selId).then((d) => setDetail(d ?? undefined));
  }, [selId]);

  const rows = q
    ? props.rows.filter((r) =>
        r.url.toLowerCase().includes(q.toLowerCase()) || r.host.toLowerCase().includes(q.toLowerCase()))
    : props.rows;

  return (
    <div className="logger">
      <div className="logger-bar">
        <span className="mut">{rows.length} of {props.rows.length} entries</span>
        <input className="logger-search" placeholder="filter host or URL…" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <SplitPane
        direction="vertical" storageKey="shrike.logger.v" defaultSize={48}
        first={<HistoryTable rows={rows} selectedId={selId} onSelect={setSelId} onContextMenu={props.onContextMenu} />}
        second={detail ? (
          <div className="detail">
            <div className="detailbar">
              <span className="detail-url" title={detail.request.url}>{detail.request.method} {detail.request.url}</span>
            </div>
            <SplitPane
              direction="horizontal" storageKey="shrike.logger.h" defaultSize={50}
              first={<MessageViewer title="Request" request={detail.request} />}
              second={<MessageViewer title={detail.response ? `Response · ${detail.response.status}` : (detail.error ? "Error" : "Response")} response={detail.response} />}
            />
            {detail.error && <div className="errbar">upstream error: {detail.error}</div>}
          </div>
        ) : (
          <div className="hint">select an entry to inspect its request and response</div>
        )}
      />
    </div>
  );
}
