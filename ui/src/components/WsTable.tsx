import type { WsMessage } from "../types";
import { humanBytes } from "../util";

export function WsTable(props: { rows: WsMessage[] }) {
  return (
    <div className="table ws">
      <div className="thead">
        <div className="th" style={{ flex: "0 0 60px" }}>Dir</div>
        <div className="th" style={{ flex: "0 0 66px" }}>Kind</div>
        <div className="th" style={{ flex: "0 0 72px" }}>Len</div>
        <div className="th" style={{ flex: "1 1 240px" }}>URL</div>
        <div className="th" style={{ flex: "2 1 300px" }}>Preview</div>
      </div>
      <div className="tbody static">
        {props.rows.map((w, i) => (
          <div className="tr" key={i}>
            <div className={"td " + (w.direction === "c2s" ? "s-3xx" : "s-2xx")} style={{ flex: "0 0 60px" }}>
              {w.direction === "c2s" ? "▲ out" : "▼ in"}
            </div>
            <div className="td" style={{ flex: "0 0 66px" }}>{w.kind}</div>
            <div className="td num" style={{ flex: "0 0 72px" }}>{humanBytes(w.len)}</div>
            <div className="td mut" style={{ flex: "1 1 240px" }} title={w.url}>{w.url}</div>
            <div className="td mono-cell" style={{ flex: "2 1 300px" }}>{w.text ?? ""}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
