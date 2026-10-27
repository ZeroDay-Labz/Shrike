import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";

function load(key: string, def: number): number {
  try { const v = localStorage.getItem(key); return v ? Number(v) : def; } catch { return def; }
}

/** Two panes with a draggable divider. Size (% of the first pane) persists. */
export function SplitPane(props: {
  direction: "vertical" | "horizontal";
  storageKey: string;
  defaultSize: number;
  min?: number;
  max?: number;
  first: ReactNode;
  second: ReactNode;
}) {
  const { direction, storageKey, defaultSize, min = 12, max = 88 } = props;
  const vertical = direction === "vertical";
  const [size, setSize] = useState(() => load(storageKey, defaultSize));
  const [dragging, setDragging] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => { try { localStorage.setItem(storageKey, String(size)); } catch { /* ignore */ } }, [size, storageKey]);

  const onDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    const el = ref.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    setDragging(true);
    const move = (ev: MouseEvent) => {
      const pct = vertical
        ? ((ev.clientY - rect.top) / rect.height) * 100
        : ((ev.clientX - rect.left) / rect.width) * 100;
      setSize(Math.max(min, Math.min(max, pct)));
    };
    const up = () => {
      setDragging(false);
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  }, [vertical, min, max]);

  const firstStyle = vertical ? { height: `${size}%` } : { width: `${size}%` };

  return (
    <div className={"splitpane " + (vertical ? "v" : "h")} ref={ref}>
      <div className="sp-first" style={firstStyle}>{props.first}</div>
      <div className={"sp-divider " + (vertical ? "v" : "h")} onMouseDown={onDown} />
      <div className="sp-second">{props.second}</div>
      {dragging && <div className="sp-overlay" style={{ cursor: vertical ? "row-resize" : "col-resize" }} />}
    </div>
  );
}
