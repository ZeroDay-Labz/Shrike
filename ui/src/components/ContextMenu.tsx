import { useEffect, useRef } from "react";

export interface MenuItem {
  label: string;
  onClick: () => void;
  disabled?: boolean;
  danger?: boolean;
  separatorBefore?: boolean;
}

export function ContextMenu(props: { x: number; y: number; items: MenuItem[]; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const close = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) props.onClose(); };
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") props.onClose(); };
    window.addEventListener("mousedown", close);
    window.addEventListener("keydown", esc);
    window.addEventListener("resize", props.onClose);
    return () => {
      window.removeEventListener("mousedown", close);
      window.removeEventListener("keydown", esc);
      window.removeEventListener("resize", props.onClose);
    };
  }, [props]);

  // keep the menu on-screen
  const x = Math.min(props.x, window.innerWidth - 230);
  const y = Math.min(props.y, window.innerHeight - props.items.length * 30 - 12);

  return (
    <div className="ctxmenu" ref={ref} style={{ left: x, top: y }} onContextMenu={(e) => e.preventDefault()}>
      {props.items.map((it, i) => (
        <div key={i}>
          {it.separatorBefore && <div className="ctx-sep" />}
          <button
            className={"ctx-item" + (it.danger ? " danger" : "")}
            disabled={it.disabled}
            onClick={() => { if (!it.disabled) { it.onClick(); props.onClose(); } }}
          >
            {it.label}
          </button>
        </div>
      ))}
    </div>
  );
}
