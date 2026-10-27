import { useEffect, useMemo, useRef, useState } from "react";
import { Icon } from "./Icon";

export interface Command {
  id: string;
  label: string;
  section: string;
  icon?: string;
  tag?: string;
  run: () => void;
}

/** ⌘K / Ctrl-K palette to jump to any tool or run a quick action. */
export function CommandPalette(props: { open: boolean; onClose: () => void; commands: Command[] }) {
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const activeRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => { if (props.open) { setQ(""); setSel(0); } }, [props.open]);

  const filtered = useMemo(() => {
    const needle = q.toLowerCase().trim();
    return needle ? props.commands.filter((c) => c.label.toLowerCase().includes(needle)) : props.commands;
  }, [props.commands, q]);

  useEffect(() => { setSel(0); }, [q]);
  useEffect(() => { activeRef.current?.scrollIntoView({ block: "nearest" }); }, [sel]);

  if (!props.open) return null;

  const run = (c?: Command) => { if (!c) return; props.onClose(); c.run(); };

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(s + 1, filtered.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
    else if (e.key === "Enter") { e.preventDefault(); run(filtered[sel]); }
    else if (e.key === "Escape") { e.preventDefault(); props.onClose(); }
  };

  let lastSection = "";
  return (
    <div className="cmdk-backdrop" onMouseDown={props.onClose}>
      <div className="cmdk" onMouseDown={(e) => e.stopPropagation()}>
        <input
          className="cmdk-input"
          autoFocus
          placeholder="Search tools and actions…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={onKey}
        />
        <div className="cmdk-list">
          {filtered.length === 0 && <div className="cmdk-empty">No matches</div>}
          {filtered.map((c, i) => {
            const header = c.section !== lastSection ? c.section : null;
            lastSection = c.section;
            return (
              <div key={c.id}>
                {header && <div className="cmdk-section">{header}</div>}
                <button
                  ref={i === sel ? activeRef : null}
                  className={"cmdk-item" + (i === sel ? " active" : "")}
                  onMouseEnter={() => setSel(i)}
                  onClick={() => run(c)}
                >
                  <span className="ico"><Icon name={c.icon ?? "bolt"} size={17} /></span>
                  <span className="cmdk-label">{c.label}</span>
                  {c.tag && <span className="cmdk-tag">{c.tag}</span>}
                </button>
              </div>
            );
          })}
        </div>
        <div className="cmdk-foot">
          <span><span className="kbd">↑</span><span className="kbd">↓</span> navigate</span>
          <span><span className="kbd">↵</span> select</span>
          <span><span className="kbd">esc</span> close</span>
        </div>
      </div>
    </div>
  );
}
