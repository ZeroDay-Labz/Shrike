import { useEffect, useRef, useState } from "react";

// App-wide overlays: a confirmation dialog and transient toasts. Each is driven
// by a module-level function so any component (or plain callback) can use it
// without threading props; the host components render the current state.

// ---- confirm -----------------------------------------------------------------

export interface ConfirmOptions {
  title: string;
  body?: string;
  confirmLabel?: string;
  /** Style the confirm button as destructive. */
  danger?: boolean;
}

type ConfirmRequest = ConfirmOptions & { resolve: (ok: boolean) => void };
let showConfirm: ((r: ConfirmRequest) => void) | null = null;

/** Ask the user to confirm an action. Resolves false if dismissed. */
export function confirmAction(opts: ConfirmOptions): Promise<boolean> {
  return new Promise((resolve) => {
    if (!showConfirm) { resolve(window.confirm(opts.title)); return; }
    showConfirm({ ...opts, resolve });
  });
}

export function ConfirmHost() {
  const [req, setReq] = useState<ConfirmRequest | null>(null);
  const okRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    showConfirm = (r) => setReq((cur) => { cur?.resolve(false); return r; });
    return () => { showConfirm = null; };
  }, []);

  useEffect(() => {
    if (!req) return;
    okRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); done(false); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  function done(ok: boolean) {
    req?.resolve(ok);
    setReq(null);
  }

  if (!req) return null;
  return (
    <div className="modal-backdrop" onMouseDown={() => done(false)}>
      <div className="modal" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title"
        onMouseDown={(e) => e.stopPropagation()}>
        <h3 id="confirm-title" className="modal-title">{req.title}</h3>
        {req.body && <p className="modal-body">{req.body}</p>}
        <div className="modal-actions">
          <button className="btn ghost" onClick={() => done(false)}>Cancel</button>
          <button ref={okRef} className={"btn " + (req.danger ? "danger" : "start")} onClick={() => done(true)}>
            {req.confirmLabel ?? "Confirm"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ---- toasts ------------------------------------------------------------------

export type ToastKind = "info" | "success" | "error";
interface Toast { id: number; kind: ToastKind; text: string }

let pushToast: ((t: Omit<Toast, "id">) => void) | null = null;

/** Show a short-lived notification in the corner of the window. */
export function toast(text: string, kind: ToastKind = "info") {
  pushToast?.({ text, kind });
}

const TOAST_MS = 5000;

export function ToastHost() {
  const [items, setItems] = useState<Toast[]>([]);
  const next = useRef(1);

  useEffect(() => {
    pushToast = (t) => {
      const id = next.current++;
      setItems((prev) => [...prev.slice(-3), { ...t, id }]);
      setTimeout(() => setItems((prev) => prev.filter((x) => x.id !== id)), t.kind === "error" ? TOAST_MS * 2 : TOAST_MS);
    };
    return () => { pushToast = null; };
  }, []);

  if (items.length === 0) return null;
  return (
    <div className="toasts" role="status" aria-live="polite">
      {items.map((t) => (
        <button key={t.id} className={"toast " + t.kind} title="Dismiss"
          onClick={() => setItems((prev) => prev.filter((x) => x.id !== t.id))}>
          {t.text}
        </button>
      ))}
    </div>
  );
}
