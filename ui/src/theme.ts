export type Theme = "dark" | "light";

const KEY = "shrike.theme";

export function getTheme(): Theme {
  try {
    const v = localStorage.getItem(KEY);
    if (v === "light" || v === "dark") return v;
  } catch { /* ignore */ }
  return "dark";
}

export function applyTheme(t: Theme) {
  document.documentElement.setAttribute("data-theme", t);
}

export function setTheme(t: Theme) {
  applyTheme(t);
  try { localStorage.setItem(KEY, t); } catch { /* ignore */ }
}

/** Apply the saved theme as early as possible to avoid a flash of the wrong one. */
export function initTheme(): Theme {
  const t = getTheme();
  applyTheme(t);
  return t;
}
