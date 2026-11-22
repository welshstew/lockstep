/** Light, dark, or following the system: remembered per browser, applied as <html data-theme>. */
export type Theme = "system" | "light" | "dark";
const KEY = "lockstep.theme";

export function loadTheme(): Theme {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch { return "system"; }
}

export function applyTheme(t: Theme): void {
  if (t === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = t;
  try { localStorage.setItem(KEY, t); } catch { /* ignore */ }
}
