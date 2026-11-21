export type Theme = "dark" | "light";
const KEY = "network-ai-theme";

/** Per-viewer convenience, not shared state -- wrapped defensively since a
 * private window or blocked storage can throw. */
export function getStoredTheme(): Theme {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

export function applyTheme(theme: Theme) {
  try {
    document.documentElement.setAttribute("data-theme", theme);
  } catch {
    /* no-op */
  }
}

export function setStoredTheme(theme: Theme) {
  applyTheme(theme);
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    /* per-viewer convenience only -- a failed save just means it resets next visit */
  }
}
