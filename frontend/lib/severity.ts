export type Severity = "low" | "medium" | "high" | "critical" | null;

export function severityColor(s: Severity): string {
  switch (s) {
    case "critical": return "var(--critical)";
    case "high": return "var(--alert)";
    case "medium": return "#c99a3d";
    case "low": return "var(--text-muted)";
    default: return "var(--text-dim)";
  }
}

export function severityLabel(s: Severity): string {
  return s ? s[0].toUpperCase() + s.slice(1) : "Normal";
}
