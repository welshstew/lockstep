// Human-friendly timestamps. Metadata only: never used in comparisons.
const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 365 * 86400], ["month", 30 * 86400], ["week", 7 * 86400],
  ["day", 86400], ["hour", 3600], ["minute", 60], ["second", 1],
];
const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

export function relativeTime(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "unknown";
  const secs = (Date.parse(iso) - now) / 1000;
  if (Number.isNaN(secs)) return "unknown";
  for (const [unit, size] of UNITS) {
    if (Math.abs(secs) >= size || unit === "second") return rtf.format(Math.round(secs / size), unit);
  }
  return "";
}

export function absoluteTime(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, {
    dateStyle: "medium", timeStyle: "long",
  });
}
