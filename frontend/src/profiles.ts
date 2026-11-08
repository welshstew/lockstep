// Comparison profiles in the browser: personal profiles live in localStorage (export/import
// as JSON to share); shared profiles come from the server (read-only).
import type { Profile, ProfileRules } from "./types";

const KEY = "lockstep.profiles";
const ACTIVE = "lockstep.activeProfile";

export type ProfileRef = { source: "shared" | "personal"; name: string };

export const emptyRules = (): ProfileRules => ({ mappings: [], ignore_paths: [], ignore_keys: [] });

export function loadPersonal(): Profile[] {
  try {
    const v = JSON.parse(localStorage.getItem(KEY) ?? "[]");
    return Array.isArray(v) ? v.filter(isProfile) : [];
  } catch {
    return [];
  }
}

export function savePersonal(list: Profile[]): void {
  try { localStorage.setItem(KEY, JSON.stringify(list)); } catch { /* storage unavailable */ }
}

export function loadActive(): ProfileRef | null {
  try { return JSON.parse(localStorage.getItem(ACTIVE) ?? "null"); } catch { return null; }
}

export function saveActive(ref: ProfileRef | null): void {
  try { localStorage.setItem(ACTIVE, JSON.stringify(ref)); } catch { /* ignore */ }
}

function isProfile(p: unknown): p is Profile {
  const x = p as Profile;
  return !!x && typeof x.name === "string" && !!x.rules && Array.isArray(x.rules.mappings)
    && Array.isArray(x.rules.ignore_paths) && Array.isArray(x.rules.ignore_keys);
}

const wildcards = (p: string) => p.match(/\*\*|\*/g) ?? [];

/** Same check the server makes: both sides of a mapping need the same wildcards in order. */
export function validateRules(r: ProfileRules): string | null {
  for (const m of r.mappings) {
    if (!m.left.trim() || !m.right.trim()) return "Each mapping needs a left and a right pattern.";
    if (wildcards(m.left).join() !== wildcards(m.right).join())
      return `Mapping "${m.left}" ⇄ "${m.right}": both sides need the same wildcards in the same order.`;
  }
  if (r.ignore_keys.some((k) => !k.key.trim())) return "Each ignored key needs a key pattern.";
  return null;
}

export function describe(p: Profile): string {
  const r = p.rules;
  const parts = [
    r.mappings.length && `${r.mappings.length} mapping${r.mappings.length === 1 ? "" : "s"}`,
    r.ignore_keys.length && `${r.ignore_keys.length} ignored key rule${r.ignore_keys.length === 1 ? "" : "s"}`,
    r.ignore_paths.length && `${r.ignore_paths.length} ignored path${r.ignore_paths.length === 1 ? "" : "s"}`,
  ].filter(Boolean);
  return parts.join(" · ") || "no rules";
}

export function exportProfiles(list: Profile[]): void {
  const blob = new Blob([JSON.stringify({ lockstep_profiles: 1, profiles: list }, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = list.length === 1 ? `${list[0].name.replace(/[^\w.-]+/g, "_")}.lockstep.json` : "lockstep-profiles.json";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Parse an exported file (or a bare list). Throws with a readable message. */
export async function importProfiles(file: File): Promise<Profile[]> {
  let data: unknown;
  try { data = JSON.parse(await file.text()); } catch { throw new Error("That file isn't JSON."); }
  const list = Array.isArray(data) ? data : (data as { profiles?: unknown })?.profiles;
  if (!Array.isArray(list) || !list.length) throw new Error("No profiles found in that file.");
  const bad = list.find((p) => !isProfile(p));
  if (bad) throw new Error("That file contains something that isn't a Lockstep profile.");
  for (const p of list as Profile[]) {
    const err = validateRules(p.rules);
    if (err) throw new Error(`Profile "${p.name}": ${err}`);
  }
  return list as Profile[];
}
