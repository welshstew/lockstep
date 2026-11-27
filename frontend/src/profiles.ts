// Comparison profiles in the browser: personal profiles live in localStorage (export/import
// as JSON to share); shared profiles come from the server (read-only).
import type { IgnoreRule, Profile, ProfileRules } from "./types";

const KEY = "lockstep.profiles";
const ACTIVE = "lockstep.activeProfile";

export type ProfileRef = { source: "shared" | "personal"; name: string };

export const emptyRules = (): ProfileRules => ({ mappings: [], ignore_paths: [], ignore_keys: [], rewrites: [], exact_keys: [], unordered_keys: [], volatile: [] });

/** Profiles saved before rewrites existed have none. */
export const rewritesOf = (r: ProfileRules | null | undefined) => r?.rewrites ?? [];
/** Nor before keys could be compared as text only. */
export const exactOf = (r: ProfileRules | null | undefined) => r?.exact_keys ?? [];
export const unorderedOf = (r: ProfileRules | null | undefined) => r?.unordered_keys ?? [];
export const volatileOf = (r: ProfileRules | null | undefined) => r?.volatile ?? [];

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
    && Array.isArray(x.rules.ignore_paths) && Array.isArray(x.rules.ignore_keys)
    && (x.rules.rewrites === undefined || Array.isArray(x.rules.rewrites))
    && (x.rules.exact_keys === undefined || Array.isArray(x.rules.exact_keys))
    && (x.rules.unordered_keys === undefined || Array.isArray(x.rules.unordered_keys))
    && (x.rules.volatile === undefined || Array.isArray(x.rules.volatile));
}

const wildcards = (p: string) => p.match(/\*\*|\*/g) ?? [];

/** Same check the server makes: both sides of a mapping need the same wildcards in order. */
export function validateRules(r: ProfileRules): string | null {
  for (const m of r.mappings) {
    if (!m.left.trim() || !m.right.trim()) return "Each mapping needs a left and a right pattern.";
    if (wildcards(m.left).join() !== wildcards(m.right).join())
      return `Mapping "${m.left}" ⇄ "${m.right}": both sides need the same wildcards in the same order.`;
  }
  const rw = rewritesOf(r);
  for (const w of rw) {
    if (!w.left.trim() || !w.right.trim()) return "Each rewrite needs a word on each side.";
    if (w.left.trim() === w.right.trim()) return `Rewrite "${w.left}" ⇄ "${w.right}": the two words are the same.`;
    const holes = (t: string) => (t.match(/\{[A-Za-z_][A-Za-z0-9_]*\}/g) ?? []).sort().join();
    if (holes(w.left) !== holes(w.right)) return `Rewrite "${w.left}" ⇄ "${w.right}": both sides need the same placeholders.`;
  }
  for (const side of ["left", "right"] as const) {
    const words = rw.map((w) => w[side].trim());
    const dup = words.find((w, i) => words.indexOf(w) !== i);
    if (dup) return `"${dup}" is on the ${side} of more than one rewrite.`;
  }
  if (r.ignore_keys.some((k) => !k.key.trim())) return "Each ignored key needs a key pattern.";
  if (exactOf(r).some((k) => !k.key.trim())) return "Each key compared as text needs a key pattern.";
  if (unorderedOf(r).some((k) => !k.key.trim())) return "Each unordered list needs a key pattern.";
  for (const v of volatileOf(r)) {
    if (!v.key.trim() || !v.pattern) return "Each volatile pattern needs a key pattern and a regex.";
    try { new RegExp(v.pattern); } catch { return `Volatile pattern "${v.pattern}" isn't a valid regex.`; }
  }
  return null;
}

export function describe(p: Profile): string {
  const r = p.rules;
  const parts = [
    r.mappings.length && `${r.mappings.length} mapping${r.mappings.length === 1 ? "" : "s"}`,
    r.ignore_keys.length && `${r.ignore_keys.length} ignored key rule${r.ignore_keys.length === 1 ? "" : "s"}`,
    r.ignore_paths.length && `${r.ignore_paths.length} ignored path${r.ignore_paths.length === 1 ? "" : "s"}`,
    rewritesOf(r).length && `${rewritesOf(r).length} rewrite${rewritesOf(r).length === 1 ? "" : "s"}`,
    exactOf(r).length && `${exactOf(r).length} compared as text`,
    unorderedOf(r).length && `${unorderedOf(r).length} unordered list${unorderedOf(r).length === 1 ? "" : "s"}`,
    volatileOf(r).length && `${volatileOf(r).length} volatile pattern${volatileOf(r).length === 1 ? "" : "s"}`,
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

// ---- Building rules from a comparison ("Ignore mode")

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Same glob semantics as the server (rules.py): `*` within a segment, `**` any depth. */
export function globRegex(pattern: string): RegExp {
  const p = pattern.trim().replace(/^\/+|\/+$/g, "");
  let rx = p.split(/(\*\*|\*)/).map((part) => (part === "**" ? "(.*)" : part === "*" ? "([^/]*)" : escapeRe(part))).join("");
  if (p.endsWith("/**")) rx = rx.replace(/\/\(\.\*\)$/, "(?:/(.*))?"); // "a/**" also matches "a"
  return new RegExp(`^${rx}$`);
}

function keyGlob(pattern: string): RegExp {
  return new RegExp(`^${pattern.split("*").map(escapeRe).join(".*")}$`);
}

export function pathIgnored(rules: ProfileRules, ...paths: string[]): boolean {
  return rules.ignore_paths.some((g) => paths.some((p) => p && globRegex(g).test(p)));
}

export function keyIgnored(rules: ProfileRules, key: string, ...paths: string[]): boolean {
  // A rule for one field inside the value doesn't ignore the whole key (the server works that out)
  return rules.ignore_keys.some((k) => !k.field && keyGlob(k.key).test(key) && paths.some((p) => p && globRegex(k.path || "**").test(p)));
}

/** Rules in both, without duplicates (a's order first). */
export function mergeRules(a: ProfileRules | null | undefined, b: ProfileRules): ProfileRules {
  const base = a ?? emptyRules();
  const paths = [...base.ignore_paths, ...b.ignore_paths.filter((p) => !base.ignore_paths.includes(p))];
  const same = (x: IgnoreRule, y: IgnoreRule) => x.key === y.key && (x.path || "**") === (y.path || "**") && (x.field || "") === (y.field || "");
  const keys = [...base.ignore_keys, ...b.ignore_keys.filter((k) => !base.ignore_keys.some((x) => same(x, k)))];
  const maps = [...base.mappings, ...b.mappings.filter((m) => !base.mappings.some((x) => x.left === m.left && x.right === m.right))];
  const rws = [...rewritesOf(base), ...rewritesOf(b).filter((w) => !rewritesOf(base).some((x) => x.left === w.left || x.right === w.right))];
  const exact = [...exactOf(base), ...exactOf(b).filter((k) => !exactOf(base).some((x) => same(x, k)))];
  const unord = [...unorderedOf(base), ...unorderedOf(b).filter((k) => !unorderedOf(base).some((x) => same(x, k) && (x.separator || "") === (k.separator || "")))];
  const vol = [...volatileOf(base), ...volatileOf(b).filter((k) => !volatileOf(base).some((x) => x.key === k.key && x.path === k.path && x.pattern === k.pattern))];
  return { mappings: maps, ignore_paths: paths, ignore_keys: keys, rewrites: rws, exact_keys: exact, unordered_keys: unord, volatile: vol };
}

export function ruleCount(r: ProfileRules): number {
  return r.mappings.length + r.ignore_paths.length + r.ignore_keys.length + rewritesOf(r).length + exactOf(r).length
    + unorderedOf(r).length + volatileOf(r).length;
}

/** Add or remove one ignored path in a draft. */
export function toggleIgnorePath(r: ProfileRules, pattern: string): ProfileRules {
  return r.ignore_paths.includes(pattern)
    ? { ...r, ignore_paths: r.ignore_paths.filter((p) => p !== pattern) }
    : { ...r, ignore_paths: [...r.ignore_paths, pattern] };
}

/** Add or remove one ignored key (in `path`, "**" for everywhere) in a draft. */
export function toggleIgnoreKey(r: ProfileRules, key: string, path: string): ProfileRules {
  const has = r.ignore_keys.some((k) => k.key === key && k.path === path);
  return has
    ? { ...r, ignore_keys: r.ignore_keys.filter((k) => !(k.key === key && k.path === path)) }
    : { ...r, ignore_keys: [...r.ignore_keys, { key, path }] };
}

/** Glob characters in a literal path would be read as wildcards; such paths can't be picked. */
export const literalSafe = (path: string) => !path.includes("*");

// ---- Explaining a profile against what's in the two Vaults (the profile builder)

/** Where a left path lands on the right under the mappings (first match wins), like rules.py. */
export function mapToRight(r: ProfileRules, path: string): string {
  for (const m of r.mappings) {
    const left = m.left.trim().replace(/^\/+|\/+$/g, "");
    if (!left) continue;
    let rx: RegExp;
    try { rx = globRegex(left); } catch { continue; }
    const hit = rx.exec(path);
    if (!hit) continue;
    const caps = hit.slice(1);
    let i = 0;
    return m.right.trim().replace(/^\/+|\/+$/g, "").replace(/\*\*|\*/g, () => caps[i++] ?? "").replace(/\/{2,}/g, "/").replace(/^\/|\/$/g, "");
  }
  return path;
}

export interface RuleEffect {
  /** Per mapping: the pairs it makes, and the left paths it matches that have no partner */
  mappings: { pairs: [string, string][]; unmatched: string[] }[];
  /** Per ignored path pattern: how many secrets it leaves out on each side */
  ignoredPaths: { left: number; right: number }[];
  /** Per ignored key: how many secrets its path pattern covers */
  ignoredKeys: number[];
  /** What no rule pairs up, once the rules are applied */
  leftOnly: string[];
  rightOnly: string[];
  paired: number;
}

/** What the rules do to these two lists of secret paths. Pure: no values involved. */
export function ruleEffect(r: ProfileRules, left: string[], right: string[]): RuleEffect {
  const rightSet = new Set(right);
  const safe = (g: string) => { try { return globRegex(g); } catch { return /$^/; } };
  const mappings = r.mappings.map((m, i) => {
    const rx = safe(m.left);
    const earlier = r.mappings.slice(0, i).map((x) => safe(x.left));
    const hits = left.filter((p) => rx.test(p) && !earlier.some((e) => e.test(p)));
    const pairs = hits.map((p) => [p, mapToRight(r, p)] as [string, string]).filter(([, q]) => rightSet.has(q));
    return { pairs, unmatched: hits.filter((p) => !rightSet.has(mapToRight(r, p))) };
  });
  const ignoredPaths = r.ignore_paths.map((g) => ({ left: left.filter((p) => safe(g).test(p)).length, right: right.filter((p) => safe(g).test(p)).length }));
  const all = [...new Set([...left, ...right])];
  const ignoredKeys = r.ignore_keys.map((k) => all.filter((p) => safe(k.path || "**").test(p)).length);
  const kept = (p: string) => !r.ignore_paths.some((g) => safe(g).test(p));
  const mapped = new Set(left.filter(kept).map((p) => mapToRight(r, p)));
  const leftOnly = left.filter(kept).filter((p) => !rightSet.has(mapToRight(r, p)));
  const rightOnly = right.filter(kept).filter((p) => !mapped.has(p));
  return { mappings, ignoredPaths, ignoredKeys, leftOnly, rightOnly, paired: [...mapped].filter((p) => rightSet.has(p)).length };
}
