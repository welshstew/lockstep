// The changeset: which values the user has chosen to copy, and in which direction, plus
// values typed in to override a side. Nothing here talks to Vault: the server re-reads
// everything at preview/apply time. Override values are the only values kept here.
import type { CompareResult, KeyDiff, SecretDiff } from "./types";

export type Direction = "left_to_right" | "right_to_left";

export interface Staged {
  path: string;
  direction: Direction; // left_to_right writes the right side
  keys: "all" | string[]; // copied from the source; "all" = every key the source has, [] = none
  set?: Record<string, unknown>; // override: typed values written to the target
}

export type Side = "left" | "right";
export const targetDirection = (side: Side): Direction => (side === "right" ? "left_to_right" : "right_to_left");

export type Changeset = Record<string, Staged>; // keyed by `${direction}|${path}`

const id = (path: string, d: Direction) => `${d}|${path}`;
const opposite = (d: Direction): Direction => (d === "left_to_right" ? "right_to_left" : "left_to_right");

/** Can this key be copied in this direction? Only from a side that has it, and only if it differs. */
export function canCopyKey(s: SecretDiff, k: KeyDiff, d: Direction): boolean {
  if (s.status === "no_access" || s.status === "error") return false;
  const src = d === "left_to_right" ? s.left : s.right;
  if (src.state !== "present") return false;
  return k.status === "different" || k.status === (d === "left_to_right" ? "left_only" : "right_only");
}

/** Can the whole secret be copied in this direction? */
export function canCopySecret(s: SecretDiff, d: Direction): boolean {
  return s.keys.some((k) => canCopyKey(s, k, d));
}

function sourceKeys(s: SecretDiff, d: Direction): string[] {
  const other = d === "left_to_right" ? "right_only" : "left_only";
  return s.keys.filter((k) => k.status !== other && k.status !== "unknown").map((k) => k.key);
}

export function isKeyStaged(cs: Changeset, path: string, key: string, d: Direction): boolean {
  const e = cs[id(path, d)];
  return !!e && !(e.set && key in e.set) && (e.keys === "all" || e.keys.includes(key));
}

/** Override values staged for one side of a secret, if any. */
export function overridesFor(cs: Changeset, path: string, side: Side): Record<string, unknown> | undefined {
  const set = cs[id(path, targetDirection(side))]?.set;
  return set && Object.keys(set).length ? set : undefined;
}

export function isKeyOverridden(cs: Changeset, path: string, key: string, side: Side): boolean {
  return !!overridesFor(cs, path, side) && key in overridesFor(cs, path, side)!;
}

export function hasOverrides(cs: Changeset): boolean {
  return Object.values(cs).some((e) => e.set && Object.keys(e.set).length > 0);
}

/** Can this side of the secret be overridden? Not if we can't see what's there now. */
export function canOverride(s: SecretDiff, side: Side): boolean {
  if (s.status === "no_access" || s.status === "error") return false;
  return ["present", "absent", "deleted"].includes(s[side].state);
}

/** Stage (or with null, remove) typed values for one side. Those keys stop being copied there. */
export function setOverride(cs: Changeset, s: SecretDiff, side: Side, values: Record<string, unknown> | null): Changeset {
  const d = targetDirection(side);
  const next = { ...cs };
  const e = next[id(s.path, d)];
  const set = values && Object.keys(values).length ? { ...values } : undefined;
  let keys: Staged["keys"] = e?.keys ?? [];
  if (set && keys === "all") keys = sourceKeys(s, d);
  if (set && keys !== "all") keys = keys.filter((k) => !(k in set));
  if ((keys === "all" || keys.length) || set) next[id(s.path, d)] = { path: s.path, direction: d, keys, ...(set ? { set } : {}) };
  else delete next[id(s.path, d)];
  return next;
}

export function isSecretStaged(cs: Changeset, path: string, d: Direction): boolean {
  return cs[id(path, d)]?.keys === "all";
}

export function stagedKeyCount(cs: Changeset, s: SecretDiff): number {
  return (["left_to_right", "right_to_left"] as Direction[]).reduce((n, d) => {
    const e = cs[id(s.path, d)];
    if (!e) return n;
    const set = Object.keys(e.set ?? {});
    const copied = e.keys === "all" ? s.keys.filter((k) => canCopyKey(s, k, d) && !set.includes(k.key)).length : e.keys.length;
    return n + copied + set.length;
  }, 0);
}

/** Remove one key from an entry, expanding "all" into an explicit list first. */
function without(cs: Changeset, s: SecretDiff, d: Direction, key: string): Changeset {
  const e = cs[id(s.path, d)];
  if (!e) return cs;
  const keys = (e.keys === "all" ? sourceKeys(s, d) : e.keys).filter((k) => k !== key);
  const next = { ...cs };
  if (keys.length || e.set) next[id(s.path, d)] = { ...e, keys };
  else delete next[id(s.path, d)];
  return next;
}

export function toggleKey(cs: Changeset, s: SecretDiff, key: string, d: Direction): Changeset {
  if (isKeyStaged(cs, s.path, key, d)) return without(cs, s, d, key);
  // A key can only travel one way: staging it here unstages the other direction.
  const next = without(cs, s, opposite(d), key);
  const e = next[id(s.path, d)];
  const keys = e ? (e.keys === "all" ? sourceKeys(s, d) : e.keys) : [];
  const set = e?.set ? Object.fromEntries(Object.entries(e.set).filter(([k]) => k !== key)) : undefined;
  return { ...next, [id(s.path, d)]: { path: s.path, direction: d, keys: [...keys, key].sort(),
                                        ...(set && Object.keys(set).length ? { set } : {}) } };
}

export function toggleSecret(cs: Changeset, s: SecretDiff, d: Direction): Changeset {
  const next = { ...cs };
  const set = next[id(s.path, d)]?.set; // overrides on the target stay staged either way
  if (isSecretStaged(cs, s.path, d)) {
    if (set) next[id(s.path, d)] = { path: s.path, direction: d, keys: [], set };
    else delete next[id(s.path, d)];
    return next;
  }
  const back = next[id(s.path, opposite(d))];
  if (back?.set) next[id(s.path, opposite(d))] = { ...back, keys: [] };
  else delete next[id(s.path, opposite(d))];
  next[id(s.path, d)] = { path: s.path, direction: d, keys: "all", ...(set ? { set } : {}) };
  return next;
}

/** Turn the changeset into the API's change list, with the versions seen in the comparison. */
export function toApiChanges(cs: Changeset, result: CompareResult) {
  const byPath = new Map(result.secrets.map((s) => [s.path, s]));
  return Object.values(cs).flatMap((e) => {
    const s = byPath.get(e.path);
    if (!s) return [];
    const [src, tgt] = e.direction === "left_to_right" ? [s.left, s.right] : [s.right, s.left];
    const set = e.set && Object.keys(e.set).length ? e.set : null;
    // "all" with overrides: every source key except the overridden ones
    const keys = e.keys === "all" ? (set ? sourceKeys(s, e.direction).filter((k) => !(k in set)) : null) : e.keys;
    if (keys && !keys.length && !set) return [];
    return [{
      path: s.left_path || s.path,
      right_path: s.right_path || s.path,
      direction: e.direction,
      keys,
      ...(set ? { set } : {}),
      expected_target_version: tgt.state === "present" || tgt.state === "deleted" ? tgt.version : null,
      expected_source_version: src.version,
    }];
  });
}

export function changesetSize(cs: Changeset, result: CompareResult): { keys: number; secrets: number } {
  const byPath = new Map(result.secrets.map((s) => [s.path, s]));
  const paths = new Set(Object.values(cs).map((e) => e.path));
  let keys = 0;
  for (const p of paths) keys += stagedKeyCount(cs, byPath.get(p)!);
  return { keys, secrets: paths.size };
}
