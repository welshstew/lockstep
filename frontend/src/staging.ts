// The changeset: which values the user has chosen to copy, and in which direction, values
// typed in to override a side, and keys to remove from a side. Nothing here talks to Vault:
// the server re-reads everything at preview/apply time. Typed values are the only values kept here.
import type { CompareResult, KeyDiff, SecretDiff } from "./types";

export type Direction = "left_to_right" | "right_to_left";

export interface Staged {
  path: string;
  direction: Direction; // left_to_right writes the right side
  keys: "all" | string[]; // copied from the source; "all" = every key the source has, [] = none
  set?: Record<string, unknown>; // override: typed values written to the target
  remove?: string[]; // keys removed from the target
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

/** Keys an entry takes over itself (typed or removed): those aren't copied. */
const claimed = (e: Staged | undefined) => new Set([...Object.keys(e?.set ?? {}), ...(e?.remove ?? [])]);

/** Write an entry back, tidied: empty parts dropped, the entry dropped when nothing is left. */
function put(cs: Changeset, s: SecretDiff, d: Direction, e: Omit<Staged, "path" | "direction">): Changeset {
  const next = { ...cs };
  const set = e.set && Object.keys(e.set).length ? e.set : undefined;
  const remove = e.remove && e.remove.length ? [...e.remove].sort() : undefined;
  const keys = e.keys === "all" ? "all" : e.keys.filter((k) => !(set && k in set) && !remove?.includes(k));
  if (keys === "all" || keys.length || set || remove) {
    next[id(s.path, d)] = { path: s.path, direction: d, keys, ...(set ? { set } : {}), ...(remove ? { remove } : {}) };
  } else {
    delete next[id(s.path, d)];
  }
  return next;
}

const explicit = (s: SecretDiff, d: Direction, e: Staged | undefined): string[] =>
  !e ? [] : e.keys === "all" ? sourceKeys(s, d).filter((k) => !claimed(e).has(k)) : e.keys;

export function isKeyStaged(cs: Changeset, path: string, key: string, d: Direction): boolean {
  const e = cs[id(path, d)];
  return !!e && !claimed(e).has(key) && (e.keys === "all" || e.keys.includes(key));
}

/** Override values staged for one side of a secret, if any. */
export function overridesFor(cs: Changeset, path: string, side: Side): Record<string, unknown> | undefined {
  const set = cs[id(path, targetDirection(side))]?.set;
  return set && Object.keys(set).length ? set : undefined;
}

export function isKeyOverridden(cs: Changeset, path: string, key: string, side: Side): boolean {
  const set = overridesFor(cs, path, side);
  return !!set && key in set;
}

export function isKeyRemoved(cs: Changeset, path: string, key: string, side: Side): boolean {
  return !!cs[id(path, targetDirection(side))]?.remove?.includes(key);
}

export function hasOverrides(cs: Changeset): boolean {
  return Object.values(cs).some((e) => e.set && Object.keys(e.set).length > 0);
}

/** Can this side of the secret be overridden? Not if we can't see what's there now. */
export function canOverride(s: SecretDiff, side: Side): boolean {
  if (s.status === "no_access" || s.status === "error") return false;
  return ["present", "absent", "deleted"].includes(s[side].state);
}

/** Stage a typed value for one key on one side (undefined: drop it). That key stops being copied or removed there. */
export function setKeyValue(cs: Changeset, s: SecretDiff, side: Side, key: string, value: unknown | undefined): Changeset {
  const d = targetDirection(side);
  const e = cs[id(s.path, d)];
  const set = { ...(e?.set ?? {}) };
  if (value === undefined) delete set[key];
  else set[key] = value;
  const keys = e?.keys === "all" && value !== undefined ? explicit(s, d, e) : e?.keys ?? [];
  return put(cs, s, d, { keys, set, remove: (e?.remove ?? []).filter((k) => k !== key) });
}

/** Stage (or unstage) removing a key from one side. A removed key isn't copied or typed there. */
export function toggleRemove(cs: Changeset, s: SecretDiff, side: Side, key: string): Changeset {
  const d = targetDirection(side);
  const e = cs[id(s.path, d)];
  if (e?.remove?.includes(key)) return put(cs, s, d, { ...e, remove: e.remove.filter((k) => k !== key) });
  const set = Object.fromEntries(Object.entries(e?.set ?? {}).filter(([k]) => k !== key));
  return put(cs, s, d, { keys: explicit(s, d, e).filter((k) => k !== key), set, remove: [...(e?.remove ?? []), key] });
}

/** Keys of this secret that could be copied this way and aren't typed or removed on the target. */
function copyCandidates(cs: Changeset, s: SecretDiff, d: Direction): string[] {
  const taken = claimed(cs[id(s.path, d)]);
  return s.keys.filter((k) => canCopyKey(s, k, d) && !taken.has(k.key)).map((k) => k.key);
}

/** Is every key that can be copied this way staged? (With the "all keys" button, or one by one.) */
export function isSecretStaged(cs: Changeset, s: SecretDiff, d: Direction): boolean {
  const e = cs[id(s.path, d)];
  if (!e) return false;
  if (e.keys === "all") return true;
  const want = copyCandidates(cs, s, d);
  return want.length > 0 && want.every((k) => (e.keys as string[]).includes(k));
}

export function stagedKeyCount(cs: Changeset, s: SecretDiff): number {
  return (["left_to_right", "right_to_left"] as Direction[]).reduce((n, d) => {
    const e = cs[id(s.path, d)];
    if (!e) return n;
    const taken = claimed(e);
    const copied = e.keys === "all" ? s.keys.filter((k) => canCopyKey(s, k, d) && !taken.has(k.key)).length : e.keys.length;
    return n + copied + taken.size;
  }, 0);
}

/** Remove one copied key from an entry, expanding "all" into an explicit list first. */
function without(cs: Changeset, s: SecretDiff, d: Direction, key: string): Changeset {
  const e = cs[id(s.path, d)];
  if (!e) return cs;
  return put(cs, s, d, { ...e, keys: explicit(s, d, e).filter((k) => k !== key) });
}

export function toggleKey(cs: Changeset, s: SecretDiff, key: string, d: Direction): Changeset {
  if (isKeyStaged(cs, s.path, key, d)) return without(cs, s, d, key);
  // A key can only travel one way: staging it here unstages the other direction.
  const next = without(cs, s, opposite(d), key);
  const e = next[id(s.path, d)];
  const set = Object.fromEntries(Object.entries(e?.set ?? {}).filter(([k]) => k !== key));
  return put(next, s, d, { keys: [...explicit(s, d, e), key].sort(), set, remove: (e?.remove ?? []).filter((k) => k !== key) });
}

/** Copy every key this way (or, when they all are already, none). Typed and removed keys stay. */
export function toggleSecret(cs: Changeset, s: SecretDiff, d: Direction): Changeset {
  return stageSecret(cs, s, d, !isSecretStaged(cs, s, d));
}

function stageSecret(cs: Changeset, s: SecretDiff, d: Direction, on: boolean): Changeset {
  const e = cs[id(s.path, d)];
  if (!on) return e ? put(cs, s, d, { ...e, keys: [] }) : cs;
  const back = cs[id(s.path, opposite(d))];
  const next = back ? put(cs, s, opposite(d), { ...back, keys: [] }) : cs;
  return put(next, s, d, { ...(e ?? {}), keys: "all" });
}

/** Stage every secret in a list one way, or, if they all are already, unstage them. */
export function toggleSecrets(cs: Changeset, secrets: SecretDiff[], d: Direction): Changeset {
  const can = secrets.filter((s) => canCopySecret(s, d));
  const on = !can.every((s) => isSecretStaged(cs, s, d));
  return can.reduce((acc, s) => stageSecret(acc, s, d, on), cs);
}

export function allStaged(cs: Changeset, secrets: SecretDiff[], d: Direction): boolean {
  const can = secrets.filter((s) => canCopySecret(s, d));
  return can.length > 0 && can.every((s) => isSecretStaged(cs, s, d));
}

/** Take one key out of a change (copied, typed or removed), e.g. from the review. */
export function unstageKey(cs: Changeset, s: SecretDiff, d: Direction, key: string): Changeset {
  const e = cs[id(s.path, d)];
  if (!e) return cs;
  const set = Object.fromEntries(Object.entries(e.set ?? {}).filter(([k]) => k !== key));
  return put(cs, s, d, { keys: explicit(s, d, e).filter((k) => k !== key), set, remove: (e.remove ?? []).filter((k) => k !== key) });
}

/** Drop a whole change. */
export function unstageChange(cs: Changeset, s: SecretDiff, d: Direction): Changeset {
  const next = { ...cs };
  delete next[id(s.path, d)];
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
    const remove = e.remove?.length ? e.remove : null;
    // "all" with typed or removed keys: every source key except those
    const keys = e.keys === "all" ? (set || remove ? explicit(s, e.direction, e) : null) : e.keys;
    if (keys && !keys.length && !set && !remove) return [];
    return [{
      path: s.left_path || s.path,
      right_path: s.right_path || s.path,
      direction: e.direction,
      keys,
      ...(set ? { set } : {}),
      ...(remove ? { remove } : {}),
      expected_target_version: tgt.state === "present" || tgt.state === "deleted" ? tgt.version : null,
      expected_source_version: src.version,
    }];
  });
}

/** The compared secret a change (from the API) belongs to. */
export function secretFor(result: CompareResult, path: string, rightPath?: string): SecretDiff | undefined {
  return result.secrets.find((s) => (s.left_path || s.path) === path && (s.right_path || s.path) === (rightPath ?? path));
}

export function changesetSize(cs: Changeset, result: CompareResult): { keys: number; secrets: number } {
  const byPath = new Map(result.secrets.map((s) => [s.path, s]));
  const paths = new Set(Object.values(cs).map((e) => e.path));
  let keys = 0;
  for (const p of paths) keys += stagedKeyCount(cs, byPath.get(p)!);
  return { keys, secrets: paths.size };
}
