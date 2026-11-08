// The changeset: which values the user has chosen to copy, and in which direction.
// Nothing here talks to Vault. The server re-reads everything at preview/apply time.
import type { CompareResult, KeyDiff, SecretDiff } from "./types";

export type Direction = "left_to_right" | "right_to_left";

export interface Staged {
  path: string;
  direction: Direction;
  keys: "all" | string[]; // "all" = every key the source has (whole secret)
}

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
  return !!e && (e.keys === "all" || e.keys.includes(key));
}

export function isSecretStaged(cs: Changeset, path: string, d: Direction): boolean {
  return cs[id(path, d)]?.keys === "all";
}

export function stagedKeyCount(cs: Changeset, s: SecretDiff): number {
  return (["left_to_right", "right_to_left"] as Direction[]).reduce((n, d) => {
    const e = cs[id(s.path, d)];
    return n + (!e ? 0 : e.keys === "all" ? s.keys.filter((k) => canCopyKey(s, k, d)).length : e.keys.length);
  }, 0);
}

/** Remove one key from an entry, expanding "all" into an explicit list first. */
function without(cs: Changeset, s: SecretDiff, d: Direction, key: string): Changeset {
  const e = cs[id(s.path, d)];
  if (!e) return cs;
  const keys = (e.keys === "all" ? sourceKeys(s, d) : e.keys).filter((k) => k !== key);
  const next = { ...cs };
  if (keys.length) next[id(s.path, d)] = { ...e, keys };
  else delete next[id(s.path, d)];
  return next;
}

export function toggleKey(cs: Changeset, s: SecretDiff, key: string, d: Direction): Changeset {
  if (isKeyStaged(cs, s.path, key, d)) return without(cs, s, d, key);
  // A key can only travel one way: staging it here unstages the other direction.
  const next = without(cs, s, opposite(d), key);
  const e = next[id(s.path, d)];
  const keys = e ? (e.keys === "all" ? sourceKeys(s, d) : e.keys) : [];
  return { ...next, [id(s.path, d)]: { path: s.path, direction: d, keys: [...keys, key].sort() } };
}

export function toggleSecret(cs: Changeset, s: SecretDiff, d: Direction): Changeset {
  const next = { ...cs };
  if (isSecretStaged(cs, s.path, d)) {
    delete next[id(s.path, d)];
    return next;
  }
  delete next[id(s.path, opposite(d))];
  next[id(s.path, d)] = { path: s.path, direction: d, keys: "all" };
  return next;
}

/** Turn the changeset into the API's change list, with the versions seen in the comparison. */
export function toApiChanges(cs: Changeset, result: CompareResult) {
  const byPath = new Map(result.secrets.map((s) => [s.path, s]));
  return Object.values(cs).flatMap((e) => {
    const s = byPath.get(e.path);
    if (!s) return [];
    const [src, tgt] = e.direction === "left_to_right" ? [s.left, s.right] : [s.right, s.left];
    return [{
      path: s.left_path || s.path,
      right_path: s.right_path || s.path,
      direction: e.direction,
      keys: e.keys === "all" ? null : e.keys,
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
