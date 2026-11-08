import { useEffect, useState } from "react";
import { api } from "../api";
import {
  canCopyKey, canCopySecret, type Changeset, type Direction, isKeyStaged, isSecretStaged,
  stagedKeyCount, toggleKey, toggleSecret,
} from "../staging";
import { absoluteTime, relativeTime } from "../time";
import type { Badge, KeyChange, KeyDiff, KeyHistory, KeyStatus, SecretDiff, SideInfo, SideSummary } from "../types";
import type { InspectTarget } from "./Inspector";
import { typeName, ValueCell } from "./ValueCell";

export const STATUS_LABEL: Record<string, string> = {
  equal: "Equal",
  different: "Different",
  left_only: "Left only",
  right_only: "Right only",
  no_access: "No access",
  error: "Error",
  unknown: "Unknown",
};

interface Props {
  secret: SecretDiff;
  left: SideSummary;
  right: SideSummary;
  reveal: boolean;
  changeset: Changeset;
  onChangeset: (cs: Changeset) => void;
  onInspect: (targets: InspectTarget[]) => void;
  sideNames: { left: string; right: string };
}

type Values = Record<string, unknown> | null;

/** A side's own path for this pair (differs from secret.path only under a profile mapping). */
export function sidePath(s: SecretDiff, side: "left" | "right"): string {
  return (side === "left" ? s.left_path : s.right_path) || s.path;
}

function fullPath(side: SideSummary, rel: string) {
  return side.prefix ? `${side.prefix}/${rel}` : rel;
}

function onSide(k: KeyDiff, side: "left" | "right", info: SideInfo): boolean {
  if (k.status === "unknown") return info.state === "present";
  if (k.status === "left_only") return side === "left";
  if (k.status === "right_only") return side === "right";
  return true;
}

function unavailableFor(k: KeyDiff, side: "left" | "right", info: SideInfo) {
  if (info.state === "no_access" || info.state === "error" || info.state === "deleted") return info.state;
  return onSide(k, side, info) ? undefined : "absent" as const;
}

function summaryText(s: SecretDiff): string {
  const n = (st: KeyStatus) => s.keys.filter((k) => k.status === st).length;
  if (s.status === "equal") return `${s.keys.length} key${s.keys.length === 1 ? "" : "s"}`;
  if (s.status === "different") {
    const parts = [n("different") && `${n("different")} differ`, n("left_only") && `${n("left_only")} left only`,
                   n("right_only") && `${n("right_only")} right only`].filter(Boolean);
    return `${parts.join(", ")} of ${s.keys.length}`;
  }
  return `${s.keys.length} key${s.keys.length === 1 ? "" : "s"}`;
}

function Version({ info }: { info: SideInfo }) {
  if (info.state === "deleted") return <span className="del" title={`Latest version is deleted (written ${absoluteTime(info.updated)})`}>v{info.version} deleted</span>;
  if (info.version == null) return <>–</>;
  return (
    <span title={`Version ${info.version}, written ${absoluteTime(info.updated)}`}>
      v{info.version} · {relativeTime(info.updated)}
    </span>
  );
}

function BadgeChip({ b }: { b: Badge | null | undefined }) {
  if (!b) return null;
  const tone = b.status === "bad" ? "error" : b.status === "warn" ? "different" : b.status === "ok" ? "equal" : "unknown";
  return <span className={`badge kind ${tone}`} title={b.label}>{b.label}{b.detail ? ` · ${b.detail}` : ""}</span>;
}

function Changed({ c }: { c: KeyChange | undefined }) {
  if (!c) return null;
  return (
    <span title={`${c.exact ? "Value set in" : "Unchanged since at least"} version ${c.version}, ${absoluteTime(c.time)}`}>
      changed {c.exact ? "" : "≥ "}{relativeTime(c.time)} · v{c.version}
    </span>
  );
}

function Arrow({ dir, pressed, onClick, label }: { dir: Direction; pressed: boolean; onClick: () => void; label: string }) {
  return (
    <button type="button" className={`arrow ${dir === "left_to_right" ? "to-right" : "to-left"}`}
            aria-pressed={pressed} title={label} aria-label={label} onClick={onClick}>
      {dir === "left_to_right" ? "→" : "←"}
    </button>
  );
}

export function SecretRow({ secret, left, right, reveal, changeset, onChangeset, onInspect, sideNames }: Props) {
  const [open, setOpen] = useState(false);
  const [values, setValues] = useState<{ left: Values; right: Values } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<{ left: KeyHistory | null; right: KeyHistory | null } | null>(null);

  // When each key last changed: version numbers and times only, so no Reveal needed.
  useEffect(() => {
    if (!open || history) return;
    let live = true;
    const load = (s: SideSummary, info: SideInfo) => info.state === "present"
      ? api.history(s.conn_id, s.mount, fullPath(s, sidePath(secret, s === left ? "left" : "right"))).catch(() => null)
      : Promise.resolve(null);
    Promise.all([load(left, secret.left), load(right, secret.right)])
      .then(([l, r]) => { if (live) setHistory({ left: l, right: r }); });
    return () => { live = false; };
  }, [open, history, left, right, secret]);

  // Fetch values only when this row is open AND Reveal is on. Forget them when Reveal goes off.
  useEffect(() => {
    if (!reveal) { setValues(null); return; }
    if (!open || values) return;
    let live = true;
    const read = (s: SideSummary, info: SideInfo) => info.state === "present"
      ? api.secret(s.conn_id, s.mount, fullPath(s, sidePath(secret, s === left ? "left" : "right"))).then((r) => r.data)
      : Promise.resolve(null);
    Promise.all([read(left, secret.left), read(right, secret.right)])
      .then(([l, r]) => { if (live) setValues({ left: l, right: r }); })
      .catch((e) => { if (live) setError(e.message); });
    return () => { live = false; };
  }, [open, reveal, values, left, right, secret]);

  const slash = secret.path.lastIndexOf("/");
  const dir = slash >= 0 ? secret.path.slice(0, slash + 1) : "";
  const leaf = secret.path.slice(slash + 1);
  const loading = reveal && open && !values && !error;
  const staged = stagedKeyCount(changeset, secret);
  const inspectTargets = (k: KeyDiff): InspectTarget[] => (["left", "right"] as const)
    .filter((side) => onSide(k, side, secret[side]) && secret[side].state === "present")
    .map((side) => {
      const s = side === "left" ? left : right;
      return { side, title: `${sideNames[side]} · ${k.key}`,
               loc: { conn_id: s.conn_id, mount: s.mount, path: fullPath(s, sidePath(secret, side)), key: k.key } };
    });
  const incoming = (k: KeyDiff, side: "left" | "right") =>
    isKeyStaged(changeset, secret.path, k.key, side === "right" ? "left_to_right" : "right_to_left");

  return (
    <div className="secret" data-open={open}>
      <button type="button" className="secret-head" aria-expanded={open} onClick={() => setOpen(!open)}>
        <span className="caret">▸</span>
        <span className="secret-path">
          {secret.left_path && secret.left_path !== secret.right_path ? (
            <span title="Paired by a profile mapping">
              <span className="map-l">{secret.left_path}</span><span className="map-arrow"> ⇄ </span><span className="map-r">{secret.right_path}</span>
            </span>
          ) : <><span className="dir">{dir}</span>{leaf}</>}
        </span>
        <span className="secret-meta">
          {staged > 0 && <span className="staged-count">{staged} staged</span>}
          {secret.ignored_keys > 0 && <span className="badge ignored" title="Differences in these keys are ignored by the profile">{secret.ignored_keys} ignored</span>}
          <span className="subtle">{summaryText(secret)}</span>
          <span className="vers">
            <Version info={secret.left} /> / <Version info={secret.right} />
          </span>
          <span className={`badge ${secret.status}`}>{STATUS_LABEL[secret.status]}</span>
        </span>
      </button>

      {open && (
        <div className="keys">
          {secret.note && <div className="notice error">{secret.note}</div>}
          {secret.status === "no_access" && (
            <div className="notice info">
              One side can’t read this secret, so its keys can’t be compared.
            </div>
          )}
          {(secret.left.error || secret.right.error) && (
            <div className="notice error">{secret.left.error || secret.right.error}</div>
          )}
          {error && <div className="notice error">Couldn’t read values: {error}</div>}
          {(canCopySecret(secret, "left_to_right") || canCopySecret(secret, "right_to_left")) && (
            <div className="secret-actions">
              <span className="subtle">Copy whole secret:</span>
              {canCopySecret(secret, "right_to_left") && (
                <button type="button" className="btn small to-left-btn" aria-pressed={isSecretStaged(changeset, secret.path, "right_to_left")}
                        onClick={() => onChangeset(toggleSecret(changeset, secret, "right_to_left"))}>
                  ← all keys to left
                </button>
              )}
              {canCopySecret(secret, "left_to_right") && (
                <button type="button" className="btn small to-right-btn" aria-pressed={isSecretStaged(changeset, secret.path, "left_to_right")}
                        onClick={() => onChangeset(toggleSecret(changeset, secret, "left_to_right"))}>
                  all keys to right →
                </button>
              )}
              <span className="subtle">Keys only on the target are kept.</span>
            </div>
          )}
          {secret.keys.length === 0 && <div className="subtle">No keys.</div>}
          {secret.keys.map((k) => (
            <div className={`key-row${k.ignored ? " ignored" : ""}`} key={k.key}
                 data-incoming={incoming(k, "right") ? "right" : incoming(k, "left") ? "left" : undefined}>
              <div className="key-name">
                {k.key}
                {k.ignored && <span className="badge ignored" title="The profile ignores differences in this key">ignored</span>}
                {k.type_differs && (
                  <span className="subtle" title="The values look alike but are stored as different JSON types">
                    type differs{values ? `: ${typeName(values.left?.[k.key])} vs ${typeName(values.right?.[k.key])}` : ""}
                  </span>
                )}
              </div>
              <ValueCell side="left" unavailable={unavailableFor(k, "left", secret.left)} reveal={reveal}
                         loading={loading} value={values?.left?.[k.key]} highlight={k.status === "different"} typed={k.type_differs}
                         meta={<><BadgeChip b={secret.badges?.[k.key]?.left} /><Changed c={history?.left?.keys[k.key]} /></>} />
              <div className="key-mid">
                <span className={`badge ${k.status}`}>{STATUS_LABEL[k.status]}</span>
                <div className="arrows">
                  {canCopyKey(secret, k, "right_to_left") && (
                    <Arrow dir="right_to_left" pressed={isKeyStaged(changeset, secret.path, k.key, "right_to_left")}
                           label={`Copy ${k.key} from right to left`}
                           onClick={() => onChangeset(toggleKey(changeset, secret, k.key, "right_to_left"))} />
                  )}
                  {canCopyKey(secret, k, "left_to_right") && (
                    <Arrow dir="left_to_right" pressed={isKeyStaged(changeset, secret.path, k.key, "left_to_right")}
                           label={`Copy ${k.key} from left to right`}
                           onClick={() => onChangeset(toggleKey(changeset, secret, k.key, "left_to_right"))} />
                  )}
                </div>
                {secret.badges?.[k.key] && inspectTargets(k).length > 0 && (
                  <button type="button" className="btn ghost small inspect-btn" onClick={() => onInspect(inspectTargets(k))}
                          title={inspectTargets(k).length > 1 ? "Inspect both sides" : "Inspect this value"}>
                    Inspect
                  </button>
                )}
              </div>
              <ValueCell side="right" unavailable={unavailableFor(k, "right", secret.right)} reveal={reveal}
                         loading={loading} value={values?.right?.[k.key]} highlight={k.status === "different"} typed={k.type_differs}
                         meta={<><BadgeChip b={secret.badges?.[k.key]?.right} /><Changed c={history?.right?.keys[k.key]} /></>} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
