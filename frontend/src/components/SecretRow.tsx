import { type ReactNode, useEffect, useState } from "react";
import { api } from "../api";
import {
  canCopyKey, canCopySecret, canOverride, type Changeset, type Direction, isKeyOverridden, isKeyRemoved, isKeyStaged,
  isSecretStaged, overridesFor, setKeyValue, type Side, stagedKeyCount, toggleKey, toggleRemove, toggleSecret,
} from "../staging";
import { keyIgnored, literalSafe, pathIgnored, toggleIgnoreKey, toggleIgnorePath } from "../profiles";
import { absoluteTime, relativeTime } from "../time";
import type { Badge, ExportDoc, KeyChange, KeyDiff, KeyHistory, KeyStatus, ProfileRules, SecretDiff, SideInfo, SideSummary } from "../types";
import type { InspectTarget } from "./Inspector";
import { formatValue, typeName, ValueCell } from "./ValueCell";

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
  open: boolean;
  onToggle: () => void;
  changeset: Changeset;
  onChangeset: (cs: Changeset) => void;
  onInspect: (targets: InspectTarget[]) => void;
  sideNames: { left: string; right: string };
  /** Ignore mode: pick secrets and keys to leave out, building profile rules. */
  ignoreMode?: boolean;
  draft?: ProfileRules;
  onDraft?: (r: ProfileRules) => void;
  fileDocs?: { left?: ExportDoc; right?: ExportDoc };
  /** Destroy this secret on one side (opens a confirmation) */
  onDestroy?: (side: Side) => void;
  canDestroy?: { left: boolean; right: boolean };
  readOnly?: boolean;
}

type Values = Record<string, unknown> | null;
interface Draft { text: string; json: boolean; error?: string; touched?: boolean }
const SIDES: Side[] = ["left", "right"];
const other = (s: Side): Side => (s === "left" ? "right" : "left");
const asText = (v: unknown) => (v === undefined ? "" : typeof v === "string" ? v : JSON.stringify(v, null, 2));

// Opening many rows at once (Expand all) mustn't fire hundreds of reads together.
const MAX_READS = 6;
let reading = 0;
const queue: (() => void)[] = [];
function gated<T>(f: () => Promise<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const run = () => {
      reading++;
      f().then(resolve, reject).finally(() => { reading--; queue.shift()?.(); });
    };
    if (reading < MAX_READS) run();
    else queue.push(run);
  });
}

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

/** A value being typed in place of what a side has now. */
function ValueEditor({ name, draft, reveal, onChange, onSave, onCancel }: {
  name: string; draft: Draft; reveal: boolean;
  onChange: (d: Draft) => void; onSave: () => void; onCancel: () => void;
}) {
  return (
    <div className="val-cell editing">
      <textarea className={`val mono val-input${reveal ? "" : " masked-input"}`} autoFocus spellCheck={false} autoComplete="off"
                rows={Math.min(8, Math.max(2, draft.text.split("\n").length))} value={draft.text} aria-label={name}
                placeholder={reveal ? "New value" : "New value (Show values is off, so it starts empty)"}
                onChange={(e) => onChange({ ...draft, text: e.target.value, error: undefined, touched: true })}
                onKeyDown={(e) => {
                  if (e.key === "Escape") { e.preventDefault(); onCancel(); }
                  if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) { e.preventDefault(); onSave(); }
                }} />
      {draft.error && <div className="notice error" role="alert">{draft.error}</div>}
      <div className="cell-tools">
        <label className="inline-check subtle" title="Store as a JSON value (number, boolean, object…) instead of text">
          <input type="checkbox" checked={draft.json} onChange={(e) => onChange({ ...draft, json: e.target.checked, error: undefined, touched: true })} /> JSON
        </label>
        <span className="spacer" />
        <button type="button" className="btn ghost small" onClick={onCancel}>Cancel</button>
        <button type="button" className="btn primary small" onClick={onSave}>Set value</button>
      </div>
    </div>
  );
}

/** What a side will hold once applied: a typed value, or nothing (the key is removed). */
function StagedCell({ side, kind, value, reveal, onEdit, onUndo }: {
  side: Side; kind: "set" | "remove"; value?: unknown; reveal: boolean; onEdit?: () => void; onUndo: () => void;
}) {
  const typed = value !== undefined && typeof value !== "string";
  return (
    <div className={`val-cell staged ${kind}`}>
      {kind === "remove"
        ? <div className="val removed-val">will be removed</div>
        : <div className={`val typed-val ${reveal ? "" : "masked"}`}>
            {reveal ? <>{typed && <span className="type-tag">{typeName(value)}</span>}{formatValue(value, typed)}</> : "••••••••"}
          </div>}
      <div className="cell-tools">
        <span className={`badge override-tag ${kind === "remove" ? "remove" : side}`}>{kind === "remove" ? "delete staged" : "new value"}</span>
        <span className="spacer" />
        {onEdit && <button type="button" className="btn ghost small" onClick={onEdit}>Edit</button>}
        <button type="button" className="btn ghost small" onClick={onUndo}>Undo</button>
      </div>
    </div>
  );
}

export function SecretRow({ secret, left, right, reveal, open, onToggle, changeset, onChangeset, onInspect, sideNames, ignoreMode, draft, onDraft, fileDocs, onDestroy, canDestroy, readOnly }: Props) {
  // An export file side is read-only and has no history; its values are in the opened file.
  const isFile = { left: left.kind === "file", right: right.kind === "file" };
  const fileData = (s: SideSummary, path: string) => {
    const d = fileDocs?.[s === left ? "left" : "right"];
    return d?.secrets.find((x) => x.path === path)?.data ?? null;
  };
  const copyable = (d: Direction) => !readOnly && !isFile[d === "left_to_right" ? "right" : "left"];
  const [values, setValues] = useState<{ left: Values; right: Values } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<{ left: KeyHistory | null; right: KeyHistory | null } | null>(null);
  const [editing, setEditing] = useState<Record<string, Draft>>({}); // by `${side}|${key}`
  const [pending, setPending] = useState<string[]>([]); // keys being added, not staged yet
  const [newKey, setNewKey] = useState("");
  const [newKeyError, setNewKeyError] = useState<string | null>(null);

  // When each key last changed: version numbers and times only, so no Reveal needed.
  useEffect(() => {
    if (!open || history) return;
    let live = true;
    const load = (s: SideSummary, info: SideInfo) => info.state === "present" && s.kind !== "file"
      ? gated(() => api.history(s.conn_id, s.mount, fullPath(s, sidePath(secret, s === left ? "left" : "right")))).catch(() => null)
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
    const read = (s: SideSummary, info: SideInfo) => {
      if (info.state !== "present") return Promise.resolve(null);
      const path = fullPath(s, sidePath(secret, s === left ? "left" : "right"));
      if (s.kind === "file") return Promise.resolve(fileData(s, path));
      return gated(() => api.secret(s.conn_id, s.mount, path)).then((r) => r.data);
    };
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
    .filter((side) => onSide(k, side, secret[side]) && secret[side].state === "present" && !isFile[side])
    .map((side) => {
      const s = side === "left" ? left : right;
      return { side, title: `${sideNames[side]} · ${k.key}`,
               loc: { conn_id: s.conn_id, mount: s.mount, path: fullPath(s, sidePath(secret, side)), key: k.key } };
    });
  const copied = (key: string, side: Side) => isKeyStaged(changeset, secret.path, key, side === "right" ? "left_to_right" : "right_to_left");
  const editable = (side: Side) => !readOnly && canOverride(secret, side) && !isFile[side];
  const copySecret = (d: Direction) => copyable(d) && canCopySecret(secret, d);
  const overridden = { left: overridesFor(changeset, secret.path, "left"), right: overridesFor(changeset, secret.path, "right") };
  const known = new Set(secret.keys.map((k) => k.key));
  const addedKeys = [...new Set([...pending, ...SIDES.flatMap((x) => Object.keys(overridden[x] ?? {}))])]
    .filter((k) => !known.has(k)).sort();
  const lp = secret.left_path || secret.path, rp = secret.right_path || secret.path;
  const folder = dir ? `${dir}**` : null;
  const draftOut = !!draft && pathIgnored(draft, lp, rp);
  const pick = !!(ignoreMode && draft && onDraft);
  const present = (k: KeyDiff, side: Side) => secret[side].state === "present" && onSide(k, side, secret[side]);

  // Start from the value already typed, else the other side's value (that's usually the point),
  // else this side's own. Values are only known while Show values is on.
  function startValue(side: Side, key: string, vals: typeof values): Draft {
    const typed = overridden[side];
    const v = typed && key in typed ? typed[key]
      : vals?.[other(side)] && key in vals[other(side)]! ? vals[other(side)]![key]
      : vals?.[side]?.[key];
    return { text: asText(v), json: v !== undefined && typeof v !== "string" };
  }

  function startEdit(side: Side, key: string) {
    setEditing((e) => ({ ...e, [`${side}|${key}`]: startValue(side, key, values) }));
  }

  // Values that arrive after an editor opened fill it, unless something was typed already.
  useEffect(() => {
    if (!values) return;
    setEditing((e) => {
      let changed = false;
      const next = Object.fromEntries(Object.entries(e).map(([id, d]) => {
        if (d.touched || d.text) return [id, d];
        const [side, ...rest] = id.split("|");
        const fresh = startValue(side as Side, rest.join("|"), values);
        if (fresh.text) changed = true;
        return [id, fresh.text ? fresh : d];
      }));
      return changed ? next : e;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [values]);

  function stopEdit(side: Side, key: string) {
    setEditing((e) => {
      const next = { ...e };
      delete next[`${side}|${key}`];
      return next;
    });
  }

  function saveEdit(side: Side, key: string) {
    const d = editing[`${side}|${key}`];
    let value: unknown = d.text;
    if (d.json) {
      try { value = JSON.parse(d.text); } catch {
        setEditing((e) => ({ ...e, [`${side}|${key}`]: { ...d, error: "That isn't valid JSON. Untick JSON to store it as text." } }));
        return;
      }
    }
    onChangeset(setKeyValue(changeset, secret, side, key, value));
    stopEdit(side, key);
    setPending((p) => p.filter((k) => k !== key));
  }

  function cancelEdit(side: Side, key: string) {
    stopEdit(side, key);
    // A key that was being added and has nothing staged anywhere goes away again
    const elsewhere = Object.keys(editing).some((x) => x !== `${side}|${key}` && x.endsWith(`|${key}`));
    if (!elsewhere) setPending((p) => p.filter((k) => k !== key));
  }

  function addKey(sides: Side[]) {
    const k = newKey.trim();
    if (!k) return;
    if (known.has(k) || addedKeys.includes(k)) { setNewKeyError(`“${k}” is already in this secret: use Edit on its value.`); return; }
    setPending((p) => [...p, k]);
    setEditing((e) => ({ ...e, ...Object.fromEntries(sides.map((x) => [`${x}|${k}`, { text: "", json: false }])) }));
    setNewKey("");
    setNewKeyError(null);
  }

  /** One side of one key: the value, a staged change to it, or an editor. */
  function cell(key: string, side: Side, normal: (tools: ReactNode) => ReactNode, isPresent: boolean) {
    const d = editing[`${side}|${key}`];
    if (d) {
      return <ValueEditor name={`New value for ${key} on ${sideNames[side]}`} draft={d} reveal={reveal}
                          onChange={(n) => setEditing((e) => ({ ...e, [`${side}|${key}`]: n }))}
                          onSave={() => saveEdit(side, key)} onCancel={() => cancelEdit(side, key)} />;
    }
    if (isKeyRemoved(changeset, secret.path, key, side)) {
      return <StagedCell side={side} kind="remove" reveal={reveal} onUndo={() => onChangeset(toggleRemove(changeset, secret, side, key))} />;
    }
    if (isKeyOverridden(changeset, secret.path, key, side)) {
      return <StagedCell side={side} kind="set" value={overridden[side]![key]} reveal={reveal}
                         onEdit={() => startEdit(side, key)}
                         onUndo={() => onChangeset(setKeyValue(changeset, secret, side, key, undefined))} />;
    }
    const tools = editable(side) && (
      <>
        <button type="button" className="btn ghost small" onClick={() => startEdit(side, key)}
                title={`Type a new value for ${key} on ${sideNames[side]}`}>Edit</button>
        {isPresent && (
          <button type="button" className="btn ghost small danger" onClick={() => onChangeset(toggleRemove(changeset, secret, side, key))}
                  title={`Remove ${key} from ${sideNames[side]}`}>Delete</button>
        )}
      </>
    );
    return normal(tools || null);
  }

  /** Delete a key from every side that has it (or, if that's staged already, undo it). */
  function toggleDeleteEverywhere(k: KeyDiff) {
    const sides = SIDES.filter((x) => present(k, x) && editable(x));
    const all = sides.every((x) => isKeyRemoved(changeset, secret.path, k.key, x));
    onChangeset(sides.reduce((cs, x) => (isKeyRemoved(cs, secret.path, k.key, x) === all ? toggleRemove(cs, secret, x, k.key) : cs), changeset));
  }

  return (
    <div className={`secret${draftOut ? " draft-ignored" : ""}`} data-open={open}>
      <div className="secret-head-row">
      <button type="button" className="secret-head" aria-expanded={open} onClick={onToggle}>
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
      {pick && (
        <span className="ignore-tools" role="group" aria-label={`Ignore ${secret.path}`}>
          {draftOut && <span className="subtle">left out</span>}
          <button type="button" className="btn ghost small" aria-pressed={draft!.ignore_paths.includes(secret.path)}
                  disabled={!literalSafe(secret.path)} title="Leave this secret out of the comparison"
                  onClick={() => onDraft!(toggleIgnorePath(draft!, secret.path))}>Ignore secret</button>
          {folder && (
            <button type="button" className="btn ghost small" aria-pressed={draft!.ignore_paths.includes(folder)}
                    disabled={!literalSafe(folder.slice(0, -2))} title={`Leave out everything under ${dir}`}
                    onClick={() => onDraft!(toggleIgnorePath(draft!, folder))}>Ignore {folder}</button>
          )}
        </span>
      )}
      </div>

      {open && (
        <div className="keys">
          {secret.note && <div className="notice error">{secret.note}</div>}
          {secret.metadata_note && <div className="notice warn">{secret.metadata_note}</div>}
          {secret.metadata && secret.metadata.length > 0 && (
            <div className="notice info meta-diff" aria-label="Custom metadata differences">
              <strong>Custom metadata differs:</strong>
              <ul>{secret.metadata.map((m) => (
                <li key={m.key}><span className="mono">{m.key}</span>{" "}
                  {m.status === "different" ? <><span className="mono">{m.left}</span> → <span className="mono">{m.right}</span></>
                    : m.status === "left_only" ? <>only on the left: <span className="mono">{m.left}</span></>
                    : <>only on the right: <span className="mono">{m.right}</span></>}
                </li>))}</ul>
            </div>
          )}
          {secret.status === "no_access" && (
            <div className="notice info">
              One side can’t read this secret, so its keys can’t be compared.
            </div>
          )}
          {(secret.left.error || secret.right.error) && (
            <div className="notice error">{secret.left.error || secret.right.error}</div>
          )}
          {error && <div className="notice error">Couldn’t read values: {error}</div>}
          {(copySecret("left_to_right") || copySecret("right_to_left")) && (
            <div className="secret-actions">
              <span className="subtle">Copy whole secret:</span>
              {copySecret("right_to_left") && (
                <button type="button" className="btn small to-left-btn" aria-pressed={isSecretStaged(changeset, secret, "right_to_left")}
                        onClick={() => onChangeset(toggleSecret(changeset, secret, "right_to_left"))}>
                  ← all keys to left
                </button>
              )}
              {copySecret("left_to_right") && (
                <button type="button" className="btn small to-right-btn" aria-pressed={isSecretStaged(changeset, secret, "left_to_right")}
                        onClick={() => onChangeset(toggleSecret(changeset, secret, "left_to_right"))}>
                  all keys to right →
                </button>
              )}
              <span className="subtle">Keys only on the target are kept.</span>
            </div>
          )}
          {secret.keys.length === 0 && addedKeys.length === 0 && <div className="subtle">No keys.</div>}
          {secret.keys.map((k) => {
            const deletable = SIDES.filter((x) => present(k, x) && editable(x));
            const allDeleted = deletable.length > 0 && deletable.every((x) => isKeyRemoved(changeset, secret.path, k.key, x));
            return (
            <div className={`key-row${k.ignored ? " ignored" : ""}${draft && !k.ignored && keyIgnored(draft, k.key, lp, rp) ? " draft-ignored" : ""}`} key={k.key}
                 data-incoming={copied(k.key, "right") ? "right" : copied(k.key, "left") ? "left" : undefined}>
              <div className="key-name">
                <span className="key-label">{k.key}</span>
                {k.ignored && <span className="badge ignored" title="The profile ignores differences in this key">ignored</span>}
                {pick && k.status !== "equal" && (
                  <span className="ignore-tools key" role="group" aria-label={`Ignore key ${k.key}`}>
                    <button type="button" className="btn ghost small" aria-pressed={draft!.ignore_keys.some((x) => x.key === k.key && x.path === secret.path)}
                            disabled={!literalSafe(k.key) || !literalSafe(secret.path)} title="Ignore differences in this key, in this secret"
                            onClick={() => onDraft!(toggleIgnoreKey(draft!, k.key, secret.path))}>Ignore here</button>
                    <button type="button" className="btn ghost small" aria-pressed={draft!.ignore_keys.some((x) => x.key === k.key && x.path === "**")}
                            disabled={!literalSafe(k.key)} title="Ignore differences in this key in every secret"
                            onClick={() => onDraft!(toggleIgnoreKey(draft!, k.key, "**"))}>Ignore everywhere</button>
                  </span>
                )}
                {k.type_differs && (
                  <span className="subtle" title="The values look alike but are stored as different JSON types">
                    type differs{values ? `: ${typeName(values.left?.[k.key])} vs ${typeName(values.right?.[k.key])}` : ""}
                  </span>
                )}
                {deletable.length > 1 && (
                  <button type="button" className="btn ghost small danger key-delete" aria-pressed={allDeleted}
                          title={allDeleted ? "Keep this key" : `Remove ${k.key} from both sides`}
                          onClick={() => toggleDeleteEverywhere(k)}>
                    {allDeleted ? "Undo delete everywhere" : "Delete everywhere"}
                  </button>
                )}
              </div>
              {cell(k.key, "left", (tools) => (
                <ValueCell side="left" unavailable={unavailableFor(k, "left", secret.left)} reveal={reveal}
                           loading={loading} value={values?.left?.[k.key]} highlight={k.status === "different"} typed={k.type_differs}
                           meta={<><BadgeChip b={secret.badges?.[k.key]?.left} /><Changed c={history?.left?.keys[k.key]} /></>}
                           tools={tools} />
              ), present(k, "left"))}
              <div className="key-mid">
                <span className={`badge ${k.status}`}>{STATUS_LABEL[k.status]}</span>
                <div className="arrows">
                  {copyable("right_to_left") && canCopyKey(secret, k, "right_to_left")
                    && !isKeyOverridden(changeset, secret.path, k.key, "left") && !isKeyRemoved(changeset, secret.path, k.key, "left") && (
                    <Arrow dir="right_to_left" pressed={isKeyStaged(changeset, secret.path, k.key, "right_to_left")}
                           label={`Copy ${k.key} from right to left`}
                           onClick={() => onChangeset(toggleKey(changeset, secret, k.key, "right_to_left"))} />
                  )}
                  {copyable("left_to_right") && canCopyKey(secret, k, "left_to_right")
                    && !isKeyOverridden(changeset, secret.path, k.key, "right") && !isKeyRemoved(changeset, secret.path, k.key, "right") && (
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
              {cell(k.key, "right", (tools) => (
                <ValueCell side="right" unavailable={unavailableFor(k, "right", secret.right)} reveal={reveal}
                           loading={loading} value={values?.right?.[k.key]} highlight={k.status === "different"} typed={k.type_differs}
                           meta={<><BadgeChip b={secret.badges?.[k.key]?.right} /><Changed c={history?.right?.keys[k.key]} /></>}
                           tools={tools} />
              ), present(k, "right"))}
            </div>
            );
          })}
          {addedKeys.map((key) => (
            <div className="key-row added" key={`new:${key}`}>
              <div className="key-name">
                <span className="key-label">{key}</span>
                <span className="badge kind equal">new key</span>
              </div>
              {cell(key, "left", (tools) => <ValueCell side="left" unavailable="absent" reveal={reveal} loading={false} value={undefined} highlight={false} tools={tools} />, false)}
              <div className="key-mid" />
              {cell(key, "right", (tools) => <ValueCell side="right" unavailable="absent" reveal={reveal} loading={false} value={undefined} highlight={false} tools={tools} />, false)}
            </div>
          ))}
          {(editable("left") || editable("right")) && (
            <div className="add-key">
              <input type="text" className="mono" placeholder="new key name" value={newKey} aria-label="New key name"
                     onChange={(e) => { setNewKey(e.target.value); setNewKeyError(null); }}
                     onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addKey(SIDES.filter(editable)); } }} />
              {SIDES.filter(editable).map((x) => (
                <button key={x} type="button" className={`btn small add-${x}`} disabled={!newKey.trim()} onClick={() => addKey([x])}>
                  ＋ Add to {x}
                </button>
              ))}
              {editable("left") && editable("right") && (
                <button type="button" className="btn small" disabled={!newKey.trim()} onClick={() => addKey(["left", "right"])}>＋ Add to both</button>
              )}
              {newKeyError && <span className="notice error" role="alert">{newKeyError}</span>}
            </div>
          )}
          {onDestroy && SIDES.some((x) => canDestroy?.[x] && ["present", "deleted"].includes(secret[x].state)) && (
            <div className="secret-actions destroy-actions">
              <span className="subtle">Every version, permanently:</span>
              {SIDES.filter((x) => canDestroy?.[x] && ["present", "deleted"].includes(secret[x].state)).map((x) => (
                <button key={x} type="button" className="btn ghost small danger" onClick={() => onDestroy(x)}
                        title={`Permanently delete every version of this secret, and its metadata, on the ${x} (${sideNames[x]})`}>
                  Destroy on {x}…
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
