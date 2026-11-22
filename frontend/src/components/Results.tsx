import { useMemo, useState } from "react";
import { allStaged, canCopySecret, type Changeset, type Direction, stagedKeyCount, toggleSecrets } from "../staging";
import type { InspectTarget } from "./Inspector";
import type { CompareResult, ExportDoc, ProfileRules, SecretDiff, SecretStatus } from "../types";
import { SecretRow, STATUS_LABEL } from "./SecretRow";
import { DestroyDialog, type DestroyTarget } from "./DestroyDialog";

type VaultSide = { conn_id: string; mount: string; prefix: string };
type Side = "left" | "right";

type Filter = "changes" | "all" | SecretStatus;
type Grouping = "none" | "folder" | "staged";

const CHANGE_STATUSES: SecretStatus[] = ["different", "left_only", "right_only", "no_access", "error"];
const PAGE = 200;
const GROUP_KEY = "lockstep.group";

interface Props {
  result: CompareResult;
  reveal: boolean;
  leftLabel: string;
  rightLabel: string;
  changeset: Changeset;
  onChangeset: (cs: Changeset) => void;
  onInspect: (targets: InspectTarget[]) => void;
  ignoreMode?: boolean;
  draft?: ProfileRules;
  onDraft?: (r: ProfileRules) => void;
  /** Opened export files used as a side: their values are read here, not from Vault */
  fileDocs?: { left?: ExportDoc; right?: ExportDoc };
  /** Destroying secrets: each Vault side (not an export file), and what to do afterwards */
  destroy?: { left?: VaultSide; right?: VaultSide; onDone: () => void };
  /** A read-only server: no copies, edits or deletes */
  readOnly?: boolean;
}

const pathOn = (x: SecretDiff, side: Side) => (side === "left" ? x.left_path : x.right_path) || x.path;
/** Secrets with something on this side to destroy (current or soft-deleted versions). */
const destroyable = (x: SecretDiff, side: Side) => x[side].state === "present" || x[side].state === "deleted";
const targetOf = (x: SecretDiff, side: Side): DestroyTarget => ({ path: pathOn(x, side), version: x[side].version });

const folderOf = (path: string) => (path.includes("/") ? path.slice(0, path.lastIndexOf("/") + 1) : "");

function loadGrouping(): Grouping {
  try {
    const v = localStorage.getItem(GROUP_KEY);
    return v === "folder" || v === "staged" ? v : "none";
  } catch { return "none"; }
}

/** Copy every secret in a list one way: per folder, or everything shown. */
function BulkCopy({ secrets, changeset, onChangeset, sides, what }: {
  secrets: SecretDiff[]; changeset: Changeset; onChangeset: (cs: Changeset) => void;
  sides: { left: boolean; right: boolean }; what: string;
}) {
  const button = (d: Direction) => {
    const can = secrets.filter((s) => canCopySecret(s, d));
    if (!can.length || !sides[d === "left_to_right" ? "right" : "left"]) return null;
    const on = allStaged(changeset, secrets, d);
    const n = `${can.length} secret${can.length === 1 ? "" : "s"}`;
    return (
      <button key={d} type="button" className={`btn small ${d === "left_to_right" ? "to-right-btn" : "to-left-btn"}`} aria-pressed={on}
              title={on ? `Unstage the copies of ${what}` : `Copy every differing key of ${what} (${n}) ${d === "left_to_right" ? "to the right" : "to the left"}`}
              onClick={() => onChangeset(toggleSecrets(changeset, secrets, d))}>
        {d === "left_to_right" ? `all ${n} to right →` : `← all ${n} to left`}
      </button>
    );
  };
  return <span className="bulk-copy">{button("right_to_left")}{button("left_to_right")}</span>;
}

export function Results({ result, reveal, leftLabel, rightLabel, changeset, onChangeset, onInspect, ignoreMode, draft, onDraft, fileDocs, destroy, readOnly }: Props) {
  const [destroying, setDestroying] = useState<{ side: Side; secrets: DestroyTarget[] } | null>(null);
  const [filter, setFilter] = useState<Filter>("changes");
  const [query, setQuery] = useState("");
  const [limit, setLimit] = useState(PAGE);
  const [grouping, setGroupingState] = useState<Grouping>(loadGrouping);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [folded, setFolded] = useState<Set<string>>(new Set()); // collapsed group headers
  const s = result.summary;
  const changes = CHANGE_STATUSES.reduce((n, st) => n + s[st], 0);
  const writable = { left: !readOnly && result.left.kind !== "file", right: !readOnly && result.right.kind !== "file" };

  const setGrouping = (g: Grouping) => {
    setGroupingState(g);
    try { localStorage.setItem(GROUP_KEY, g); } catch { /* ignore */ }
  };

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return result.secrets.filter((x) =>
      (filter === "all" || (filter === "changes" ? CHANGE_STATUSES.includes(x.status) : x.status === filter))
      && (!q || x.path.toLowerCase().includes(q) || x.keys.some((k) => k.key.toLowerCase().includes(q))));
  }, [result, filter, query]);
  const page = shown.slice(0, limit);

  // Groups of the rows on this page, in order. Staged grouping puts staged secrets first.
  const groups = (() => {
    if (grouping === "none") return [{ id: "", label: "", rows: page }];
    if (grouping === "staged") {
      const st = page.filter((x) => stagedKeyCount(changeset, x) > 0);
      return [{ id: "staged", label: "Staged", rows: st }, { id: "unstaged", label: "Not staged", rows: page.filter((x) => !st.includes(x)) }]
        .filter((g) => g.rows.length);
    }
    const by = new Map<string, SecretDiff[]>();
    for (const x of page) {
      const f = folderOf(x.path);
      by.set(f, [...(by.get(f) ?? []), x]);
    }
    return [...by.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([f, rows]) => ({ id: `f:${f}`, label: f || "(top level)", rows }));
  })();

  const chips: { id: Filter; label: string; n: number }[] = [
    { id: "changes", label: "All changes", n: changes },
    ...(["different", "left_only", "right_only", "no_access", "error", "equal"] as SecretStatus[])
      .filter((st) => s[st] > 0)
      .map((st) => ({ id: st as Filter, label: STATUS_LABEL[st], n: s[st] })),
    { id: "all", label: "Everything", n: s.total },
  ];

  const warnings = [
    ...(["left", "right"] as const).flatMap((side) => {
      const sum = result[side];
      const label = side === "left" ? leftLabel : rightLabel;
      return [
        sum.denied.length > 0 && `${label}: no permission to list ${sum.denied.map((d) => d || "(root)").join(", ")}. Secrets there show as “No access”.`,
        sum.truncated && `${label}: too many secrets, so the listing was cut short. Narrow it with a path prefix.`,
      ].filter(Boolean) as string[];
    }),
  ];

  const toggleOpen = (path: string) => setOpen((o) => {
    const next = new Set(o);
    if (next.has(path)) next.delete(path); else next.add(path);
    return next;
  });
  const toggleFold = (id: string) => setFolded((f) => {
    const next = new Set(f);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });
  const row = (x: SecretDiff) => (
    <SecretRow key={x.path} secret={x} left={result.left} right={result.right} reveal={reveal}
               open={open.has(x.path)} onToggle={() => toggleOpen(x.path)}
               changeset={changeset} onChangeset={onChangeset} onInspect={onInspect}
               sideNames={{ left: leftLabel, right: rightLabel }}
               ignoreMode={ignoreMode} draft={draft} onDraft={onDraft} fileDocs={fileDocs}
               onDestroy={destroy && ((side) => setDestroying({ side, secrets: [targetOf(x, side)] }))}
               canDestroy={{ left: !!destroy?.left, right: !!destroy?.right }} readOnly={readOnly} />
  );
  const destroyAll = (side: Side) => {
    if (!destroy?.[side]) return null;
    const these = shown.filter((x) => destroyable(x, side));
    if (!these.length) return null;
    return (
      <button type="button" className="btn ghost small danger" onClick={() => setDestroying({ side, secrets: these.map((x) => targetOf(x, side)) })}
              title={`Permanently delete every secret ${query.trim() ? "matching the filter" : "shown"} that exists on the ${side} (${these.length}), with all their versions`}>
        Destroy all on {side} ({these.length})…
      </button>
    );
  };

  return (
    <section>
      {warnings.map((w) => <div key={w} className="notice warn">{w}</div>)}

      <div className="results-head">
        <div className="filters" role="group" aria-label="Filter by status">
          {chips.map((c) => (
            <button key={c.id} type="button" className="chip" aria-pressed={filter === c.id}
                    onClick={() => { setFilter(c.id); setLimit(PAGE); }}>
              {c.label} <span className="n">{c.n}</span>
            </button>
          ))}
        </div>
        <input type="search" className="search" placeholder="Filter by path or key…" value={query}
               onChange={(e) => { setQuery(e.target.value); setLimit(PAGE); }} />
      </div>

      <div className="results-tools">
        <label className="group-select">
          <span className="subtle">Group</span>
          <select value={grouping} onChange={(e) => setGrouping(e.target.value as Grouping)} aria-label="Group secrets">
            <option value="none">None</option>
            <option value="folder">By folder</option>
            <option value="staged">Staged first</option>
          </select>
        </label>
        <button type="button" className="btn ghost small" disabled={!page.length}
                onClick={() => { setOpen(new Set(page.map((x) => x.path))); setFolded(new Set()); }}>Expand all</button>
        <button type="button" className="btn ghost small" disabled={!open.size}
                onClick={() => setOpen(new Set())}>Collapse all</button>
        <span className="spacer" />
        {shown.length > 0 && (
          <>
            <span className="subtle">{query.trim() ? "Everything matching the filter:" : "Everything shown:"}</span>
            <BulkCopy secrets={shown} changeset={changeset} onChangeset={onChangeset} sides={writable}
                      what={query.trim() ? "the secrets matching the filter" : "the secrets shown"} />
            {(destroy?.left || destroy?.right) && <span className="destroy-all">{destroyAll("left")}{destroyAll("right")}</span>}
          </>
        )}
      </div>

      {destroying && destroy?.[destroying.side] && (
        <DestroyDialog side={destroying.side} sideLabel={destroying.side === "left" ? leftLabel : rightLabel}
                       vault={destroy[destroying.side]!} secrets={destroying.secrets}
                       onClose={(destroyed) => { setDestroying(null); if (destroyed) destroy.onDone(); }} />
      )}

      <div className="card">
        <div className="cols-head">
          <span className="l">◧ {leftLabel}</span>
          <span className="r">{rightLabel} ◨</span>
        </div>
        {shown.length === 0 ? (
          <div className="empty">
            {s.total === 0 ? "Neither side has any secrets here."
              : filter === "changes" ? "No differences. Both sides match." : "Nothing matches this filter."}
          </div>
        ) : groups.map((g) => g.id === "" ? <div key="all">{g.rows.map(row)}</div> : (
          <div key={g.id} className="group" data-folded={folded.has(g.id)}>
            <div className="group-head">
              <button type="button" className="group-toggle" aria-expanded={!folded.has(g.id)} onClick={() => toggleFold(g.id)}>
                <span className="caret">▸</span>
                <span className={grouping === "folder" ? "mono" : ""}>{g.label}</span>
                <span className="subtle">{g.rows.length} secret{g.rows.length === 1 ? "" : "s"}</span>
              </button>
              {grouping === "folder" && (
                <BulkCopy secrets={g.rows} changeset={changeset} onChangeset={onChangeset} sides={writable} what={`everything in ${g.label}`} />
              )}
            </div>
            {!folded.has(g.id) && g.rows.map(row)}
          </div>
        ))}
        {shown.length > limit && (
          <div className="empty">
            <button type="button" className="btn" onClick={() => setLimit(limit + PAGE)}>
              Show {Math.min(PAGE, shown.length - limit)} more of {shown.length - limit}
            </button>
          </div>
        )}
      </div>
    </section>
  );
}
