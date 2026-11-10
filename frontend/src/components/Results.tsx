import { useMemo, useState } from "react";
import type { Changeset } from "../staging";
import type { InspectTarget } from "./Inspector";
import type { CompareResult, ExportDoc, ProfileRules, SecretStatus } from "../types";
import { SecretRow, STATUS_LABEL } from "./SecretRow";

type Filter = "changes" | "all" | SecretStatus;

const CHANGE_STATUSES: SecretStatus[] = ["different", "left_only", "right_only", "no_access", "error"];
const PAGE = 200;

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
}

export function Results({ result, reveal, leftLabel, rightLabel, changeset, onChangeset, onInspect, ignoreMode, draft, onDraft, fileDocs }: Props) {
  const [filter, setFilter] = useState<Filter>("changes");
  const [query, setQuery] = useState("");
  const [limit, setLimit] = useState(PAGE);
  const s = result.summary;
  const changes = CHANGE_STATUSES.reduce((n, st) => n + s[st], 0);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return result.secrets.filter((x) =>
      (filter === "all" || (filter === "changes" ? CHANGE_STATUSES.includes(x.status) : x.status === filter))
      && (!q || x.path.toLowerCase().includes(q) || x.keys.some((k) => k.key.toLowerCase().includes(q))));
  }, [result, filter, query]);

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
        ) : (
          shown.slice(0, limit).map((x) => (
            <SecretRow key={x.path} secret={x} left={result.left} right={result.right} reveal={reveal}
                       changeset={changeset} onChangeset={onChangeset} onInspect={onInspect}
                       sideNames={{ left: leftLabel, right: rightLabel }}
                       ignoreMode={ignoreMode} draft={draft} onDraft={onDraft} fileDocs={fileDocs} />
          ))
        )}
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
