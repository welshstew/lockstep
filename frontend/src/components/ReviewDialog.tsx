import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import { type Changeset, toApiChanges } from "../staging";
import type { ApplyResult, ChangePlan, CompareResult, PlanStatus, ResultStatus } from "../types";
import { formatValue } from "./ValueCell";

interface Props {
  result: CompareResult;
  changeset: Changeset;
  reveal: boolean;
  onClose: (applied: boolean) => void;
}

const PLAN_LABEL: Record<PlanStatus, string> = {
  ready: "Will be written", noop: "Already the same", conflict: "Changed since compare",
  denied: "No permission", invalid: "Can’t copy", error: "Error",
};
const RESULT_LABEL: Record<ResultStatus, string> = {
  applied: "Written", noop: "No change needed", conflict: "Conflict: not written",
  denied: "Denied: not written", invalid: "Skipped", error: "Failed",
};
const tone = (s: string) =>
  s === "ready" || s === "applied" ? "equal" : s === "noop" ? "unknown" : s === "conflict" ? "different" : "error";

function side(r: CompareResult["left"]) {
  return { conn_id: r.conn_id, mount: r.mount, prefix: r.prefix };
}

export function ReviewDialog({ result, changeset, reveal, onClose }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const changes = useMemo(() => toApiChanges(changeset, result), [changeset, result]);
  const [plans, setPlans] = useState<ChangePlan[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [applying, setApplying] = useState(false);
  const [applied, setApplied] = useState<ApplyResult | null>(null);

  useEffect(() => { ref.current?.showModal(); }, []);
  useEffect(() => {
    let live = true;
    setPlans(null);
    api.syncPreview(side(result.left), side(result.right), changes, reveal)
      .then((p) => { if (live) setPlans(p); })
      .catch((e) => { if (live) setError(e.message); });
    return () => { live = false; };
  }, [changes, reveal, result]);

  const ready = plans?.filter((p) => p.status === "ready") ?? [];
  const blocked = plans?.filter((p) => p.status !== "ready" && p.status !== "noop") ?? [];
  const targets = [...new Set(ready.map((p) => `${p.target.name} · ${p.target.mount}`))];

  async function apply() {
    setApplying(true);
    setError(null);
    try {
      const readyChanges = changes.filter((c) => ready.some((p) => p.path === c.path && p.direction === c.direction));
      setApplied(await api.syncApply(side(result.left), side(result.right), readyChanges));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setApplying(false);
    }
  }

  const close = () => onClose(Boolean(applied?.summary.applied));

  return (
    <dialog ref={ref} className="review" onClose={close} onCancel={(e) => { if (applying) e.preventDefault(); }}>
      <header className="review-head">
        <h2>{applied ? "Changes applied" : "Review changes"}</h2>
        <button type="button" className="btn ghost icon small" aria-label="Close" onClick={() => ref.current?.close()} disabled={applying}>✕</button>
      </header>

      <div className="review-body">
        {error && <div className="notice error" role="alert">{error}</div>}
        {!plans && !error && <div className="empty"><span className="spinner" /> Checking current values in both Vaults…</div>}

        {applied ? (
          <ul className="plan-list">
            {applied.results.map((r) => (
              <li key={`${r.direction}${r.path}`} className="plan">
                <div className="plan-head">
                  <span className="mono">{r.target}</span>
                  <span className={`badge ${tone(r.status)}`}>{RESULT_LABEL[r.status]}</span>
                </div>
                <div className="subtle">
                  {r.status === "applied" ? `v${r.old_version ?? "—"} → v${r.new_version} · ${r.keys.join(", ")}` : r.message}
                </div>
              </li>
            ))}
          </ul>
        ) : plans && (
          <ul className="plan-list">
            {plans.map((p) => (
              <li key={`${p.direction}${p.path}`} className={`plan ${p.status}`}>
                <div className="plan-head">
                  <span className="mono">
                    <span className="muted">{p.source.name} · {p.source.mount}/{p.source.path}</span>
                    <span className={p.direction === "left_to_right" ? "dir-r" : "dir-l"}> → </span>
                    {p.target.name} · {p.target.mount}/{p.target.path}
                  </span>
                  <span className={`badge ${tone(p.status)}`}>{PLAN_LABEL[p.status]}</span>
                </div>
                <div className="subtle">
                  {p.target.state === "absent" ? "New secret on the target"
                    : `Target v${p.target.version ?? "—"} → v${(p.target.version ?? 0) + 1}`}
                </div>
                {p.problems.map((m) => <div key={m} className="notice error">{m}</div>)}
                {p.warnings.map((m) => <div key={m} className="notice warn">{m}</div>)}
                {p.keys.length > 0 && (
                  <table className="plan-keys">
                    <tbody>
                      {p.keys.map((k) => (
                        <tr key={k.key} className={k.action}>
                          <td className="mono">{k.key}</td>
                          <td><span className={`action ${k.action}`}>{k.action === "add" ? "add" : k.action === "update" ? "update" : "same"}</span>
                            {k.type_change && <span className="type-tag">type changes</span>}</td>
                          {reveal && (
                            <td className="mono vals">
                              {k.action === "update" && <><s>{formatValue(k.target_value, k.type_change)}</s> → </>}
                              {formatValue(k.source_value, k.type_change)}
                            </td>
                          )}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      <footer className="review-foot">
        {applied ? (
          <>
            <span className="muted">
              {applied.summary.applied} written
              {applied.summary.conflict + applied.summary.denied + applied.summary.error > 0 &&
                `, ${applied.summary.conflict + applied.summary.denied + applied.summary.error} not written`}
            </span>
            <button type="button" className="btn primary" onClick={() => ref.current?.close()}>Done, compare again</button>
          </>
        ) : (
          <>
            {plans && ready.length > 0 && (
              <label className="confirm">
                <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
                Write {ready.length} secret{ready.length === 1 ? "" : "s"} to <strong>{targets.join(", ")}</strong>
              </label>
            )}
            {plans && ready.length === 0 && <span className="muted">Nothing can be written. See the notes above.</span>}
            {blocked.length > 0 && ready.length > 0 && <span className="subtle">{blocked.length} item(s) will be skipped</span>}
            <span className="spacer" />
            <button type="button" className="btn ghost" onClick={() => ref.current?.close()} disabled={applying}>Cancel</button>
            <button type="button" className="btn primary" disabled={!confirmed || applying || ready.length === 0} onClick={apply}>
              {applying && <span className="spinner" />} Apply
            </button>
          </>
        )}
      </footer>
    </dialog>
  );
}
