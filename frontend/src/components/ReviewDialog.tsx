import { useEffect, useMemo, useRef, useState } from "react";
import { api, type SideRef } from "../api";
import { downloadPlan, downloadReport, downloadUndoPlan, planFileName } from "../plans";
import { type Changeset, hasOverrides, secretFor, toApiChanges, unstageChange, unstageKey } from "../staging";
import type { ApplyResult, ChangePlan, CompareResult, PlanStatus, ResultStatus, Rewrite, SyncPlan } from "../types";
import { AudienceField, parseAudience } from "./AudienceField";
import { formatValue } from "./ValueCell";

interface Props {
  result: CompareResult;
  changeset: Changeset;
  /** Taking things out of the review changes what's staged */
  onChangeset: (cs: Changeset) => void;
  reveal: boolean;
  profile: string | null;
  /** The profile's rewrites the comparison used: copies apply them too, in the copy's direction */
  rewrites?: Rewrite[];
  /** The two sides as compared (a Vault location or an opened export file) */
  sides: { left: SideRef; right: SideRef };
  onClose: (applied: boolean) => void;
}

const PLAN_LABEL: Record<PlanStatus, string> = {
  ready: "Will be written", noop: "Already the same", conflict: "Changed since compare",
  denied: "No permission", invalid: "Can’t copy", error: "Error",
};
const RESULT_LABEL: Record<ResultStatus, string> = {
  applied: "Written", noop: "No change needed", conflict: "Conflict: not written",
  denied: "Denied: not written", invalid: "Skipped", error: "Failed", skipped: "Not attempted",
};
const tone = (s: string) =>
  s === "ready" || s === "applied" ? "equal" : s === "noop" ? "unknown" : s === "conflict" ? "different" : "error";

export function ReviewDialog({ result, changeset, onChangeset, reveal, profile, rewrites = [], sides, onClose }: Props) {
  // Plans name Vaults on both sides, so they can't involve an export file
  const vaultSide = (s: SideRef) => ("conn_id" in s ? s : null);
  const fileSide = !vaultSide(sides.left) || !vaultSide(sides.right);
  const ref = useRef<HTMLDialogElement>(null);
  const changes = useMemo(() => toApiChanges(changeset, result), [changeset, result]);
  const [plans, setPlans] = useState<ChangePlan[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [applying, setApplying] = useState(false);
  const [applied, setApplied] = useState<ApplyResult | null>(null);
  const [undoing, setUndoing] = useState(false);
  const [undoFile, setUndoFile] = useState<string | null>(null);
  const [planning, setPlanning] = useState(false);
  const [note, setNote] = useState("");
  const [audience, setAudience] = useState(""); // the Lockstep servers that may apply the plan
  const [saved, setSaved] = useState<SyncPlan | null>(null);

  useEffect(() => { ref.current?.showModal(); }, []);
  useEffect(() => {
    let live = true;
    setPlans(null);
    setConfirmed(false); // what's confirmed changed
    api.syncPreview(sides.left, sides.right, changes, reveal, rewrites)
      .then((p) => { if (live) setPlans(p); })
      .catch((e) => { if (live) setError(e.message); });
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [changes, reveal, result]);

  const ready = plans?.filter((p) => p.status === "ready") ?? [];
  const blocked = plans?.filter((p) => p.status !== "ready" && p.status !== "noop") ?? [];
  const targets = [...new Set(ready.map((p) => `${p.target.name} · ${p.target.mount}`))];
  // A plan can hold changes you can't write yourself (someone with write access applies it),
  // but not ones that conflict or can't be read.
  const writeDenied = (p: ChangePlan) => p.status === "denied" && p.keys.length > 0;
  const plannable = plans?.filter((p) => p.status === "ready" || writeDenied(p)) ?? [];
  const unplannable = plans?.filter((p) => !["ready", "noop"].includes(p.status) && !writeDenied(p)) ?? [];
  // Typed values (overrides) aren't saved in a plan: whoever applies it types them again
  const overrides = hasOverrides(changeset);
  const secretOf = (p: ChangePlan) => secretFor(result, p.path, p.right_path);
  const dropKey = (p: ChangePlan, key: string) => {
    const s = secretOf(p);
    if (s) onChangeset(unstageKey(changeset, s, p.direction, key));
  };
  const dropChange = (p: ChangePlan) => {
    const s = secretOf(p);
    if (s) onChangeset(unstageChange(changeset, s, p.direction));
  };

  async function savePlan() {
    setPlanning(true);
    setError(null);
    try {
      const plan = await api.planCreate(vaultSide(sides.left)!, vaultSide(sides.right)!, changes, note, profile, rewrites, parseAudience(audience));
      downloadPlan(plan);
      setSaved(plan);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setPlanning(false);
    }
  }

  async function apply() {
    setApplying(true);
    setError(null);
    try {
      const readyChanges = changes.filter((c) => ready.some((p) => p.path === c.path && p.direction === c.direction));
      setApplied(await api.syncApply(sides.left, sides.right, readyChanges, rewrites));
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
        {undoFile && (
          <div className="notice info" role="status">
            Undo plan saved as <span className="mono">{undoFile}</span>. To put the old versions back, open it in
            the <strong>Sync plans</strong> tab. It works while nobody has written these secrets since.
          </div>
        )}
        {saved && (
          <div className="notice info" role="status">
            Plan saved as <span className="mono">{planFileName(saved, "json")}</span>. Pass it to someone with write access:
            they open it in the <strong>Sync plans</strong> tab, check it and apply it.
            {saved.changes.some((c) => c.typed) && " The values you typed aren't in it: tell whoever applies it what to type (Lockstep checks they match yours)."}{" "}
            <button type="button" className="btn ghost small" onClick={() => downloadReport(saved).catch((e) => setError(e.message))}>
              Download report
            </button>
          </div>
        )}
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
                  {r.status === "applied"
                    ? r.action === "delete" ? `v${r.old_version ?? "—"} deleted (every key removed: ${r.keys.join(", ")})`
                    : `v${r.old_version ?? "—"} → v${r.new_version} · ${r.keys.join(", ")}${r.overridden.length ? ` (typed: ${r.overridden.join(", ")})` : ""}`
                    : r.message}
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
                    <span className="muted">{p.source.state === "unused" ? (p.keys.every((k) => k.action === "remove") ? "Removing keys" : "Typed values") : `${p.source.name} · ${p.source.mount}/${p.source.path}`}</span>
                    <span className={p.direction === "left_to_right" ? "dir-r" : "dir-l"}> → </span>
                    {p.target.name} · {p.target.mount}/{p.target.path}
                  </span>
                  <span className="plan-head-end">
                    <span className={`badge ${tone(p.status)}`}>{PLAN_LABEL[p.status]}</span>
                    <button type="button" className="btn ghost small" onClick={() => dropChange(p)}
                            title="Take this secret out of the changes">Remove</button>
                  </span>
                </div>
                <div className="subtle">
                  {p.action === "delete" ? `Target v${p.target.version ?? "—"} is deleted (soft: \`vault kv undelete\` brings it back)`
                    : p.target.state === "absent" ? "New secret on the target"
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
                          <td><span className={`action ${k.action}`}>{k.action === "unchanged" ? "same" : k.action}</span>
                            {k.type_change && <span className="type-tag">type changes</span>}
                            {k.override && <span className="type-tag" title="A value you typed, not copied from the other side">typed</span>}
                            {k.rewritten && <span className="type-tag" title={`The profile's rewrites change the copied value: ${rewrites.map((w) => p.direction === "left_to_right" ? `${w.left} → ${w.right}` : `${w.right} → ${w.left}`).join(", ")}`}>rewritten</span>}</td>
                          {reveal && (
                            <td className="mono vals">
                              {k.action === "remove" ? <s>{formatValue(k.target_value)}</s> : <>
                                {k.action === "update" && <><s>{formatValue(k.target_value, k.type_change)}</s> → </>}
                                {formatValue(k.source_value, k.type_change)}
                              </>}
                            </td>
                          )}
                          <td className="drop">
                            <button type="button" className="btn ghost icon small" aria-label={`Don't change ${k.key}`}
                                    title="Don't change this key" onClick={() => dropKey(p, k.key)}>×</button>
                          </td>
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
            {applied.summary.applied > 0 && (
              <button type="button" className="btn ghost" disabled={undoing || Boolean(undoFile)}
                      title="Download a plan that puts back the versions these writes replaced (read from Vault's history when applied)"
                      onClick={async () => {
                        setUndoing(true);
                        setError(null);
                        try { setUndoFile(await downloadUndoPlan(applied.results)); } catch (e) { setError((e as Error).message); }
                        finally { setUndoing(false); }
                      }}>
                {undoing && <span className="spinner" />} {undoFile ? "Undo plan saved" : "Make an undo plan"}
              </button>
            )}
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
            {plans && plannable.length > 0 && !saved && overrides && !fileSide && (
              <span className="subtle plan-values-ok" title="The plan keeps a check code for each typed value, never the value">
                A plan doesn't keep the values you typed: whoever applies it types them again.
              </span>
            )}
            {plans && plannable.length > 0 && !saved && !fileSide && (
              <input type="text" className="plan-note-input" placeholder="Note for the plan (optional)" value={note}
                     maxLength={2000} onChange={(e) => setNote(e.target.value)} aria-label="Plan note" />
            )}
            {plans && plannable.length > 0 && !saved && !fileSide && <AudienceField value={audience} onChange={setAudience} />}
            <button type="button" className="btn ghost" disabled={!plans || plannable.length === 0 || unplannable.length > 0 || fileSide || planning || applying || Boolean(saved)}
                    title={fileSide ? "A plan needs a Vault on both sides, not an export file"
                      : unplannable.length > 0 ? "Some changes conflict or can't be read: compare again first" : "Download these changes as a plan for someone else to apply"}
                    onClick={savePlan}>
              {planning && <span className="spinner" />} {saved ? "Plan saved" : "Save as plan"}
            </button>
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
