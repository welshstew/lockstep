import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { saveAccessPlan } from "../accessPlan";
import { approvalsNeeded } from "../plans";
import { AudienceField, parseAudience } from "./AudienceField";
import type { AccessChanges, AccessItem, AccessPlanInfo, PlanApprovals } from "../types";

const ACTION: Record<AccessItem["action"], [string, string]> = {
  new: ["new", "equal"], change: ["change", "different"], same: ["same", "unknown"], delete: ["delete", "error"], absent: ["not there", "unknown"],
};
const STATUS: Record<AccessItem["status"], string> = {
  ready: "Will be written", noop: "Nothing to do", denied: "Not allowed", invalid: "Can’t be written", conflict: "Changed: not written",
  applied: "Done", error: "Failed",
};

/** Review policy and role changes against what's in Vault, then write them (policy builder phase 5).
 * With `plan`, the changes come from a saved access plan: checked and applied by the server, on
 * whichever of `connIds` is signed in to the plan's Vault. */
export function AccessApply({ changes, label, onClose, plan, connIds = [], canApply = true }: {
  changes?: AccessChanges; label?: string; onClose: (done: boolean) => void;
  plan?: Record<string, unknown>; connIds?: string[]; canApply?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const [items, setItems] = useState<AccessItem[] | null>(null);
  const [applied, setApplied] = useState<AccessItem[] | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<AccessPlanInfo | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const [audience, setAudience] = useState(""); // the Lockstep servers that may apply a saved plan
  const [target, setTarget] = useState<string | null>(null);
  const [current, setCurrent] = useState(plan);  // the plan, with any approval added here
  const [approvals, setApprovals] = useState<PlanApprovals | null>(null);
  useEffect(() => { ref.current?.showModal(); }, []);
  const check = (p: Record<string, unknown>) => api.accessPlanCheck(connIds, p)
    .then((r) => { setInfo(r.plan); setItems(r.items); setTarget(r.conn_id); setApprovals(r.approvals); })
    .catch((e) => setError(e.message));
  useEffect(() => {
    if (plan) check(plan);
    else if (changes) api.accessPreview(changes).then(setItems).catch((e) => setError(e.message));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  const unapproved = Boolean(approvals && approvals.approved_by.length < approvals.required);

  async function approve() {
    setBusy(true);
    setError(null);
    try {
      const approved = await api.accessPlanApprove(target ? [target] : connIds, current!);
      setCurrent(approved);
      const url = URL.createObjectURL(new Blob([JSON.stringify(approved, null, 2) + "\n"], { type: "application/json" }));
      const a = document.createElement("a");
      a.href = url; a.download = `lockstep-access-plan-${approved.id}-approved.json`; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      await check(approved);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const where = info ? info.vault + (info.namespace ? ` (namespace ${info.namespace})` : "") : label ?? "";

  const ready = (items ?? []).filter((i) => i.status === "ready");
  const deletes = ready.filter((i) => i.action === "delete");
  const phrase = deletes.length === 1 ? `delete ${deletes[0].name}` : `delete ${deletes.length} items`;
  const rows = applied ?? items ?? [];

  async function apply() {
    setBusy(true);
    setError(null);
    try {
      setApplied(plan ? await api.accessPlanApply(target ? [target] : connIds, current!)
        : await api.accessApply(changes!, Object.fromEntries((items ?? []).map((i) => [i.id, i.hash]))));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <dialog ref={ref} className="review" aria-label="Write policies and roles" onClose={() => onClose(Boolean(applied?.some((i) => i.status === "applied")))}>
      <header className="review-head">
        <h2>{applied ? "Written" : plan ? `Access plan ${info?.id ?? ""}` : `Write to ${label}`}</h2>
        <button type="button" className="btn ghost icon small" aria-label="Close" onClick={() => ref.current?.close()} disabled={busy}>✕</button>
      </header>
      <div className="review-body">
        {error && <div className="notice error" role="alert">{error}</div>}
        {!items && !error && <div className="empty"><span className="spinner" /> Comparing with what’s in Vault…</div>}
        {info && <div className="subtle">Made by <strong>{info.created_by}</strong> on {new Date(info.created).toLocaleString()} for <strong>{where}</strong>.
          Anything that changed in Vault since then is skipped.{info.audience?.length ? <> Only for <strong>{info.audience.join(", ")}</strong>.</> : null}</div>}
        {approvals && !applied && (approvals.required > 0 || approvals.approved_by.length > 0) && (
          <div className={`notice ${unapproved ? "warn" : "info"} plan-approvals`} role="status">
            {approvals.approved_by.length > 0 ? <>Approved by {approvals.approved_by.join(", ")}. </> : <>Not approved yet. </>}
            {approvalsNeeded(approvals)}
            {approvals.problems.join(" ")}
          </div>
        )}
        {plan && !canApply && <div className="notice warn">Writing policies and roles is turned off on this Lockstep server (LOCKSTEP_POLICY_APPLY): you can check the plan, not apply it.</div>}
        {saved && <div className="notice info" role="status">Saved access plan {saved}. Anyone with the rights can open it in Policies → Open an access plan… on this Lockstep server, check it and apply it.</div>}
        <ul className="plan-list">
          {rows.map((i) => (
            <li key={i.id} className={`plan ${["denied", "invalid", "conflict", "error"].includes(i.status) ? i.status : ""}`}>
              <div className="plan-head">
                <span className="mono">{i.kind === "policy" ? `policy ${i.name}` : i.kind === "group" ? `group ${i.name}: policies` : i.kind === "tune" ? `${i.name} tuning` : i.kind === "engine" ? i.name : `auth/${i.name.replace(/\/([^/]+)$/, "/role/$1")}`}</span>
                <span className="plan-head-end">
                  <span className={`badge ${ACTION[i.action][1]}`}>{ACTION[i.action][0]}</span>
                  <span className={`badge ${i.status === "ready" || i.status === "applied" ? "equal" : i.status === "noop" ? "unknown" : "error"}`}>{STATUS[i.status]}</span>
                </span>
              </div>
              {i.problems.map((p) => <div key={p} className="notice error">{p}</div>)}
              {i.warnings.map((w) => <div key={w} className="notice warn">{w}</div>)}
              {i.diff && !applied && <pre className="mono hcl-preview diff">{i.diff.split("\n").map((l, n) => (
                <span key={n} className={l.startsWith("+") && !l.startsWith("+++") ? "add" : l.startsWith("-") && !l.startsWith("---") ? "del" : ""}>{l}{"\n"}</span>))}</pre>}
            </li>
          ))}
        </ul>
        {items && !applied && ready.length > 0 && (
          <div className="subtle">Vault keeps no versions of policies or roles: each is checked again just before writing, and skipped if it changed since this preview.
            Policies are written before roles, deletes last. Every write is audit-logged.</div>
        )}
      </div>
      <footer className="review-foot">
        {applied ? <><span className="spacer" /><button type="button" className="btn primary" onClick={() => ref.current?.close()}>Close</button></> : (
          <>
            {ready.length > 0 && (deletes.length ? (
              <label className="destroy-confirm inline">Type <code className="phrase">{phrase}</code>
                <input type="text" className="mono" aria-label="Confirmation phrase" value={typed} onChange={(e) => setTyped(e.target.value)} /></label>
            ) : (
              <label className="confirm"><input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
                Write {ready.length} change{ready.length === 1 ? "" : "s"} to <strong>{where}</strong></label>
            ))}
            <span className="spacer" />
            {!plan && changes && items && !saved && <AudienceField value={audience} onChange={setAudience} />}
            {!plan && changes && items && (
              <button type="button" className="btn ghost" title="A signed file with these changes (no secrets), for someone with the rights to check and apply"
                      onClick={async () => { try { setSaved(await saveAccessPlan(changes, parseAudience(audience))); } catch (e) { setError((e as Error).message); } }}>Save as access plan</button>
            )}
            {plan && items && (approvals?.required ?? 0) > 0 && (
              <button type="button" className="btn ghost" disabled={busy} onClick={approve}
                      title="Add your approval to the plan and download it: four-eyes, before someone applies it">Approve</button>
            )}
            <button type="button" className="btn ghost" onClick={() => ref.current?.close()} disabled={busy}>Cancel</button>
            <button type="button" className={`btn ${deletes.length ? "danger-solid" : "primary"}`}
                    disabled={busy || !canApply || unapproved || !ready.length || (deletes.length ? typed !== phrase : !confirmed)} onClick={apply}>
              {busy && <span className="spinner" />} {deletes.length ? "Delete" : "Write"}
            </button>
          </>
        )}
      </footer>
    </dialog>
  );
}
