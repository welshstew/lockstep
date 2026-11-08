import { useRef, useState } from "react";
import { api } from "../api";
import { downloadReport, vaultLabel } from "../plans";
import { absoluteTime } from "../time";
import type { Connection, PlanApplyResult, PlanCheck, PlanCheckStatus, SyncPlan } from "../types";

interface Props {
  connections: Connection[];
  leftConnId: string | null;
  rightConnId: string | null;
}

const CHECK_LABEL: Record<PlanCheckStatus, [string, string]> = {
  ready: ["Unchanged", "equal"],
  stale: ["Changed since the plan", "different"],
  denied: ["No write permission", "error"],
  error: ["Error", "error"],
};

/** Does this connection look like the plan's Vault? (A hint only: the server decides.) */
function looksLike(c: Connection | undefined, v: SyncPlan["left"]) {
  if (!c) return false;
  const ns = (x: string | null) => (x ?? "").replace(/^\/+|\/+$/g, "");
  const same = v.preset ? c.preset_id !== null && c.name === v.vault : (c.url ?? "").replace(/\/+$/, "") === v.vault;
  return same && ns(c.namespace) === ns(v.namespace);
}

export function PlansView({ connections, leftConnId, rightConnId }: Props) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [plan, setPlan] = useState<SyncPlan | null>(null);
  const [fileName, setFileName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [checked, setChecked] = useState<PlanCheck | null>(null);
  const [busy, setBusy] = useState<"check" | "apply" | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [applied, setApplied] = useState<PlanApplyResult | null>(null);

  const left = connections.find((c) => c.id === leftConnId);
  const right = connections.find((c) => c.id === rightConnId);

  function reset() {
    setChecked(null);
    setConfirmed(false);
    setApplied(null);
    setError(null);
  }

  async function open(file: File) {
    reset();
    setPlan(null);
    setFileName(file.name);
    try {
      let raw: unknown;
      try { raw = JSON.parse(await file.text()); } catch { throw new Error("This file isn't valid JSON, so it can't be a Lockstep plan."); }
      setPlan((await api.planVerify(raw)).plan);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function check() {
    if (!plan || !leftConnId || !rightConnId) return;
    reset();
    setBusy("check");
    try { setChecked(await api.planCheck(plan, leftConnId, rightConnId)); }
    catch (e) { setError((e as Error).message); }
    finally { setBusy(null); }
  }

  async function apply() {
    if (!plan || !leftConnId || !rightConnId) return;
    setBusy("apply");
    setError(null);
    try { setApplied(await api.planApply(plan, leftConnId, rightConnId)); }
    catch (e) {
      setError((e as Error).message);
      setChecked(null);
      setConfirmed(false);
    } finally { setBusy(null); }
  }

  const keys = plan?.changes.reduce((n, c) => n + c.keys.length, 0) ?? 0;
  const checkFor = (path: string, dir: string) => checked?.changes.find((c) => c.path === path && c.direction === dir);
  const resultFor = (path: string, dir: string) => applied?.results.find((r) => r.path === path && r.direction === dir);
  const targets = plan ? [...new Set(plan.changes.map((c) => vaultLabel(c.direction === "left_to_right" ? plan.right : plan.left)))] : [];

  return (
    <section className="card plans">
      <div className="expiry-head">
        <div>
          <h2>Sync plans</h2>
          <p className="subtle">
            A plan is a reviewed set of copies saved as a file (<strong>Save as plan</strong> in the review dialog), so
            someone with write access can apply it later. It holds paths, keys and versions, never values. If anything
            in it has changed since it was made, it can't be applied and has to be made again.
          </p>
        </div>
        <div className="plans-open">
          <input ref={fileRef} type="file" accept=".json,application/json" hidden aria-label="Plan file"
                 onChange={(e) => { const f = e.target.files?.[0]; if (f) open(f); e.target.value = ""; }} />
          <button type="button" className="btn primary" onClick={() => fileRef.current?.click()}>Open a plan file…</button>
        </div>
      </div>

      {error && <div className="notice error" role="alert">{error}</div>}

      {plan && (
        <>
          <div className="plan-meta">
            <div><span className="subtle">File</span> <span className="mono">{fileName}</span></div>
            <div><span className="subtle">Created</span> {absoluteTime(plan.created_at)}</div>
            <div><span className="subtle">Plan ID</span> <span className="mono">{plan.id}</span></div>
            {plan.profile && <div><span className="subtle">Profile</span> {plan.profile}</div>}
            <div><span className="subtle">Changes</span> {keys} key{keys === 1 ? "" : "s"} in {plan.changes.length} secret{plan.changes.length === 1 ? "" : "s"}</div>
            <span className="spacer" />
            <button type="button" className="btn ghost small" onClick={() => downloadReport(plan).catch((e) => setError(e.message))}>
              Download report
            </button>
          </div>
          {plan.note && <blockquote className="plan-note">{plan.note}</blockquote>}

          <div className="plan-sides">
            {(["left", "right"] as const).map((s) => {
              const v = plan[s];
              const conn = s === "left" ? left : right;
              const ok = looksLike(conn, v);
              return (
                <div key={s} className={`plan-side ${s}`}>
                  <div className="side-label">{s === "left" ? "Left" : "Right"}</div>
                  <div><strong>{vaultLabel(v)}</strong> · <span className="mono">{v.mount}/{v.prefix}</span></div>
                  <div className="subtle">Planned by {v.identity || "unknown"}</div>
                  <div className={ok ? "subtle" : "notice warn"}>
                    {conn ? <>Connected as {conn.display_name || conn.auth_method} to {conn.name}{!ok && <>: connect this side to <strong>{vaultLabel(v)}</strong></>}</>
                      : <>Connect this side (above) to <strong>{vaultLabel(v)}</strong></>}
                  </div>
                </div>
              );
            })}
          </div>

          <table className="expiry-table plan-table">
            <thead><tr><th>From</th><th>To</th><th>Keys</th><th>Status</th></tr></thead>
            <tbody>
              {plan.changes.map((c) => {
                const [src, tgt] = c.direction === "left_to_right" ? [plan.left, plan.right] : [plan.right, plan.left];
                const ck = checkFor(c.path, c.direction);
                const res = resultFor(c.path, c.direction);
                return (
                  <tr key={`${c.direction}${c.path}`}>
                    <td><span className="subtle">{src.vault}</span><br /><span className="mono">{src.mount}/{c.source_path}</span> <span className="subtle">v{c.source_version}</span></td>
                    <td><span className="subtle">{tgt.vault}</span><br /><span className="mono">{tgt.mount}/{c.target_path}</span>{" "}
                      <span className="subtle">{c.target_version ? `v${c.target_version}` : "new"}</span></td>
                    <td>{c.keys.map((k) => <div key={k.key}><span className="mono">{k.key}</span> <span className={`action ${k.action}`}>{k.action}</span></div>)}</td>
                    <td>
                      {res ? <span className={`badge ${res.status === "applied" ? "equal" : "error"}`}>
                               {res.status === "applied" ? `Written v${res.new_version}` : res.status}</span>
                        : ck ? <span className={`badge ${CHECK_LABEL[ck.status][1]}`}>{CHECK_LABEL[ck.status][0]}</span>
                        : <span className="subtle">Not checked</span>}
                      {(res?.message ? [res.message] : ck?.problems ?? []).map((m) => <div key={m} className="subtle small">{m}</div>)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {checked && !applied && (
            <div className={`notice ${checked.status === "ready" ? "info" : checked.status === "stale" ? "warn" : "error"}`} role="status">
              {checked.status === "stale" && <strong>This plan can't be applied. </strong>}
              {checked.message}
            </div>
          )}
          {applied && (
            <div className={`notice ${applied.summary.applied === applied.results.length ? "info" : "error"}`} role="status">
              Plan applied: {applied.summary.applied} of {applied.results.length} secret(s) written
              {applied.summary.applied < applied.results.length && ". Some secrets changed while the plan was being applied; see the table"}.
            </div>
          )}

          {!applied && (
            <div className="review-foot plan-actions">
              {checked?.status === "ready" && (
                <label className="confirm">
                  <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
                  Write {plan.changes.length} secret{plan.changes.length === 1 ? "" : "s"} to <strong>{targets.join(", ")}</strong>
                </label>
              )}
              <span className="spacer" />
              <button type="button" className="btn ghost" disabled={!left || !right || busy !== null} onClick={check}>
                {busy === "check" && <span className="spinner" />} {checked ? "Check again" : "Check plan"}
              </button>
              <button type="button" className="btn primary" disabled={checked?.status !== "ready" || !confirmed || busy !== null} onClick={apply}>
                {busy === "apply" && <span className="spinner" />} Apply plan
              </button>
            </div>
          )}
        </>
      )}
    </section>
  );
}
