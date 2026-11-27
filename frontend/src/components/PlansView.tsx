import { useRef, useState } from "react";
import { api } from "../api";
import { approvalsNeeded, downloadReport, downloadUndoPlan, planFileName, saveFile, vaultLabel } from "../plans";
import { absoluteTime } from "../time";
import type { Connection, PlanApplyResult, PlanCheck, PlanCheckStatus, SyncPlan, UndoApplyResult, UndoCheck, UndoPlan } from "../types";

interface Props {
  connections: Connection[];
  leftConnId: string | null;
  rightConnId: string | null;
  readOnly?: boolean;
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

const UNDO_LABEL = { restore: "Put back", delete: "Delete (it was new)", undelete: "Undelete" } as const;

/** An undo plan: put back what an apply changed. Checked and applied by the server. */
function UndoPanel({ plan: opened, connIds, readOnly }: { plan: UndoPlan; connIds: string[]; readOnly?: boolean }) {
  const [plan, setPlan] = useState(opened);  // with any approval added here
  const [checked, setChecked] = useState<UndoCheck | null>(null);
  const [applied, setApplied] = useState<UndoApplyResult | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async (what: "check" | "apply") => {
    setBusy(true);
    setError(null);
    try {
      if (what === "check") { setChecked(await api.undoCheck(plan, connIds)); setConfirmed(false); }
      else setApplied(await api.undoApply(plan, connIds));
    } catch (e) { setError((e as Error).message); setChecked(null); } finally { setBusy(false); }
  };
  const approve = async () => {
    setBusy(true);
    setError(null);
    try {
      const approved = await api.undoApprove(plan, connIds);
      setPlan(approved);
      saveFile(JSON.stringify(approved, null, 2) + "\n", `lockstep-undo-plan-${approved.id.slice(0, 8)}-approved.json`, "application/json");
      setChecked(await api.undoCheck(approved, connIds));
    } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  };
  const ap = checked?.approvals;
  const unapproved = Boolean(ap && ap.approved_by.length < ap.required);
  const rows = applied?.entries ?? checked?.entries;
  return (
    <>
      <div className="notice info">
        An undo plan puts back what an apply wrote{plan.undoes ? <> (plan <span className="mono">{plan.undoes.slice(0, 8)}</span>)</> : null}: each
        secret's old version is read from Vault's history and written again. It works only while nobody has written these secrets
        since. Made {absoluteTime(plan.created_at)} by {plan.created_by || "unknown"}.
      </div>
      {error && <div className="notice error" role="alert">{error}</div>}
      <table className="expiry-table plan-table">
        <thead><tr><th>Secret</th><th>Undo</th><th>Status</th></tr></thead>
        <tbody>
          {plan.entries.map((e, i) => {
            const r = rows?.[i];
            return (
              <tr key={`${e.vault.vault}${e.vault.mount}${e.path}`}>
                <td><span className="subtle">{vaultLabel(e.vault)}</span><br /><span className="mono">{e.vault.mount}/{e.path}</span></td>
                <td>{UNDO_LABEL[e.action]}{e.restore_version ? ` v${e.restore_version}` : ""} <span className="subtle">(now v{e.current_version})</span></td>
                <td>{r ? <span className={`badge ${r.status === "ready" || r.status === "applied" ? "equal" : r.status === "skipped" ? "" : "error"}`}>
                    {r.status === "applied" ? `Done${r.new_version ? `: v${r.new_version}` : ""}` : r.status === "ready" ? "Can be undone" : r.status}</span>
                  : <span className="subtle">Not checked</span>}
                  {r?.message && <div className="subtle small">{r.message}</div>}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {(applied ?? checked) && (
        <div className={`notice ${(applied?.outcome ?? checked?.status) === "applied" || checked?.status === "ready" ? "info" : "error"}`} role="status">
          {(applied ?? checked)!.message}
        </div>
      )}
      {ap && !applied && (ap.required > 0 || ap.approved_by.length > 0) && (
        <div className={`notice ${unapproved ? "warn" : "info"} plan-approvals`} role="status">
          {ap.approved_by.length > 0 ? <>Approved by {ap.approved_by.join(", ")}. </> : <>Not approved yet. </>}
          {approvalsNeeded(ap)}
          {ap.problems.join(" ")}
        </div>
      )}
      {!applied && (
        <div className="review-foot plan-actions">
          {checked?.status === "ready" && !readOnly && (
            <label className="confirm">
              <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
              Put back {plan.entries.length} secret{plan.entries.length === 1 ? "" : "s"}
            </label>
          )}
          <span className="spacer" />
          {checked && (checked.status === "ready" || checked.status === "denied") && (ap?.required ?? 0) > 0 && (
            <button type="button" className="btn ghost" disabled={busy} onClick={approve}
                    title="Add your approval to the undo plan and download it: four-eyes, before someone applies it">Approve</button>
          )}
          <button type="button" className="btn ghost" disabled={busy || connIds.length === 0} onClick={() => run("check")}>
            {busy && !checked && <span className="spinner" />} {checked ? "Check again" : "Check undo plan"}
          </button>
          {!readOnly && <button type="button" className="btn primary" disabled={checked?.status !== "ready" || !confirmed || busy || unapproved} onClick={() => run("apply")}>
            Apply undo plan</button>}
        </div>
      )}
    </>
  );
}

export function PlansView({ connections, leftConnId, rightConnId, readOnly }: Props) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [undo, setUndo] = useState<UndoPlan | null>(null);
  const [undoFile, setUndoFile] = useState<string | null>(null);
  const [plan, setPlan] = useState<SyncPlan | null>(null);
  const [fileName, setFileName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [checked, setChecked] = useState<PlanCheck | null>(null);
  const [busy, setBusy] = useState<"check" | "apply" | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [applied, setApplied] = useState<PlanApplyResult | null>(null);
  // Values the plan's creator typed, entered again here (they aren't in the file)
  const [values, setValues] = useState<Record<string, Record<string, string>>>({});
  // A plan from another installation: typed values can't be checked against the creator's here,
  // so they're typed twice instead
  const [local, setLocal] = useState(true);
  const [again, setAgain] = useState<Record<string, string>>({});
  const typed = plan ? plan.changes.flatMap((c, i) => Object.keys(c.typed ?? {}).map((key) => ({ i, key, path: c.target_path }))) : [];
  const allTyped = typed.every((t) => (values[String(t.i)]?.[t.key] ?? "") !== ""
    && (local || again[`${t.i}:${t.key}`] === values[String(t.i)]?.[t.key]));
  const setValue = (i: number, key: string, v: string) => {
    setValues((prev) => ({ ...prev, [String(i)]: { ...prev[String(i)], [key]: v } }));
    setChecked(null);
    setConfirmed(false);
  };

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
    setUndo(null);
    setUndoFile(null);
    setValues({});
    setFileName(file.name);
    try {
      let raw: unknown;
      try { raw = JSON.parse(await file.text()); } catch { throw new Error("This file isn't valid JSON, so it can't be a Lockstep plan."); }
      if ((raw as { format?: string })?.format === "lockstep.undo-plan") { setUndo(raw as UndoPlan); return; }
      const v = await api.planVerify(raw);
      setPlan(v.plan);
      setLocal(v.local);
      setAgain({});
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function check() {
    if (!plan || !leftConnId || !rightConnId) return;
    reset();
    setBusy("check");
    try { setChecked(await api.planCheck(plan, leftConnId, rightConnId, values)); }
    catch (e) { setError((e as Error).message); }
    finally { setBusy(null); }
  }

  async function approve() {
    if (!plan || !leftConnId || !rightConnId) return;
    setBusy("check");
    setError(null);
    try {
      const approved = (await api.planApprove(plan, leftConnId, rightConnId, values)).plan;
      setPlan(approved);
      saveFile(JSON.stringify(approved, null, 2) + "\n", planFileName(approved, "json").replace(".json", "-approved.json"), "application/json");
      setChecked(await api.planCheck(approved, leftConnId, rightConnId, values));
    } catch (e) { setError((e as Error).message); } finally { setBusy(null); }
  }

  async function apply() {
    if (!plan || !leftConnId || !rightConnId) return;
    setBusy("apply");
    setError(null);
    try { setApplied(await api.planApply(plan, leftConnId, rightConnId, values)); }
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
            someone with write access can apply it later. It holds paths, keys and versions. Copied values aren't in it:
            they're read from the source when it's applied. Values its creator typed aren't in it either: you type them again here.
            If anything in it has changed since it was made, it can't be applied and has to be made again.
          </p>
        </div>
        <div className="plans-open">
          <input ref={fileRef} type="file" accept=".json,application/json" hidden aria-label="Plan file"
                 onChange={(e) => { const f = e.target.files?.[0]; if (f) open(f); e.target.value = ""; }} />
          <button type="button" className="btn primary" onClick={() => fileRef.current?.click()}>Open a plan file…</button>
        </div>
      </div>

      {error && <div className="notice error" role="alert">{error}</div>}

      {undo && <UndoPanel plan={undo} connIds={[leftConnId, rightConnId].filter((x): x is string => Boolean(x))} readOnly={readOnly} />}

      {plan && (
        <>
          <div className="plan-meta">
            <div><span className="subtle">File</span> <span className="mono">{fileName}</span></div>
            <div><span className="subtle">Created</span> {absoluteTime(plan.created_at)}</div>
            <div><span className="subtle">Plan ID</span> <span className="mono">{plan.id}</span></div>
            {plan.profile && <div><span className="subtle">Profile</span> {plan.profile}</div>}
            {plan.issuer && <div><span className="subtle">Made on</span> {plan.issuer.name}{plan.issuer.key_id && <span className="subtle mono"> · key {plan.issuer.key_id}</span>}</div>}
            {plan.expires_at && <div><span className="subtle">Valid until</span> {absoluteTime(plan.expires_at)}</div>}
            {plan.approvals && plan.approvals.length > 0 && <div><span className="subtle">Approved by</span> {plan.approvals.map((a) => a.by).join(", ")}</div>}
            {plan.audience && plan.audience.length > 0 && <div><span className="subtle">For</span> {plan.audience.join(", ")}</div>}
            <div><span className="subtle">Changes</span> {keys} key{keys === 1 ? "" : "s"} in {plan.changes.length} secret{plan.changes.length === 1 ? "" : "s"}</div>
            <span className="spacer" />
            <button type="button" className="btn ghost small" onClick={() => downloadReport(plan).catch((e) => setError(e.message))}>
              Download report
            </button>
          </div>
          {plan.note && <blockquote className="plan-note">{plan.note}</blockquote>}
          {plan.holds_values && (
            <div className="notice warn">
              This plan holds values its creator typed (keys marked <em>typed</em>). They're written as they are, and anyone
              with the file can read them.
            </div>
          )}

          {typed.length > 0 && !applied && (
            <fieldset className="plan-typed card">
              <legend>Values typed by hand</legend>
              <p className="subtle">
                The plan's creator set these keys to values they typed. Those values aren't in the file: type them again.
                {local ? " Lockstep checks each one matches what the creator typed before anything is written."
                  : " This plan was made on another Lockstep server, so they can't be checked against the creator's here: type each one twice."}
              </p>
              {typed.map((t) => (
                <label key={`${t.i}:${t.key}`} className="field">
                  <span className="mono">{t.path} · {t.key}</span>
                  <input type="password" autoComplete="off" spellCheck={false} aria-label={`Value for ${t.path} ${t.key}`}
                         value={values[String(t.i)]?.[t.key] ?? ""} onChange={(e) => setValue(t.i, t.key, e.target.value)} />
                  {!local && (
                    <input type="password" autoComplete="off" spellCheck={false} aria-label={`Value for ${t.path} ${t.key} again`}
                           placeholder="Again" value={again[`${t.i}:${t.key}`] ?? ""}
                           onChange={(e) => setAgain((a) => ({ ...a, [`${t.i}:${t.key}`]: e.target.value }))} />
                  )}
                </label>
              ))}
            </fieldset>
          )}

          <div className="plan-sides">
            {(["left", "right"] as const).map((s) => {
              const v = plan[s];
              const conn = s === "left" ? left : right;
              const ok = looksLike(conn, v);
              return (
                <div key={s} className={`plan-side ${s}`}>
                  <div className="side-label">{s === "left" ? "Left" : "Right"}</div>
                  <div><strong>{vaultLabel(v)}</strong> · <span className="mono">{v.mount}/{v.prefix}</span></div>
                  <div className="subtle" title={v.entity_id ? `Vault entity ${v.entity_id}, token accessor ${v.accessor}` : undefined}>
                    Planned by {v.identity || "unknown"}{v.entity_id && <span className="mono"> · entity {v.entity_id.slice(0, 8)}</span>}
                  </div>
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
                    <td>{c.keys.some((k) => !k.override && k.action !== "remove")
                      ? <><span className="subtle">{src.vault}</span><br /><span className="mono">{src.mount}/{c.source_path}</span> <span className="subtle">v{c.source_version}</span></>
                      : <span className="subtle">{c.keys.every((k) => k.action === "remove") ? "Removing keys" : "Typed values"}</span>}</td>
                    <td><span className="subtle">{tgt.vault}</span><br /><span className="mono">{tgt.mount}/{c.target_path}</span>{" "}
                      <span className="subtle">{c.target_version ? `v${c.target_version}` : "new"}</span></td>
                    <td>{c.keys.map((k) => <div key={k.key}><span className="mono">{k.key}</span> <span className={`action ${k.action}`}>{k.action}</span>{k.override && <span className="type-tag">typed</span>}</div>)}</td>
                    <td>
                      {res ? <span className={`badge ${res.status === "applied" ? "equal" : res.status === "skipped" ? "" : "error"}`}
                                   title={res.message || undefined}>
                               {res.status === "applied" ? `Written v${res.new_version}` : res.status === "skipped" ? "not attempted" : res.status}</span>
                        : ck ? <span className={`badge ${CHECK_LABEL[ck.status][1]}`}>{CHECK_LABEL[ck.status][0]}</span>
                        : <span className="subtle">Not checked</span>}
                      {(res?.message ? [res.message] : ck?.problems ?? []).map((m) => <div key={m} className="subtle small">{m}</div>)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {checked?.approvals && !applied && (checked.approvals.required > 0 || checked.approvals.approved_by.length > 0) && (
            <div className={`notice ${checked.approvals.approved_by.length >= checked.approvals.required ? "info" : "warn"} plan-approvals`} role="status">
              {checked.approvals.approved_by.length > 0
                ? <>Approved by {checked.approvals.approved_by.join(", ")}. </>
                : <>Not approved yet. </>}
              {approvalsNeeded(checked.approvals)}
              {checked.approvals.problems.join(" ")}
            </div>
          )}
          {checked && !applied && (
            <div className={`notice ${checked.status === "ready" ? "info" : checked.status === "stale" ? "warn" : "error"}`} role="status">
              {checked.status === "stale" && <strong>This plan can't be applied. </strong>}
              {checked.message}
            </div>
          )}
          {applied && (
            <div className={`notice ${applied.outcome === "applied" ? "info" : "error"}`} role="status">
              {applied.outcome !== "applied" && <strong>{applied.outcome === "partially_applied" ? "Partially applied. " : "Not applied. "}</strong>}
              {applied.message}
              {applied.summary.applied > 0 && (
                <div>
                  <button type="button" className="btn ghost small" disabled={Boolean(undoFile)} onClick={async () => {
                    try { setUndoFile(await downloadUndoPlan(applied.results, plan.id)); } catch (e) { setError((e as Error).message); }
                  }}>{undoFile ? `Undo plan saved as ${undoFile}` : "Make an undo plan"}</button>
                </div>
              )}
            </div>
          )}

          {!applied && (
            <div className="review-foot plan-actions">
              {readOnly && <span className="subtle">This Lockstep server is read-only: plans can be checked here, not applied.</span>}
              {checked?.status === "ready" && !readOnly && (
                <label className="confirm">
                  <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
                  Write {plan.changes.length} secret{plan.changes.length === 1 ? "" : "s"} to <strong>{targets.join(", ")}</strong>
                </label>
              )}
              <span className="spacer" />
              {checked && (checked.status === "ready" || checked.status === "denied") && (
                <button type="button" className="btn ghost" disabled={busy !== null} onClick={approve}
                        title="Add your approval to the plan and download it: four-eyes, before someone applies it">
                  Approve
                </button>
              )}
              <button type="button" className="btn ghost" disabled={!left || !right || busy !== null} onClick={check}>
                {busy === "check" && <span className="spinner" />} {checked ? "Check again" : "Check plan"}
              </button>
              {!readOnly && (
                <button type="button" className="btn primary" disabled={checked?.status !== "ready" || !confirmed || !allTyped || busy !== null
                          || Boolean(checked?.approvals && checked.approvals.approved_by.length < checked.approvals.required)} onClick={apply}
                        title={!allTyped ? "Type the values the plan's creator typed first" : undefined}>
                  {busy === "apply" && <span className="spinner" />} Apply plan
                </button>
              )}
            </div>
          )}
        </>
      )}
    </section>
  );
}
