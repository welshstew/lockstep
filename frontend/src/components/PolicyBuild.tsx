import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import type { ExplainResult, PolicyCan, PolicyDraft, PolicyFinding, PolicyProfile, SuggestResult, TerraformOptions } from "../types";
import type { ScanTarget } from "./ExpiryView";
import { AccessApply } from "./AccessApply";
import { saveAccessPlan } from "../accessPlan";
import { ExplainResultView } from "./PoliciesView";

const DRAFTS_KEY = "lockstep.policyDrafts";
const PATTERN_KEY = "lockstep.suggestPattern";
const PROFILES_KEY = "lockstep.policyProfiles"; // shared with Compare across Vaults
const CANS: { id: PolicyCan; label: string; help: string }[] = [
  { id: "names", label: "See names", help: "list on <mount>/metadata/…: the secret shows when its folder is listed" },
  { id: "read", label: "Read", help: "read on <mount>/data/…" },
  { id: "write", label: "Write", help: "create, update and patch on <mount>/data/…" },
  { id: "delete", label: "Delete", help: "soft delete and undelete: delete on data/, update on delete/ and undelete/" },
  { id: "destroy", label: "Destroy", help: "update on destroy/ and delete on metadata/: no undo" },
  { id: "history", label: "History", help: "read on <mount>/metadata/…: versions and dates" },
];
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function load<T>(key: string, fallback: T): T {
  try { const v = localStorage.getItem(key); return v === null ? fallback : JSON.parse(v); } catch { return fallback; }
}
function save(key: string, v: unknown) {
  try { localStorage.setItem(key, JSON.stringify(v)); } catch { /* ignore */ }
}

function download(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Build policies from plain rules, get suggestions from the layout, and export them for an admin. */
export function PolicyBuild({ targets, canApply = false }: { targets: ScanTarget[]; canApply?: boolean }) {
  const [sideId, setSideId] = useState<"left" | "right">(targets[0]?.side ?? "left");
  const target = targets.find((t) => t.side === sideId) ?? targets[0];
  const [drafts, setDraftsState] = useState<PolicyDraft[]>(() => load(DRAFTS_KEY, []));
  const [current, setCurrent] = useState<number>(0);
  const [hcl, setHcl] = useState<string>("");
  const [findings, setFindings] = useState<PolicyFinding[]>([]);
  const [buildError, setBuildError] = useState<string | null>(null);
  const [preview, setPreview] = useState<ExplainResult | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [suggesting, setSuggesting] = useState(false);
  const [suggest, setSuggest] = useState<SuggestResult | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [pattern, setPattern] = useState<string>(() => load(PATTERN_KEY, ""));
  const [showPattern, setShowPattern] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [shared, setShared] = useState<{ name: string; yaml: string }[]>([]);
  useEffect(() => { api.policyPatterns().then(setShared).catch(() => setShared([])); }, []);

  const setDrafts = (d: PolicyDraft[]) => { setDraftsState(d); save(DRAFTS_KEY, d); };
  const draft = drafts[current] ?? null;
  const update = (d: PolicyDraft) => setDrafts(drafts.map((x, i) => (i === current ? d : x)));

  // The draft's HCL: built on the server from its rules (debounced), or its own text in Advanced mode
  useEffect(() => {
    setPreview(null);
    if (!draft) { setHcl(""); setFindings([]); return; }
    if (draft.hcl !== undefined) { setHcl(draft.hcl); setFindings([]); setBuildError(null); return; }
    const rules = draft.rules.filter((r) => r.where.trim() && r.can.length);
    if (!rules.length) { setHcl(""); setFindings([]); setBuildError(null); return; }
    const t = setTimeout(() => {
      api.buildPolicy(draft.mount, draft.name, rules)
        .then((r) => { setHcl(r.hcl); setFindings(r.findings); setBuildError(null); })
        .catch((e) => { setBuildError((e as Error).message); setHcl(""); });
    }, 250);
    return () => clearTimeout(t);
  }, [JSON.stringify(draft)]); // eslint-disable-line react-hooks/exhaustive-deps

  const newDraft = () => {
    const d: PolicyDraft = { name: `new-policy-${drafts.length + 1}`, mount: target?.mount ?? "secret", rules: [{ where: "", can: ["names", "read"] }] };
    setDrafts([...drafts, d]);
    setCurrent(drafts.length);
  };

  async function runPreview() {
    if (!target || !hcl) return;
    setPreviewing(true);
    setError(null);
    try {
      setPreview(await api.explainPolicies({ conn_id: target.conn_id, mount: draft!.mount, prefix: target.mount === draft!.mount ? target.prefix : "",
                                             pasted: [{ name: draft!.name || "draft", text: hcl }] }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setPreviewing(false);
    }
  }

  async function runSuggest(withPattern: boolean) {
    if (!target) return;
    setSuggesting(true);
    setError(null);
    try {
      const r = await api.suggestPolicies(target.conn_id, target.mount, target.prefix, withPattern && pattern.trim() ? pattern : null);
      setSuggest(r);
      setPicked(new Set(r.suggestions.map((s) => s.name)));
      if (!withPattern || !pattern.trim()) setPattern(r.pattern_yaml);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSuggesting(false);
    }
  }

  const useSuggestions = () => {
    if (!suggest || !target) return;
    const chosen = suggest.suggestions.filter((s) => picked.has(s.name));
    const names = new Set(chosen.map((s) => s.name));
    const next = [...drafts.filter((d) => !names.has(d.name)),
      ...chosen.map((s): PolicyDraft => ({ name: s.name, mount: target.mount, rules: s.rules, description: s.description }))];
    setDrafts(next);
    setCurrent(next.findIndex((d) => d.name === chosen[0]?.name));
    setSuggest(null);
  };

  const saveProfile = (p: PolicyProfile) => {
    const mine = load<PolicyProfile[]>(PROFILES_KEY, []);
    save(PROFILES_KEY, [...mine.filter((x) => x.name !== p.name), p]);
    setError(null);
    alertOk(`Saved the policy profile “${p.name}”: pick it in Compare across Vaults.`);
  };
  const [ok, alertOk] = useState<string | null>(null);

  if (!targets.length) return <div className="notice info">Choose a connection and a KV v2 mount on a side: suggestions and previews use it.</div>;

  return (
    <div className="policy-build">
      <div className="card policies-head">
        <div className="subtle">
          Write policies as “who can do what, where”. Lockstep turns each rule into the right KV v2 paths (values under <code>data/</code>,
          listing and history under <code>metadata/</code>, …), shows what the policy allows on real secrets, and exports them for an
          admin: HCL files with an <code>apply.sh</code>, and Terraform or OpenTofu if you like. Nothing is written to Vault from here.
        </div>
        <div className="field-row">
          {targets.length > 1 && (
            <div className="segmented small" role="group" aria-label="Which side">
              {targets.map((t) => (
                <button key={t.side} type="button" aria-pressed={t.side === target.side} onClick={() => setSideId(t.side)}>
                  <span className={`side-dot ${t.side}`} /> {t.label}
                </button>
              ))}
            </div>
          )}
          <button type="button" className="btn" onClick={() => runSuggest(false)} disabled={suggesting}>
            {suggesting && <span className="spinner" />} Suggest policies for {target.mount}{target.prefix ? `/${target.prefix.replace(/^\/+|\/+$/g, "")}` : ""}
          </button>
          <button type="button" className="btn ghost small" aria-expanded={showPattern} onClick={() => setShowPattern(!showPattern)}>
            {showPattern ? "Hide pattern" : "Use my pattern…"}
          </button>
          <span className="spacer" />
          <button type="button" className="btn" onClick={newDraft}>＋ New policy</button>
          {canApply && <button type="button" className="btn ghost small danger" onClick={() => setDeleting(true)}>Delete a policy…</button>}
          <button type="button" className="btn primary" disabled={!drafts.length} onClick={() => setExporting(true)}>
            {canApply ? "Write or download…" : "Download for an admin…"}</button>
        </div>
        {showPattern && (
          <div className="pattern-box">
            <label className="field"><span>Suggestion pattern (YAML or JSON): what each level means, and the policies to make. <span className="subtle">Suggest once to start from the detected one.</span></span>
              <textarea className="mono" rows={10} spellCheck={false} aria-label="Suggestion pattern" value={pattern}
                        placeholder={"layout: \"{app}/{env}/**\"\npolicies:\n  - name: \"{app}-{env}-app\"\n    rules: [{where: \"{app}/{env}/**\", can: [read]}]\ncompare: {pair: {env: [dev, prod]}}"}
                        onChange={(e) => { setPattern(e.target.value); save(PATTERN_KEY, e.target.value); }} /></label>
            <div className="field-row">
              {shared.length > 0 && (
                <select aria-label="Shared patterns" value="" onChange={(e) => {
                  const p = shared.find((x) => x.name === e.target.value);
                  if (p) { setPattern(p.yaml); save(PATTERN_KEY, p.yaml); }
                }}>
                  <option value="">Load a shared pattern…</option>
                  {shared.map((p) => <option key={p.name} value={p.name}>{p.name}</option>)}
                </select>
              )}
              <button type="button" className="btn small" disabled={!pattern.trim() || suggesting} onClick={() => runSuggest(true)}>Suggest with this pattern</button>
              <span className="subtle">The format: <code>lockstep schema suggest-pattern</code>.</span>
            </div>
          </div>
        )}
      </div>

      {error && <div className="notice error" role="alert">{error}</div>}
      {ok && <div className="notice info" role="status">{ok} <button type="button" className="btn ghost small" onClick={() => alertOk(null)}>✕</button></div>}

      {suggest && (
        <div className="card suggest-box">
          <div className="suggest-head">
            <div><strong>Layout</strong> <code>{suggest.layout}</code> <span className="subtle">({suggest.secrets} secrets{suggest.truncated ? ", listing cut short" : ""})</span></div>
            <button type="button" className="btn ghost icon small" aria-label="Close suggestions" onClick={() => setSuggest(null)}>✕</button>
          </div>
          <ul className="subtle why-list">{[...suggest.why, ...suggest.notes].map((w) => <li key={w}>{w}</li>)}</ul>
          <div className="suggest-list" role="group" aria-label="Suggested policies">
            {suggest.suggestions.map((s) => (
              <label key={s.name} className="suggest-item">
                <input type="checkbox" checked={picked.has(s.name)} onChange={() => setPicked((p) => { const n = new Set(p); if (n.has(s.name)) n.delete(s.name); else n.add(s.name); return n; })} />
                <span className="mono">{s.name}</span> <span className="subtle">{s.description}</span>
                <span className="subtle rules-sum">{s.rules.map((r) => `${r.where}: ${r.can.join(", ")}`).join(" · ")}</span>
              </label>
            ))}
          </div>
          <div className="field-row">
            <button type="button" className="btn ghost small" onClick={() => setPicked(new Set(suggest.suggestions.map((s) => s.name)))}>All</button>
            <button type="button" className="btn ghost small" onClick={() => setPicked(new Set())}>None</button>
            {suggest.profile && (
              <button type="button" className="btn ghost small" onClick={() => saveProfile(suggest.profile!)}
                      title={suggest.profile.mappings.map((m) => `${m.left} ⇄ ${m.right}`).join(", ")}>Save policy profile “{suggest.profile.name}”</button>
            )}
            <span className="spacer" />
            <button type="button" className="btn primary small" disabled={!picked.size} onClick={useSuggestions}>Add {picked.size} to my policies</button>
          </div>
        </div>
      )}

      <div className="build-layout">
        <nav className="card build-drafts" aria-label="My policies">
          <div className="tree-head">My policies <span className="subtle">(kept in this browser)</span></div>
          {drafts.map((d, i) => (
            <button key={i} type="button" className="tree-row secret" aria-current={i === current} onClick={() => setCurrent(i)}>
              <span className="mono">{d.name || "(unnamed)"}</span>
            </button>
          ))}
          {!drafts.length && <div className="tree-note subtle">None yet: start one with ＋ New policy, or from suggestions.</div>}
        </nav>

        {draft ? (
          <div className="card build-editor">
            <div className="field-row">
              <label className="field inline"><span>Name</span>
                <input type="text" className="mono" value={draft.name} aria-label="Policy name" aria-invalid={!NAME.test(draft.name)}
                       onChange={(e) => update({ ...draft, name: e.target.value })} /></label>
              <label className="field inline"><span>Mount</span>
                <input type="text" className="mono" value={draft.mount} aria-label="Mount" onChange={(e) => update({ ...draft, mount: e.target.value.replace(/^\/+|\/+$/g, "") })} /></label>
              <span className="spacer" />
              <label className="inline-check" title="Edit the HCL directly instead of the rules">
                <input type="checkbox" checked={draft.hcl !== undefined}
                       onChange={(e) => update(e.target.checked ? { ...draft, hcl: hcl || "" } : { ...draft, hcl: undefined })} /> Advanced (HCL)
              </label>
              <button type="button" className="btn ghost small danger" onClick={() => { setDrafts(drafts.filter((_, i) => i !== current)); setCurrent(Math.max(0, current - 1)); }}>Delete</button>
            </div>
            {!NAME.test(draft.name) && <div className="notice warn">A policy name is letters, digits, “.”, “_” and “-”.</div>}
            {draft.description && <div className="subtle">{draft.description}</div>}

            {draft.hcl === undefined ? (
              <table className="build-rules">
                <thead>
                  <tr><th>Where <span className="subtle">(folder/**, a secret, * = one level)</span></th>
                    {CANS.map((c) => <th key={c.id} title={c.help}>{c.label}</th>)}<th /></tr>
                </thead>
                <tbody>
                  {draft.rules.map((r, i) => (
                    <tr key={i}>
                      <td><input type="text" className="mono" value={r.where} placeholder="payments/dev/**" aria-label={`Rule ${i + 1} where`}
                                 onChange={(e) => update({ ...draft, rules: draft.rules.map((x, j) => (j === i ? { ...x, where: e.target.value } : x)) })} /></td>
                      {CANS.map((c) => (
                        <td key={c.id} className="pcell">
                          <input type="checkbox" aria-label={`Rule ${i + 1} ${c.label}`} checked={r.can.includes(c.id)}
                                 onChange={(e) => update({ ...draft, rules: draft.rules.map((x, j) => (j === i
                                   ? { ...x, can: e.target.checked ? CANS.map((k) => k.id).filter((k) => k === c.id || x.can.includes(k)) : x.can.filter((k) => k !== c.id) } : x)) })} />
                        </td>
                      ))}
                      <td><button type="button" className="btn ghost icon small" aria-label={`Remove rule ${i + 1}`}
                                  onClick={() => update({ ...draft, rules: draft.rules.filter((_, j) => j !== i) })}>×</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <textarea className="mono hcl-edit" rows={14} spellCheck={false} aria-label="Policy HCL" value={draft.hcl}
                        onChange={(e) => update({ ...draft, hcl: e.target.value })} />
            )}
            {draft.hcl === undefined && (
              <div className="field-row">
                <button type="button" className="btn small" onClick={() => update({ ...draft, rules: [...draft.rules, { where: "", can: ["names", "read"] }] })}>＋ Add rule</button>
                <span className="subtle">“See names” on a folder doesn’t let anyone list the folders above it: add those if people browse from the top.</span>
              </div>
            )}
            {buildError && <div className="notice error">{buildError}</div>}
            {findings.length > 0 && (
              <ul className="build-findings">
                {findings.map((f, i) => <li key={i} className={`finding ${f.level}`}><span className={`badge ${f.level === "error" ? "error" : f.level === "warn" ? "different" : "unknown"}`}>{f.level}</span> {f.path && <span className="mono">{f.path}</span>} {f.message}</li>)}
              </ul>
            )}
            {draft.hcl === undefined && hcl && <pre className="mono hcl-preview" aria-label="Generated HCL">{hcl}</pre>}
            <div className="field-row">
              <button type="button" className="btn" onClick={runPreview} disabled={!hcl || previewing}>
                {previewing && <span className="spinner" />} Preview on {target.label}
              </button>
              <button type="button" className="btn ghost small" disabled={!hcl} onClick={() => navigator.clipboard?.writeText(hcl)}>Copy HCL</button>
              <button type="button" className="btn ghost small" disabled={!hcl || !NAME.test(draft.name)}
                      onClick={() => download(new Blob([hcl], { type: "text/plain" }), `${draft.name}.hcl`)}>Download .hcl</button>
            </div>
          </div>
        ) : <div className="card empty">Choose a policy on the left, or start one.</div>}
      </div>

      {preview && <ExplainResultView key={JSON.stringify(preview.policies)} result={preview} />}

      {exporting && <ExportDialog drafts={drafts} target={target} canApply={canApply} onClose={() => setExporting(false)} />}
      {deleting && <DeletePolicy target={target} onClose={() => setDeleting(false)} />}
    </div>
  );
}

function DeletePolicy({ target, onClose }: { target: ScanTarget; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const [name, setName] = useState("");
  const [users, setUsers] = useState<{ mount: string; role: string }[] | null>(null);
  const [go, setGo] = useState(false);
  useEffect(() => { ref.current?.showModal(); }, []);
  if (go) return <AccessApply changes={{ conn_id: target.conn_id, delete_policies: [name.trim()] }} label={target.label} onClose={onClose} />;
  return (
    <dialog ref={ref} className="review" aria-label="Delete a policy" onClose={onClose}>
      <header className="review-head"><h2>Delete a policy on {target.label}</h2>
        <button type="button" className="btn ghost icon small" aria-label="Close" onClick={() => ref.current?.close()}>✕</button></header>
      <div className="review-body">
        <label className="field"><span>Policy name</span>
          <input type="text" className="mono" aria-label="Policy to delete" value={name} onChange={(e) => { setName(e.target.value); setUsers(null); }} /></label>
        <button type="button" className="btn small" disabled={!name.trim()} onClick={() => api.roleGranting(target.conn_id, name.trim()).then((r) => setUsers(r.roles)).catch(() => setUsers([]))}>
          Which roles use it?</button>
        {users && (users.length
          ? <div className="notice warn">Logins through {users.map((u) => <span key={`${u.mount}/${u.role}`} className="mono grant">auth/{u.mount}/role/{u.role}</span>)} lose what it gives them.</div>
          : <div className="notice info">No Kubernetes, JWT or OIDC role grants it (groups, entities and tokens still might).</div>)}
      </div>
      <footer className="review-foot"><span className="spacer" />
        <button type="button" className="btn ghost" onClick={() => ref.current?.close()}>Cancel</button>
        <button type="button" className="btn danger-solid" disabled={!name.trim() || users === null} onClick={() => setGo(true)}>Review delete…</button>
      </footer>
    </dialog>
  );
}

function ExportDialog({ drafts, target, canApply, onClose }: { drafts: PolicyDraft[]; target: ScanTarget; canApply: boolean; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const [chosen, setChosen] = useState<Set<number>>(new Set(drafts.map((_, i) => i)));
  const [tool, setTool] = useState<"" | "terraform" | "opentofu">("");
  const [provider, setProvider] = useState<TerraformOptions["provider"]>("~> 5.0");
  const [layout, setLayout] = useState<TerraformOptions["layout"]>("single");
  const [imports, setImports] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const bad = useMemo(() => drafts.filter((d, i) => chosen.has(i) && !NAME.test(d.name)), [drafts, chosen]);
  const [writing, setWriting] = useState<{ name: string; text: string }[] | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const texts = () => Promise.all(drafts.filter((_, i) => chosen.has(i)).map(async (d) => ({
    name: d.name, text: d.hcl ?? (await api.buildPolicy(d.mount, d.name, d.rules.filter((r) => r.where.trim() && r.can.length))).hcl })));

  useEffect(() => { ref.current?.showModal(); }, []);

  async function go() {
    setBusy(true);
    setError(null);
    try {
      const policies = await Promise.all(drafts.filter((_, i) => chosen.has(i)).map(async (d) => ({
        name: d.name,
        text: d.hcl ?? (await api.buildPolicy(d.mount, d.name, d.rules.filter((r) => r.where.trim() && r.can.length))).hcl,
      })));
      const { blob, name } = await api.policyBundle(policies, tool ? { tool, provider, layout, imports } : null, imports ? target.conn_id : null);
      download(blob, name);
      ref.current?.close();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
    {writing ? <AccessApply changes={{ conn_id: target.conn_id, policies: writing }} label={target.label} onClose={onClose} /> :
    <dialog ref={ref} className="review" onClose={onClose} aria-label="Download for an admin">
      <header className="review-head">
        <h2>Download for an admin</h2>
        <button type="button" className="btn ghost icon small" aria-label="Close" onClick={() => ref.current?.close()}>✕</button>
      </header>
      <div className="review-body">
        <p className="subtle">A zip with one <code>.hcl</code> file per policy, a README, and <code>apply.sh</code>, which shows the difference with what’s in
          Vault (<code>--dry-run</code>) and writes the policies with the vault CLI. No secret values are in it.</p>
        <fieldset className="export-pick">
          <legend>Policies</legend>
          {drafts.map((d, i) => (
            <label key={i} className="inline-check"><input type="checkbox" checked={chosen.has(i)}
                   onChange={() => setChosen((c) => { const n = new Set(c); if (n.has(i)) n.delete(i); else n.add(i); return n; })} /> <span className="mono">{d.name}</span></label>
          ))}
        </fieldset>
        <fieldset className="export-pick">
          <legend>Also as infrastructure code</legend>
          <label className="inline-check"><input type="radio" name="tool" checked={tool === ""} onChange={() => setTool("")} /> No</label>
          <label className="inline-check"><input type="radio" name="tool" checked={tool === "terraform"} onChange={() => setTool("terraform")} /> Terraform</label>
          <label className="inline-check"><input type="radio" name="tool" checked={tool === "opentofu"} onChange={() => setTool("opentofu")} /> OpenTofu</label>
          {tool && (
            <div className="field-row">
              <label className="field inline"><span>hashicorp/vault provider</span>
                <select value={provider} onChange={(e) => setProvider(e.target.value as TerraformOptions["provider"])} aria-label="Provider version">
                  <option value="~> 5.0">~&gt; 5.0</option><option value="~> 4.0">~&gt; 4.0</option>
                </select></label>
              <label className="field inline"><span>Files</span>
                <select value={layout} onChange={(e) => setLayout(e.target.value as TerraformOptions["layout"])} aria-label="Terraform layout">
                  <option value="single">one policies.tf</option><option value="files">one file per policy</option>
                </select></label>
            </div>
          )}
        </fieldset>
        <label className="inline-check" title="Lists which policies already exist in the Vault on this side">
          <input type="checkbox" checked={imports} onChange={(e) => setImports(e.target.checked)} />
          Check which already exist on {target.label}{tool ? ", and add import blocks for them" : ""}
        </label>
        {bad.length > 0 && <div className="notice warn">Fix these names first: {bad.map((d) => d.name || "(unnamed)").join(", ")}</div>}
        {error && <div className="notice error">{error}</div>}
        {saved && <div className="notice info" role="status">Saved access plan {saved}. Someone with the rights opens it in Policies → Open an access plan… on this Lockstep server.</div>}
      </div>
      <footer className="review-foot">
        <span className="spacer" />
        <button type="button" className="btn ghost" onClick={() => ref.current?.close()}>Cancel</button>
        <button type="button" className="btn" disabled={busy || !chosen.size || bad.length > 0}
                title="A signed file for someone with the rights to check and apply these in Lockstep"
                onClick={async () => {
                  try { setSaved(await saveAccessPlan({ conn_id: target.conn_id, policies: await texts() })); } catch (e) { setError((e as Error).message); }
                }}>Save as access plan</button>
        {canApply && (
          <button type="button" className="btn" disabled={busy || !chosen.size || bad.length > 0}
                  onClick={async () => { try { setWriting(await texts()); } catch (e) { setError((e as Error).message); } }}>Write to {target.label}…</button>
        )}
        <button type="button" className="btn primary" disabled={busy || !chosen.size || bad.length > 0} onClick={go}>
          {busy && <span className="spinner" />} Download zip
        </button>
      </footer>
    </dialog>}
    </>
  );
}
