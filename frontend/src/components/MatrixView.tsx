import { useMemo, useState } from "react";
import { api, type SideRef } from "../api";
import type { ProfileRef } from "../profiles";
import type { Connection, DriftBaseline, LoadedFile, MatrixCell, MatrixCellStatus, MatrixResult, Profile, SideSelection } from "../types";
import { FileLoader } from "./FileLoader";
import { MountSelect } from "./MountSelect";

/** One environment compared with the baseline: where it is and which profile pairs it. */
export interface MatrixEnvSetup {
  id: string;
  name: string;
  connId: string | null;
  mount: string | null;
  prefix: string;
  profile: ProfileRef | null;
  /** Accepted drift for this pair: a drift baseline file (base.json). Statuses only, no values. */
  accepted?: { name: string; doc: DriftBaseline } | null;
}

interface Props {
  connections: Connection[];
  /** Export files opened in this page (a baseline can be one), and a callback for a newly opened one */
  files: LoadedFile[];
  onFile: (f: LoadedFile) => void;
  left: SideSelection; // the baseline, until one is chosen here
  right: SideSelection; // offered as the first environment
  shared: Profile[];
  personal: Profile[];
  /** Open one pair in Compare: the baseline on the left, the environment on the right */
  onOpenPair: (baseline: SideSelection, env: MatrixEnvSetup) => void;
}

const STORE = "lockstep.matrix";
const MAX = 12;
const SYMBOL: Record<MatrixCellStatus, string> = { equal: "=", different: "≠", missing: "missing", extra: "extra", not_compared: "?", absent: "·" };
const WORD: Record<MatrixCellStatus, string> = {
  equal: "Same as the baseline", different: "Differs from the baseline", missing: "Not in this environment",
  extra: "Only in this environment, not in the baseline", not_compared: "Couldn't be compared", absent: "Neither has it",
};

const newId = () => Math.random().toString(36).slice(2, 10);

interface Stored { baselineName: string; baseline: SideSelection | null; envs: MatrixEnvSetup[] }

// Remembered per browser: names, connections, mounts, prefixes and profile names (no secrets).
// An export file baseline isn't: opened files live in this page only.
function load(): Stored {
  try {
    const v = JSON.parse(localStorage.getItem(STORE) ?? "null");
    if (v && Array.isArray(v.envs)) {
      const b = v.baseline && typeof v.baseline === "object" && v.baseline.connId ? { connId: String(v.baseline.connId), mount: v.baseline.mount ?? null, prefix: String(v.baseline.prefix ?? "") } : null;
      return { baselineName: String(v.baselineName ?? "baseline"), baseline: b, envs: v.envs };
    }
  } catch { /* storage unavailable */ }
  return { baselineName: "baseline", baseline: null, envs: [] };
}
function save(s: Stored) {
  const b = s.baseline && !s.baseline.fileId ? { connId: s.baseline.connId, mount: s.baseline.mount, prefix: s.baseline.prefix } : null;
  try { localStorage.setItem(STORE, JSON.stringify({ baselineName: s.baselineName, baseline: b, envs: s.envs })); } catch { /* ignore */ }
}

const FILE = "file:";
const OPEN_FILE = "__open_file__";

const refKey = (r: ProfileRef | null) => (r ? `${r.source}:${r.name}` : "");

/** Read a drift baseline file (lockstep baseline update, base.json); throws a sentence when it isn't one. */
export async function readDriftBaseline(file: File): Promise<DriftBaseline> {
  let doc: unknown;
  try { doc = JSON.parse(await file.text()); } catch { throw new Error(`${file.name} isn't JSON.`); }
  const d = doc as Partial<DriftBaseline> | null;
  if (!d || typeof d !== "object" || d.lockstep_baseline !== 1 || !Array.isArray(d.drift) || !d.left || !d.right) {
    throw new Error(`${file.name} isn't a Lockstep drift baseline (lockstep baseline update writes one).`);
  }
  return d as DriftBaseline;
}

export function MatrixView({ connections, files, onFile, left, right, shared, personal, onOpenPair }: Props) {
  const initial = useMemo(load, []);
  const [baselineName, setBaselineNameState] = useState(initial.baselineName);
  // The baseline: a Vault location or an opened export file. It starts as the left side's.
  const [baseline, setBaselineState] = useState<SideSelection>(() => initial.baseline ?? { connId: left.connId, mount: left.mount, prefix: left.prefix, fileId: left.fileId });
  const [openingFile, setOpeningFile] = useState(false);
  const [envs, setEnvsState] = useState<MatrixEnvSetup[]>(() => {
    if (initial.envs.length || !right.connId || right.fileId) return initial.envs;
    return [{ id: newId(), name: connections.find((c) => c.id === right.connId)?.name ?? "environment", connId: right.connId,
              mount: right.mount, prefix: right.prefix, profile: null }];
  });
  const [includeEqual, setIncludeEqual] = useState(false);
  const [result, setResult] = useState<MatrixResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);

  const setEnvs = (next: MatrixEnvSetup[]) => { setEnvsState(next); save({ baselineName, baseline, envs: next }); setResult(null); };
  const setBaselineName = (n: string) => { setBaselineNameState(n); save({ baselineName: n, baseline, envs }); };
  const setBaseline = (b: SideSelection) => { setBaselineState(b); save({ baselineName, baseline: b, envs }); setResult(null); };
  const update = (id: string, patch: Partial<MatrixEnvSetup>) => setEnvs(envs.map((e) => (e.id === id ? { ...e, ...patch } : e)));
  const profileOf = (r: ProfileRef | null) => (r ? (r.source === "shared" ? shared : personal).find((p) => p.name === r.name) ?? null : null);

  // A remembered connection may have been signed out since (or not be loaded yet): treat it as unset
  const known = (id: string | null) => !!id && connections.some((c) => c.id === id);
  const baseFile = files.find((f) => f.id === baseline.fileId) ?? null;
  const baselineRef: SideRef | null = baseFile ? { export: baseFile.doc, name: baseFile.name, prefix: baseline.prefix }
    : known(baseline.connId) && baseline.mount ? { conn_id: baseline.connId!, mount: baseline.mount, prefix: baseline.prefix } : null;
  const baseReady = !!baselineRef;
  const baseSource = baseFile ? `${FILE}${baseFile.id}` : known(baseline.connId) ? baseline.connId! : "";
  const names = [baselineName.trim(), ...envs.map((e) => e.name.trim())];
  const duplicate = names.some((n, i) => n && names.indexOf(n) !== i);
  const ready = baseReady && envs.length > 0 && !duplicate && names.every(Boolean) && envs.every((e) => known(e.connId) && e.mount);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      const res = await api.matrix(baselineName.trim(), baselineRef!,
        envs.map((e) => ({ name: e.name.trim(), side: { conn_id: e.connId!, mount: e.mount!, prefix: e.prefix },
                           rules: profileOf(e.profile)?.rules ?? null, accepted: e.accepted ?? null })),
        includeEqual);
      setResult(res);
    } catch (e) {
      setError((e as Error).message);
      setResult(null);
    } finally {
      setBusy(false);
    }
  }

  function downloadCsv() {
    if (!result) return;
    const esc = (s: string) => { const t = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s; return /[",\n]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t; };
    const lines = [["secret", "key", ...result.environments.map((e) => e.name)].map(esc).join(",")];
    for (const r of result.rows) {
      lines.push([r.path, r.key ?? "", ...r.cells.map((c) => (c.status === "absent" ? "" : c.status.replace("_", " ") + (c.accepted ? " (accepted)" : "")))].map(esc).join(","));
    }
    const url = URL.createObjectURL(new Blob([lines.join("\n") + "\n"], { type: "text/csv" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `lockstep-matrix-${baselineName.trim() || "baseline"}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="matrix-view">
      <section className="card matrix-setup" aria-label="Environment matrix setup">
        <h2>Environment matrix</h2>
        <p className="subtle">
          Compare a baseline with several environments at once. Each environment is compared with
          the baseline under its own profile. Rows that differ in only one environment come first: they're the likeliest mistakes.
          The baseline can be a Vault or an export file.
        </p>
        <div className="matrix-baseline">
          <label className="field">
            <span>Baseline name</span>
            <input type="text" value={baselineName} maxLength={60} onChange={(e) => setBaselineName(e.target.value)} />
          </label>
          <label className="field">
            <span>Baseline</span>
            <select value={openingFile ? OPEN_FILE : baseSource} aria-label="Baseline connection or file"
                    onChange={(ev) => {
                      const v = ev.target.value;
                      if (v === OPEN_FILE) { setOpeningFile(true); return; }
                      setOpeningFile(false);
                      setBaseline(v.startsWith(FILE) ? { connId: null, mount: null, prefix: "", fileId: v.slice(FILE.length) }
                        : { connId: v || null, mount: null, prefix: "" });
                    }}>
              <option value="">Choose…</option>
              {connections.length > 0 && <optgroup label="Signed in">
                {connections.map((c) => <option key={c.id} value={c.id}>{c.name} · {c.display_name || c.auth_method}</option>)}
              </optgroup>}
              {files.length > 0 && <optgroup label="Export files">
                {files.map((f) => <option key={f.id} value={`${FILE}${f.id}`}>{f.name} (export file)</option>)}
              </optgroup>}
              <option value={OPEN_FILE}>Open an export file…</option>
            </select>
          </label>
          {openingFile ? (
            <div className="field matrix-file">
              <FileLoader onLoaded={(f) => { onFile(f); setOpeningFile(false); setBaseline({ connId: null, mount: null, prefix: "", fileId: f.id }); }} />
            </div>
          ) : known(baseline.connId) && !baseFile ? (
            <MountSelect connId={baseline.connId!} mount={baseline.mount} kv1
                         onChange={(m) => setBaseline({ ...baseline, mount: m, prefix: "" })} />
          ) : null}
          {(baseFile || (known(baseline.connId) && !openingFile)) && (
            <label className="field">
              <span>Path prefix <span className="subtle">(optional)</span></span>
              <input type="text" value={baseline.prefix} placeholder="e.g. services/" aria-label="Baseline path prefix"
                     onChange={(ev) => setBaseline({ ...baseline, prefix: ev.target.value })} />
            </label>
          )}
        </div>

        <ol className="matrix-envs" aria-label="Environments">
          {envs.map((e, i) => (
            <li key={e.id} className="matrix-env">
              <label className="field">
                <span>Name</span>
                <input type="text" value={e.name} maxLength={60} aria-label={`Environment ${i + 1} name`}
                       onChange={(ev) => update(e.id, { name: ev.target.value })} />
              </label>
              <label className="field">
                <span>Connection</span>
                <select value={known(e.connId) ? e.connId! : ""} aria-label={`Environment ${i + 1} connection`}
                        onChange={(ev) => update(e.id, { connId: ev.target.value || null, mount: null })}>
                  <option value="">Choose…</option>
                  {connections.map((c) => <option key={c.id} value={c.id}>{c.name} · {c.display_name || c.auth_method}</option>)}
                </select>
              </label>
              {known(e.connId) ? <MountSelect connId={e.connId!} mount={e.mount} kv1 onChange={(m) => update(e.id, { mount: m })} />
                : <div className="field"><span>KV secret engine</span><span className="subtle">Choose a connection first</span></div>}
              <label className="field">
                <span>Path prefix <span className="subtle">(optional)</span></span>
                <input type="text" value={e.prefix} placeholder="e.g. services/" aria-label={`Environment ${i + 1} path prefix`}
                       onChange={(ev) => update(e.id, { prefix: ev.target.value })} />
              </label>
              <label className="field">
                <span>Profile</span>
                <select value={refKey(e.profile)} aria-label={`Environment ${i + 1} profile`}
                        onChange={(ev) => {
                          const v = ev.target.value;
                          const [source, ...rest] = v.split(":");
                          update(e.id, { profile: v ? { source: source as ProfileRef["source"], name: rest.join(":") } : null });
                        }}>
                  <option value="">None</option>
                  {shared.length > 0 && <optgroup label="Shared">{shared.map((p) => <option key={p.name} value={`shared:${p.name}`}>{p.name}</option>)}</optgroup>}
                  {personal.length > 0 && <optgroup label="Yours">{personal.map((p) => <option key={p.name} value={`personal:${p.name}`}>{p.name}</option>)}</optgroup>}
                </select>
              </label>
              <div className="field matrix-accepted">
                <span>Accepted drift <span className="subtle">(optional)</span></span>
                {e.accepted ? (
                  <span className="accepted-file">
                    <span className="mono" title={`${e.accepted.doc.drift.length} accepted differences`}>{e.accepted.name}</span>
                    {e.accepted.doc.signature && <span className="subtle" title="Checked against this server's trusted plan keys when you compare">
                      signed by {e.accepted.doc.issuer?.name ?? "?"}</span>}
                    <button type="button" className="btn ghost small icon-x" aria-label={`Remove accepted drift for ${e.name || `environment ${i + 1}`}`}
                            title="Remove the accepted drift" onClick={() => update(e.id, { accepted: null })}>×</button>
                  </span>
                ) : (
                  <label className="btn small file-pick">
                    Open base.json…
                    <input type="file" accept=".json,application/json" className="sr-only" aria-label={`Environment ${i + 1} accepted drift`}
                           onChange={async (ev) => {
                             const f = ev.target.files?.[0];
                             ev.target.value = "";
                             if (!f) return;
                             try {
                               update(e.id, { accepted: { name: f.name, doc: await readDriftBaseline(f) } });
                               setFileError(null);
                             } catch (err) { setFileError((err as Error).message); }
                           }} />
                  </label>
                )}
              </div>
              <button type="button" className="btn ghost small matrix-remove" aria-label={`Remove ${e.name || `environment ${i + 1}`}`}
                      onClick={() => setEnvs(envs.filter((x) => x.id !== e.id))}>Remove</button>
            </li>
          ))}
        </ol>
        {envs.length === 0 && <p className="subtle">No environments yet. Add one for each environment to compare with the baseline.</p>}
        <div className="matrix-actions">
          <button type="button" className="btn" disabled={envs.length >= MAX}
                  onClick={() => setEnvs([...envs, { id: newId(), name: `env-${envs.length + 1}`, connId: baseFile ? null : baseline.connId,
                                                     mount: baseFile ? null : baseline.mount, prefix: baseFile ? "" : baseline.prefix, profile: null }])}>
            Add environment
          </button>
          <button type="button" className="btn primary" disabled={!ready || busy} onClick={run}>
            {busy && <span className="spinner" />} Compare all
          </button>
          <label className="inline-check">
            <input type="checkbox" checked={includeEqual} onChange={(e) => { setIncludeEqual(e.target.checked); setResult(null); }} /> Also show rows that match everywhere
          </label>
        </div>
        {duplicate && <div className="notice warn">Give the baseline and each environment a different name.</div>}
        {fileError && <div className="notice error" role="alert">{fileError}</div>}
        <p className="subtle small-print">
          Every signed-in connection is offered. To add another Vault, sign in to it under Connections above. Up to {MAX} environments.
          Accepted drift is a drift baseline for that pair (<code>lockstep baseline update</code>, or a drift check's <code>base.json</code>):
          what it lists is still shown, marked accepted, but doesn't count as a difference.
        </p>
      </section>

      {error && <div className="notice error" role="alert">{error}</div>}
      {result && <MatrixGrid result={result} onOpen={(i) => onOpenPair(baseline, envs[i])} onCsv={downloadCsv} />}
    </div>
  );
}

function MatrixGrid({ result, onOpen, onCsv }: { result: MatrixResult; onOpen: (i: number) => void; onCsv: () => void }) {
  const s = result.summary;
  const b = result.baseline;
  return (
    <section className="card matrix-result" aria-label="Environment matrix">
      <div className="matrix-summary" role="status">
        {s.differing_rows === 0 && s.unknown_rows === 0
          ? <strong>Every environment matches {b.name}{s.known_rows ? `, apart from accepted drift (${s.known_rows} row${s.known_rows === 1 ? "" : "s"})` : ""}{s.failed ? ", except those that couldn't be compared" : ""}.</strong>
          : <span><strong>{s.differing_rows}</strong> row{s.differing_rows === 1 ? " differs" : "s differ"} from {b.name}
              {s.environments > 1 && s.odd_one_out > 0 && <>, <strong>{s.odd_one_out}</strong> in only one environment (listed first)</>}
              {s.unknown_rows > 0 && <>; {s.unknown_rows} couldn't be told</>}
              {s.known_rows > 0 && <>; {s.known_rows} only accepted drift (listed last)</>}.</span>}
        <span className="spacer" />
        <button type="button" className="btn small" onClick={onCsv} disabled={result.rows.length === 0}>Download CSV</button>
      </div>
      {result.environments.filter((e) => e.error).map((e) => (
        <div key={e.name} className="notice error">{e.name} couldn't be compared: {e.error}</div>
      ))}
      {(b.truncated || result.environments.some((e) => e.truncated)) && (
        <div className="notice warn">A side has more secrets than Lockstep lists at once, so the matrix is incomplete. Narrow it with a path prefix.</div>
      )}
      {result.rows.length > 0 && (
        <div className="matrix-scroll">
          <table className="matrix-grid">
            <thead>
              <tr>
                <th scope="col">Secret</th>
                <th scope="col">Key</th>
                {result.environments.map((e, i) => (
                  <th scope="col" key={e.name} className="matrix-col">
                    <span className="matrix-env-name">{e.name}</span>
                    <span className="subtle mono">{e.mount}{e.prefix ? `/${e.prefix}` : ""}</span>
                    {e.accepted && <span className="subtle matrix-accepted-note" title={e.accepted_unused ? `${e.accepted_unused} accepted differences aren't there any more` : undefined}>
                      accepted: {e.accepted}{e.accepted_signer ? `, signed by ${e.accepted_signer}` : ""}{e.accepted_unused ? ` · ${e.accepted_unused} resolved` : ""}</span>}
                    {!e.error && <button type="button" className="btn ghost small" onClick={() => onOpen(i)}
                                         title={`Compare ${b.name} with ${e.name} side by side`}>Open in Compare</button>}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {result.rows.map((r) => (
                <tr key={`${r.path}\u0000${r.key ?? ""}`} className={r.odd === 1 && result.environments.length > 1 ? "odd-one" : undefined}>
                  <td className="mono">{r.path}</td>
                  <td className="mono">{r.key ?? <span className="subtle">the secret</span>}</td>
                  {r.cells.map((c, i) => (
                    <td key={i} className={`mcell ${c.status}${c.accepted ? " accepted" : ""}`} title={describe(c)}>
                      <span aria-hidden="true">{SYMBOL[c.status]}{c.accepted ? "*" : ""}</span>
                      <span className="sr-only">{describe(c)}</span>
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="subtle small-print">=: same as {b.name}; ≠: differs; missing: not in this environment; extra: only in this environment; ?: couldn't be compared; ·: neither has it; *: accepted drift. Values are never shown.</p>
    </section>
  );
}

function describe(c: MatrixCell): string {
  return WORD[c.status] + (c.reason ? `: ${c.reason}` : "") + (c.accepted ? " (accepted drift)" : "");
}
