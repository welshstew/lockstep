import { useMemo, useState } from "react";
import { api } from "../api";
import type { ProfileRef } from "../profiles";
import type { Connection, MatrixCellStatus, MatrixResult, Profile, SideSelection } from "../types";
import { MountSelect } from "./MountSelect";

/** One environment compared with the baseline: where it is and which profile pairs it. */
export interface MatrixEnvSetup {
  id: string;
  name: string;
  connId: string | null;
  mount: string | null;
  prefix: string;
  profile: ProfileRef | null;
}

interface Props {
  connections: Connection[];
  baseline: SideSelection; // the left side
  baselineLabel: string;
  right: SideSelection; // offered as the first environment
  shared: Profile[];
  personal: Profile[];
  onOpenPair: (env: MatrixEnvSetup) => void;
}

const STORE = "lockstep.matrix";
const MAX = 12;
const SYMBOL: Record<MatrixCellStatus, string> = { equal: "=", different: "≠", missing: "missing", extra: "extra", not_compared: "?", absent: "·" };
const WORD: Record<MatrixCellStatus, string> = {
  equal: "Same as the baseline", different: "Differs from the baseline", missing: "Not in this environment",
  extra: "Only in this environment, not in the baseline", not_compared: "Couldn't be compared", absent: "Neither has it",
};

const newId = () => Math.random().toString(36).slice(2, 10);

// Remembered per browser: names, connections, mounts, prefixes and profile names (no secrets)
function load(): { baselineName: string; envs: MatrixEnvSetup[] } {
  try {
    const v = JSON.parse(localStorage.getItem(STORE) ?? "null");
    if (v && Array.isArray(v.envs)) return { baselineName: String(v.baselineName ?? "baseline"), envs: v.envs };
  } catch { /* storage unavailable */ }
  return { baselineName: "baseline", envs: [] };
}
function save(baselineName: string, envs: MatrixEnvSetup[]) {
  try { localStorage.setItem(STORE, JSON.stringify({ baselineName, envs })); } catch { /* ignore */ }
}

const refKey = (r: ProfileRef | null) => (r ? `${r.source}:${r.name}` : "");

export function MatrixView({ connections, baseline, baselineLabel, right, shared, personal, onOpenPair }: Props) {
  const initial = useMemo(load, []);
  const [baselineName, setBaselineNameState] = useState(initial.baselineName);
  const [envs, setEnvsState] = useState<MatrixEnvSetup[]>(() => {
    if (initial.envs.length || !right.connId || right.fileId) return initial.envs;
    return [{ id: newId(), name: connections.find((c) => c.id === right.connId)?.name ?? "environment", connId: right.connId,
              mount: right.mount, prefix: right.prefix, profile: null }];
  });
  const [includeEqual, setIncludeEqual] = useState(false);
  const [result, setResult] = useState<MatrixResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const setEnvs = (next: MatrixEnvSetup[]) => { setEnvsState(next); save(baselineName, next); setResult(null); };
  const setBaselineName = (n: string) => { setBaselineNameState(n); save(n, envs); };
  const update = (id: string, patch: Partial<MatrixEnvSetup>) => setEnvs(envs.map((e) => (e.id === id ? { ...e, ...patch } : e)));
  const profileOf = (r: ProfileRef | null) => (r ? (r.source === "shared" ? shared : personal).find((p) => p.name === r.name) ?? null : null);

  // A remembered connection may have been signed out since (or not be loaded yet): treat it as unset
  const known = (id: string | null) => !!id && connections.some((c) => c.id === id);
  const baseReady = !!(baseline.connId && baseline.mount && !baseline.fileId);
  const names = [baselineName.trim(), ...envs.map((e) => e.name.trim())];
  const duplicate = names.some((n, i) => n && names.indexOf(n) !== i);
  const ready = baseReady && envs.length > 0 && !duplicate && names.every(Boolean) && envs.every((e) => known(e.connId) && e.mount);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      const res = await api.matrix(baselineName.trim(), { conn_id: baseline.connId!, mount: baseline.mount!, prefix: baseline.prefix },
        envs.map((e) => ({ name: e.name.trim(), side: { conn_id: e.connId!, mount: e.mount!, prefix: e.prefix }, rules: profileOf(e.profile)?.rules ?? null })),
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
    for (const r of result.rows) lines.push([r.path, r.key ?? "", ...r.cells.map((c) => (c.status === "absent" ? "" : c.status.replace("_", " ")))].map(esc).join(","));
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
          Compare the left side, the baseline, with several environments at once. Each environment is compared with
          the baseline under its own profile. Rows that differ in only one environment come first: they're the likeliest mistakes.
        </p>
        <div className="matrix-baseline">
          <label className="field">
            <span>Baseline name</span>
            <input type="text" value={baselineName} maxLength={60} onChange={(e) => setBaselineName(e.target.value)} />
          </label>
          <div className="field">
            <span>Baseline</span>
            {baseReady ? <span className="mono">{baselineLabel}</span>
              : <span className="subtle">Choose a Vault and mount on the left side above: it's the baseline.</span>}
          </div>
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
              <button type="button" className="btn ghost small matrix-remove" aria-label={`Remove ${e.name || `environment ${i + 1}`}`}
                      onClick={() => setEnvs(envs.filter((x) => x.id !== e.id))}>Remove</button>
            </li>
          ))}
        </ol>
        {envs.length === 0 && <p className="subtle">No environments yet. Add one for each environment to compare with the baseline.</p>}
        <div className="matrix-actions">
          <button type="button" className="btn" disabled={envs.length >= MAX}
                  onClick={() => setEnvs([...envs, { id: newId(), name: `env-${envs.length + 1}`, connId: baseline.connId,
                                                     mount: baseline.mount, prefix: baseline.prefix, profile: null }])}>
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
        <p className="subtle small-print">
          Every signed-in connection is offered. To add another Vault, sign in to it on the right side above. Up to {MAX} environments.
        </p>
      </section>

      {error && <div className="notice error" role="alert">{error}</div>}
      {result && <MatrixGrid result={result} onOpen={(i) => onOpenPair(envs[i])} onCsv={downloadCsv} />}
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
          ? <strong>Every environment matches {b.name}{s.failed ? ", except those that couldn't be compared" : ""}.</strong>
          : <span><strong>{s.differing_rows}</strong> row{s.differing_rows === 1 ? "" : "s"} differ from {b.name}
              {s.environments > 1 && s.odd_one_out > 0 && <>, <strong>{s.odd_one_out}</strong> in only one environment (listed first)</>}
              {s.unknown_rows > 0 && <>; {s.unknown_rows} couldn't be told</>}.</span>}
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
                    <td key={i} className={`mcell ${c.status}`} title={c.reason ? `${WORD[c.status]}: ${c.reason}` : WORD[c.status]}>
                      <span aria-hidden="true">{SYMBOL[c.status]}</span>
                      <span className="sr-only">{WORD[c.status]}{c.reason ? `: ${c.reason}` : ""}</span>
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="subtle small-print">=: same as {b.name}; ≠: differs; missing: not in this environment; extra: only in this environment; ?: couldn't be compared; ·: neither has it. Values are never shown.</p>
    </section>
  );
}
