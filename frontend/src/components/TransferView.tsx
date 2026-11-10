import { useRef, useState } from "react";
import { api } from "../api";
import type {
  AppConfig, ApplyResult, ChangePlan, ExportResult, ImportPreview, ImportRules, LoadedFile, Profile, Transform,
} from "../types";
import { FileLoader, FileSummary } from "./FileLoader";
import { formatValue } from "./ValueCell";

type VaultSide = { conn_id: string; mount: string; prefix: string };
export interface SideOption { side: "left" | "right"; label: string; ref: VaultSide | null }

interface Props {
  config: AppConfig;
  reveal: boolean;
  files: LoadedFile[];
  onFile: (f: LoadedFile) => void;
  sides: SideOption[];
  profiles: Profile[];
}

const RULES_SCHEMA = "https://getlockstep.cloud/schemas/lockstep-import-rules-v1.json";

export function TransferView(props: Props) {
  return (
    <div className="transfer">
      <ExportPanel {...props} />
      <ImportPanel {...props} />
    </div>
  );
}

// --------------------------------------------------------------------------- shared rule inputs

type KeyRule = { key: string; path: string };

function IgnoreInputs({ paths, keys, onPaths, onKeys, id }: {
  paths: string; keys: KeyRule[]; onPaths: (v: string) => void; onKeys: (v: KeyRule[]) => void; id: string;
}) {
  return (
    <>
      <label className="field"><span>Leave out secrets <span className="subtle">(one glob per line, e.g. <code>legacy/**</code>)</span></span>
        <textarea className="mono" rows={2} value={paths} aria-label={`${id}: ignored paths`}
                  onChange={(e) => onPaths(e.target.value)} placeholder={"legacy/**\ntmp/*"} /></label>
      <div className="field"><span>Leave out keys</span>
        {keys.map((k, i) => (
          <div className="row rule-row" key={i}>
            <input className="grow mono" type="text" value={k.key} placeholder="key pattern, e.g. *_token" aria-label={`${id}: ignored key ${i + 1}`}
                   onChange={(e) => onKeys(keys.map((x, j) => (j === i ? { ...x, key: e.target.value } : x)))} />
            <span className="subtle">under</span>
            <input className="grow mono" type="text" value={k.path} placeholder="** (everywhere)" aria-label={`${id}: ignored key ${i + 1} path`}
                   onChange={(e) => onKeys(keys.map((x, j) => (j === i ? { ...x, path: e.target.value } : x)))} />
            <button type="button" className="btn ghost icon small" aria-label={`Remove ignored key ${i + 1}`}
                    onClick={() => onKeys(keys.filter((_, j) => j !== i))}>✕</button>
          </div>
        ))}
        <div><button type="button" className="btn small" onClick={() => onKeys([...keys, { key: "", path: "" }])}>＋ Add key rule</button></div>
      </div>
    </>
  );
}

const lines = (s: string) => s.split("\n").map((l) => l.trim()).filter(Boolean);
const keyRules = (ks: KeyRule[]) => ks.filter((k) => k.key.trim()).map((k) => ({ key: k.key.trim(), path: k.path.trim() || "**" }));

function download(name: string, data: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// --------------------------------------------------------------------------- export

function ExportPanel({ config, sides, profiles }: Props) {
  const usable = sides.filter((s) => s.ref);
  const [from, setFrom] = useState<"left" | "right">(usable[0]?.side ?? "left");
  const [paths, setPaths] = useState("");
  const [keys, setKeys] = useState<KeyRule[]>([]);
  const [encrypt, setEncrypt] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<ExportResult | null>(null);
  const [copied, setCopied] = useState(false);
  const source = usable.find((s) => s.side === from) ?? usable[0];
  const mode = config.export_mode ?? "any";

  if (mode === "off") {
    return <section className="card transfer-card"><h2>Export</h2><p className="subtle">Exporting is turned off on this server.</p></section>;
  }

  async function run() {
    if (!source?.ref) return;
    setBusy(true);
    setError(null);
    setDone(null);
    try {
      const r = await api.exportCreate(source.ref, { ignore_paths: lines(paths), ignore_keys: keyRules(keys) }, encrypt || mode === "encrypted");
      download(r.filename, r.file);
      setDone(r);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card transfer-card" aria-label="Export">
      <h2>Export a secret engine</h2>
      <p className="subtle">Every secret under a mount (and prefix), with its values and version, in one file: for a backup, a migration, or to compare or import elsewhere.</p>
      {usable.length === 0 ? (
        <div className="notice info">Connect a Vault and choose a mount on the left or right side above first.</div>
      ) : (
        <>
          <label className="field"><span>Export from</span>
            <select value={source?.side} onChange={(e) => setFrom(e.target.value as "left" | "right")} aria-label="Export from">
              {usable.map((s) => <option key={s.side} value={s.side}>{s.side === "left" ? "◧ " : ""}{s.label}{s.side === "right" ? " ◨" : ""}</option>)}
            </select>
          </label>
          {profiles.some((p) => p.rules.ignore_paths.length || p.rules.ignore_keys.length) && (
            <label className="field"><span>Start from a profile's ignore rules <span className="subtle">(optional)</span></span>
              <select value="" onChange={(e) => {
                const p = profiles.find((x) => x.name === e.target.value);
                if (!p) return;
                setPaths(p.rules.ignore_paths.join("\n"));
                setKeys(p.rules.ignore_keys.map((k) => ({ key: k.key, path: k.path })));
              }}>
                <option value="">Choose…</option>
                {profiles.map((p) => <option key={p.name} value={p.name}>{p.name}</option>)}
              </select>
            </label>
          )}
          <IgnoreInputs id="Export" paths={paths} keys={keys} onPaths={setPaths} onKeys={setKeys} />
          <label className="inline-check">
            <input type="checkbox" checked={encrypt || mode === "encrypted"} disabled={mode === "encrypted"}
                   onChange={(e) => setEncrypt(e.target.checked)} />
            Encrypt with a one-time key {mode === "encrypted" && <span className="subtle">(required by this server)</span>}
          </label>
          {!encrypt && mode !== "encrypted" && (
            <div className="notice warn" role="alert">
              Without encryption the file holds every value in plain text. Anyone who gets the file can read them.
            </div>
          )}
          {error && <div className="notice error" role="alert">{error}</div>}
          <div className="row"><button type="button" className="btn primary" disabled={busy || !source} onClick={run}>
            {busy && <span className="spinner" />} Export and download
          </button></div>
        </>
      )}
      {done && (
        <div className="export-done" role="status">
          <div>
            Downloaded <span className="mono">{done.filename}</span>: {done.secrets} secret{done.secrets === 1 ? "" : "s"}, {done.keys} key{done.keys === 1 ? "" : "s"}.
            {done.skipped.ignored_paths + done.skipped.ignored_keys > 0 && ` Left out by your rules: ${done.skipped.ignored_paths} secret(s), ${done.skipped.ignored_keys} key(s).`}
          </div>
          {(done.skipped.unreadable.length > 0 || done.skipped.denied_folders.length > 0 || done.skipped.truncated) && (
            <div className="notice warn">
              Not exported: {[done.skipped.unreadable.length && `${done.skipped.unreadable.length} unreadable secret(s)`,
                              done.skipped.denied_folders.length && `folders you can't list (${done.skipped.denied_folders.join(", ")})`,
                              done.skipped.truncated && "secrets beyond the listing limit"].filter(Boolean).join("; ")}.
            </div>
          )}
          {done.key && (
            <div className="key-box">
              <strong>Your one-time key</strong>
              <code className="mono key-text" aria-label="Export key">{done.key}</code>
              <div className="row">
                <button type="button" className="btn small" onClick={async () => {
                  await navigator.clipboard.writeText(done.key!);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1200);
                }}>{copied ? "Copied" : "Copy key"}</button>
                <span className="subtle">Shown once and never stored. Keep it apart from the file: without it the file can’t be opened.</span>
              </div>
              <button type="button" className="btn ghost small" onClick={() => setDone({ ...done, key: null })}>I’ve saved the key: hide it</button>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

// --------------------------------------------------------------------------- import

const OPS: { op: Transform["op"]; label: string }[] = [
  { op: "replace", label: "Replace text" }, { op: "prefix", label: "Add prefix" }, { op: "suffix", label: "Add suffix" },
  { op: "upper", label: "UPPERCASE" }, { op: "lower", label: "lowercase" },
];
const newTransform = (): Transform => ({ op: "replace", target: "values", find: "", with: "", path: "**", key: "*" });

function ImportPanel({ reveal, files, onFile, sides }: Props) {
  const usable = sides.filter((s) => s.ref);
  const [fileId, setFileId] = useState<string | null>(null);
  const [to, setTo] = useState<"left" | "right">(usable.find((s) => s.side === "right")?.side ?? usable[0]?.side ?? "right");
  const [paths, setPaths] = useState("");
  const [keys, setKeys] = useState<KeyRule[]>([]);
  const [transforms, setTransforms] = useState<Transform[]>([]);
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [applied, setApplied] = useState<ApplyResult | null>(null);
  const rulesFile = useRef<HTMLInputElement>(null);
  const file = files.find((f) => f.id === fileId) ?? null;
  const target = usable.find((s) => s.side === to) ?? usable[0];

  const rules = (): ImportRules => ({ ignore_paths: lines(paths), ignore_keys: keyRules(keys), transforms });
  const stale = () => { setPreview(null); setApplied(null); setConfirmed(false); };
  const setT = (i: number, patch: Partial<Transform>) => { setTransforms(transforms.map((t, j) => (j === i ? { ...t, ...patch } : t))); stale(); };
  const move = (i: number, d: -1 | 1) => {
    const n = [...transforms];
    [n[i], n[i + d]] = [n[i + d], n[i]];
    setTransforms(n);
    stale();
  };

  async function runPreview() {
    if (!file || !target?.ref) return;
    setBusy(true); setError(null); setApplied(null); setConfirmed(false);
    try { setPreview(await api.importPreview(file.doc, file.name, rules(), target.ref, reveal)); }
    catch (e) { setError((e as Error).message); setPreview(null); }
    finally { setBusy(false); }
  }

  async function runImport() {
    if (!file || !target?.ref || !preview) return;
    const ready = preview.plans.filter((p) => p.status === "ready");
    setBusy(true); setError(null);
    try {
      setApplied(await api.importApply(file.doc, file.name, rules(), target.ref,
        Object.fromEntries(ready.map((p) => [p.path, p.target.state === "absent" ? null : p.target.version]))));
    } catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }

  const ready = preview?.plans.filter((p) => p.status === "ready") ?? [];
  const counts = preview ? preview.plans.reduce<Record<string, number>>((n, p) => ({ ...n, [p.status]: (n[p.status] ?? 0) + 1 }), {}) : {};

  return (
    <section className="card transfer-card" aria-label="Import">
      <h2>Import into a Vault</h2>
      <p className="subtle">Write an export into a mount, after leaving out and changing what you choose. Like copying: values are merged into each target secret with check-and-set, keys only on the target are kept, and nothing is deleted.</p>

      <h3 className="editor-h">1. File</h3>
      {file ? (
        <div className="conn-chip file-chip"><span className="dot ok" /><div className="who"><FileSummary f={file} /></div>
          <button type="button" className="btn ghost small" onClick={() => { setFileId(null); stale(); }}>Change</button></div>
      ) : (
        <div className="row">
          {files.length > 0 && (
            <select value="" aria-label="Opened files" onChange={(e) => { if (e.target.value) { setFileId(e.target.value); stale(); } }}>
              <option value="">An opened file…</option>
              {files.map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
            </select>
          )}
          <FileLoader onLoaded={(f) => { onFile(f); setFileId(f.id); stale(); }} />
        </div>
      )}

      <h3 className="editor-h">2. Target</h3>
      {usable.length === 0 ? <div className="notice info">Connect a Vault and choose a mount on the left or right side above.</div> : (
        <select value={target?.side} aria-label="Import into" onChange={(e) => { setTo(e.target.value as "left" | "right"); stale(); }}>
          {usable.map((s) => <option key={s.side} value={s.side}>{s.side === "left" ? "◧ " : ""}{s.label}{s.side === "right" ? " ◨" : ""}</option>)}
        </select>
      )}

      <h3 className="editor-h">3. Rules <span className="subtle">(optional)</span></h3>
      <IgnoreInputs id="Import" paths={paths} keys={keys} onPaths={(v) => { setPaths(v); stale(); }} onKeys={(v) => { setKeys(v); stale(); }} />
      <div className="field"><span>Transforms <span className="subtle">(applied in order, after leaving things out; text values only)</span></span>
        {transforms.map((t, i) => (
          <div className="transform-row" key={i} role="group" aria-label={`Transform ${i + 1}`}>
            <select value={t.op} aria-label={`Transform ${i + 1} operation`} onChange={(e) => setT(i, { op: e.target.value as Transform["op"] })}>
              {OPS.map((o) => <option key={o.op} value={o.op}>{o.label}</option>)}
            </select>
            <span className="subtle">in</span>
            <select value={t.target} aria-label={`Transform ${i + 1} applies to`} onChange={(e) => setT(i, { target: e.target.value as Transform["target"] })}>
              <option value="values">values</option><option value="keys">key names</option><option value="paths">paths</option>
            </select>
            {t.op === "replace" && <input className="mono" type="text" value={t.find} placeholder="find" aria-label={`Transform ${i + 1} find`} onChange={(e) => setT(i, { find: e.target.value })} />}
            {["replace", "prefix", "suffix"].includes(t.op) && (
              <input className="mono" type="text" value={t.with} placeholder={t.op === "replace" ? "replace with" : "text"}
                     aria-label={`Transform ${i + 1} ${t.op === "replace" ? "replace with" : "text"}`} onChange={(e) => setT(i, { with: e.target.value })} />
            )}
            <span className="subtle">for paths</span>
            <input className="mono narrow" type="text" value={t.path} aria-label={`Transform ${i + 1} path filter`} onChange={(e) => setT(i, { path: e.target.value || "**" })} />
            {t.target !== "paths" && <>
              <span className="subtle">keys</span>
              <input className="mono narrow" type="text" value={t.key} aria-label={`Transform ${i + 1} key filter`} onChange={(e) => setT(i, { key: e.target.value || "*" })} />
            </>}
            <span className="transform-tools">
              <button type="button" className="btn ghost icon small" disabled={i === 0} aria-label={`Move transform ${i + 1} up`} onClick={() => move(i, -1)}>↑</button>
              <button type="button" className="btn ghost icon small" disabled={i === transforms.length - 1} aria-label={`Move transform ${i + 1} down`} onClick={() => move(i, 1)}>↓</button>
              <button type="button" className="btn ghost icon small" aria-label={`Remove transform ${i + 1}`} onClick={() => { setTransforms(transforms.filter((_, j) => j !== i)); stale(); }}>✕</button>
            </span>
          </div>
        ))}
        <div className="row">
          <button type="button" className="btn small" onClick={() => { setTransforms([...transforms, newTransform()]); stale(); }}>＋ Add transform</button>
          <span className="spacer" />
          <button type="button" className="btn ghost small" onClick={() => download("lockstep-import-rules.json", { $schema: RULES_SCHEMA, ...rules() })}>Save rules</button>
          <button type="button" className="btn ghost small" onClick={() => rulesFile.current?.click()}>Load rules</button>
          <input ref={rulesFile} type="file" accept="application/json,.json" hidden aria-label="Rules file" onChange={async (e) => {
            const f = e.target.files?.[0];
            e.target.value = "";
            if (!f) return;
            try {
              const r = JSON.parse(await f.text()) as Partial<ImportRules>;
              setPaths((r.ignore_paths ?? []).join("\n"));
              setKeys((r.ignore_keys ?? []).map((k) => ({ key: k.key, path: k.path ?? "**" })));
              setTransforms((r.transforms ?? []).map((t) => ({ ...newTransform(), ...t })));
              stale();
            } catch { setError("That rules file isn't valid JSON."); }
          }} />
        </div>
      </div>

      {error && <div className="notice error" role="alert">{error}</div>}
      <div className="row">
        <button type="button" className="btn primary" disabled={busy || !file || !target?.ref} onClick={runPreview}>
          {busy && !preview && <span className="spinner" />} Preview import
        </button>
      </div>

      {preview && !applied && (
        <div className="import-preview">
          <div className="notice info">
            {preview.prepared.secrets} secret{preview.prepared.secrets === 1 ? "" : "s"} after the rules
            {preview.prepared.ignored_paths + preview.prepared.ignored_keys > 0 && ` (left out: ${preview.prepared.ignored_paths} secret(s), ${preview.prepared.ignored_keys} key(s))`}
            {preview.prepared.paths_changed + preview.prepared.keys_changed + preview.prepared.values_changed > 0 &&
              `; changed: ${preview.prepared.paths_changed} path(s), ${preview.prepared.keys_changed} key name(s), ${preview.prepared.values_changed} value(s)`}.
            {" "}{counts.ready ?? 0} to write, {counts.noop ?? 0} already the same
            {(preview.plans.length - (counts.ready ?? 0) - (counts.noop ?? 0)) > 0 && `, ${preview.plans.length - (counts.ready ?? 0) - (counts.noop ?? 0)} can’t be written`}.
          </div>
          {preview.prepared.problems.map((p) => <div key={p.path} className="notice error">Left out <span className="mono">{p.path}</span>: {p.message}</div>)}
          <PlanList plans={preview.plans.filter((p) => p.status !== "noop")} reveal={reveal} />
          {ready.length > 0 && (
            <div className="row">
              <label className="confirm"><input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
                Write {ready.length} secret{ready.length === 1 ? "" : "s"} to <strong>{target?.label}</strong></label>
              <span className="spacer" />
              <button type="button" className="btn primary" disabled={!confirmed || busy} onClick={runImport}>{busy && <span className="spinner" />} Import</button>
            </div>
          )}
        </div>
      )}
      {applied && (
        <div className="import-preview" role="status">
          <div className={`notice ${applied.summary.applied ? "info" : "warn"}`}>
            {applied.summary.applied} written{applied.summary.conflict + applied.summary.denied + applied.summary.error > 0 &&
              `, ${applied.summary.conflict + applied.summary.denied + applied.summary.error} not written`}.
          </div>
          <ul className="plan-list">
            {applied.results.map((r) => (
              <li key={r.path} className="plan"><div className="plan-head"><span className="mono">{r.target}</span>
                <span className={`badge ${r.status === "applied" ? "equal" : r.status === "noop" ? "unknown" : r.status === "conflict" ? "different" : "error"}`}>
                  {{ applied: "Written", noop: "No change", conflict: "Conflict: not written", denied: "Denied", invalid: "Skipped", error: "Failed" }[r.status]}
                </span></div>
                <div className="subtle">{r.status === "applied" ? `v${r.old_version ?? "—"} → v${r.new_version} · ${r.keys.join(", ")}` : r.message}</div></li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

const PLAN_LABEL: Record<string, string> = {
  ready: "Will be written", noop: "Already the same", conflict: "Changed", denied: "No permission", invalid: "Can’t import", error: "Error",
};

function PlanList({ plans, reveal }: { plans: ChangePlan[]; reveal: boolean }) {
  if (!plans.length) return <div className="subtle">Nothing to write: the target already has these values.</div>;
  return (
    <ul className="plan-list">
      {plans.map((p) => (
        <li key={p.path} className={`plan ${p.status}`}>
          <div className="plan-head">
            <span className="mono"><span className="muted">{p.source.path}</span> <span className="dir-r">→</span> {p.target.name} · {p.target.mount}/{p.target.path}</span>
            <span className={`badge ${p.status === "ready" ? "equal" : p.status === "conflict" ? "different" : "error"}`}>{PLAN_LABEL[p.status]}</span>
          </div>
          <div className="subtle">{p.target.state === "absent" ? "New secret on the target" : `Target v${p.target.version ?? "—"} → v${(p.target.version ?? 0) + 1}`}</div>
          {p.problems.map((m) => <div key={m} className="notice error">{m}</div>)}
          {p.warnings.map((m) => <div key={m} className="notice warn">{m}</div>)}
          <table className="plan-keys"><tbody>
            {p.keys.filter((k) => k.action !== "unchanged").map((k) => (
              <tr key={k.key} className={k.action}>
                <td className="mono">{k.key}</td>
                <td><span className={`action ${k.action}`}>{k.action}</span>{k.type_change && <span className="type-tag">type changes</span>}</td>
                {reveal && <td className="mono vals">{k.action === "update" && <><s>{formatValue(k.target_value, k.type_change)}</s> → </>}{formatValue(k.source_value, k.type_change)}</td>}
              </tr>
            ))}
          </tbody></table>
        </li>
      ))}
    </ul>
  );
}
