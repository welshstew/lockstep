import { useRef, useState } from "react";
import { api } from "../api";
import type {
  AppConfig, ApplyResult, ChangePlan, ExportProtection, ExportResult, ImportPreview, ImportRules, LoadedFile, Profile, Transform,
} from "../types";
import { FileLoader, FileSummary } from "./FileLoader";
import { formatValue } from "./ValueCell";
import { downloadUndoPlan } from "../plans";

type VaultSide = { conn_id: string; mount: string; prefix: string };
export interface SideOption {
  side: "left" | "right"; label: string; ref: VaultSide | null; exportMode?: "any" | "encrypted" | "off";
  exportProtection?: ExportProtection[]; // how an encrypted export from here may be protected
}

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
      {props.config.read_only
        ? <section className="card transfer-card" aria-label="Import"><h2>Import into a Vault</h2><p className="subtle">This Lockstep server is read-only, so importing is turned off.</p></section>
        : <ImportPanel {...props} />}
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
  const [protect, setProtect] = useState<"key" | "passphrase" | "age" | "none">("key");
  const [pass, setPass] = useState("");
  const [pass2, setPass2] = useState("");
  const [teams, setTeams] = useState<string[]>([]);
  const [ageKeys, setAgeKeys] = useState("");
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<ExportResult | null>(null);
  const [copied, setCopied] = useState(false);
  const source = usable.find((s) => s.side === from) ?? usable[0];
  const mode = source?.exportMode ?? config.export_mode ?? "encrypted";
  // The ways this source allows: a choice it doesn't allow falls back to the first it does
  const allowed: ExportProtection[] = source?.exportProtection ?? config.export_protection ?? ["key", "passphrase", "age", "teams"];
  const ok = (v: "key" | "passphrase" | "age" | "none") => v === "none" ? mode === "any"
    : v === "age" ? allowed.includes("age") || allowed.includes("teams") : allowed.includes(v);
  const teamsOnly = !allowed.includes("age");
  const firstOk = (["key", "passphrase", "age"] as const).find(ok) ?? "key";
  const chosen = (mode === "encrypted" && protect === "none") || !ok(protect) ? firstOk : protect;
  const noWay = mode !== "any" && !(["key", "passphrase", "age"] as const).some(ok);
  const offEverywhere = usable.length > 0 ? usable.every((s) => (s.exportMode ?? config.export_mode) === "off") : config.export_mode === "off";

  if (offEverywhere) {
    return <section className="card transfer-card"><h2>Export</h2><p className="subtle">Exporting is turned off on this Lockstep server.</p></section>;
  }

  async function run() {
    if (!source?.ref) return;
    setBusy(true);
    setError(null);
    setDone(null);
    try {
      const how = chosen;
      setProgress(null);
      const r = await api.exportStream(source.ref, { ignore_paths: lines(paths), ignore_keys: keyRules(keys) }, how !== "none",
        how === "passphrase" ? { passphrase: pass } : how === "age" ? { teams, recipients: teamsOnly ? [] : lines(ageKeys) } : {}, setProgress);
      download(r.filename, r.file);
      setDone(r);
      setPass("");
      setPass2("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
      setProgress(null);
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
          <fieldset className="field protect" disabled={mode === "off"}>
            <legend>Protect the file with</legend>
            {([["key", "A one-time key", "shown once after the export"],
               ["passphrase", "A passphrase", "that you choose and share yourself"],
               ["age", teamsOnly ? "A team's age keys" : "age public keys", "whoever holds a matching age key opens it, in Lockstep or with age -d"],
               ["none", "Nothing (plain text)", mode === "any" ? "" : "this Lockstep server requires encryption"]] as const).map(([v, l, hint]) => (
              <label className="inline-check" key={v}>
                <input type="radio" name="export-protect" value={v} checked={chosen === v}
                       disabled={!ok(v)} onChange={() => setProtect(v)} />
                {l} {hint && <span className="subtle">({hint})</span>}
                {v !== "none" && !ok(v) && <span className="subtle"> (not allowed here)</span>}
              </label>
            ))}
          </fieldset>
          {noWay && <div className="notice warn">This Lockstep server allows no way of protecting an export from {source?.label}: ask an admin.</div>}
          {chosen === "passphrase" && (
            <div className="row">
              <label className="field grow"><span>Passphrase <span className="subtle">(at least 12 characters)</span></span>
                <input type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="new-password" aria-label="Passphrase" /></label>
              <label className="field grow"><span>The same again</span>
                <input type="password" value={pass2} onChange={(e) => setPass2(e.target.value)} autoComplete="new-password" aria-label="Passphrase again" /></label>
            </div>
          )}
          {chosen === "age" && (
            <>
              {(config.export_teams ?? []).length > 0 && (
                <div className="field"><span>Teams</span>
                  {(config.export_teams ?? []).map((t) => (
                    <label className="inline-check" key={t.name}>
                      <input type="checkbox" checked={teams.includes(t.name)}
                             onChange={(e) => setTeams(e.target.checked ? [...teams, t.name] : teams.filter((n) => n !== t.name))} />
                      {t.name} <span className="subtle">({t.keys} key{t.keys === 1 ? "" : "s"})</span>
                    </label>
                  ))}
                </div>
              )}
              {teamsOnly ? (
                (config.export_teams ?? []).length === 0
                  && <div className="notice warn">Exports from here may only be encrypted to a team, and this Lockstep server has none (LOCKSTEP_EXPORT_RECIPIENTS).</div>
              ) : (
                <label className="field"><span>{(config.export_teams ?? []).length ? "More age public keys" : "age public keys"} <span className="subtle">(one per line, age1…)</span></span>
                  <textarea className="mono" rows={2} value={ageKeys} onChange={(e) => setAgeKeys(e.target.value)} aria-label="age public keys" placeholder="age1…" /></label>
              )}
            </>
          )}
          {mode === "off" && <div className="notice info">Exporting from {source?.label} is turned off on this Lockstep server.</div>}
          {chosen === "none" && mode === "any" && (
            <div className="notice warn" role="alert">
              Without encryption the file holds every value in plain text. Anyone who gets the file can read them.
            </div>
          )}
          {error && <div className="notice error" role="alert">{error}</div>}
          <div className="row"><button type="button" className="btn primary" onClick={run}
            disabled={busy || !source || mode === "off" || noWay || (chosen === "passphrase" && (pass.length < 12 || pass !== pass2))
                      || (chosen === "age" && !teams.length && (teamsOnly || !lines(ageKeys).length))}>
            {busy && <span className="spinner" />} Export and download
          </button>
          {busy && progress && progress.total > 0 && (
            <span className="subtle" role="status">Read {progress.done} of {progress.total} secrets…</span>
          )}</div>
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
          {done.scheme === "passphrase" && <div className="subtle">Encrypted with your passphrase. Share it apart from the file.</div>}
          {done.scheme === "age" && (
            <div className="subtle">Encrypted to {(done.file.recipients as string[] | undefined)?.length ?? 0} age key(s). Their holders open it in Lockstep, or with <code>jq -r .ciphertext {done.filename} | age -d -i key.txt</code>.</div>
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
  const [deleteMissing, setDeleteMissing] = useState(false);
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [applied, setApplied] = useState<ApplyResult | null>(null);
  const [undoFile, setUndoFile] = useState<string | null>(null);
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
    try { setPreview(await api.importPreview(file.doc, file.name, rules(), target.ref, reveal, deleteMissing)); }
    catch (e) { setError((e as Error).message); setPreview(null); }
    finally { setBusy(false); }
  }

  async function runImport() {
    if (!file || !target?.ref || !preview) return;
    const ready = preview.plans.filter((p) => p.status === "ready");
    setBusy(true); setError(null);
    setUndoFile(null);
    try {
      setApplied(await api.importApply(file.doc, file.name, rules(), target.ref,
        Object.fromEntries(ready.map((p) => [p.path, p.target.state === "absent" ? null : p.target.version])), deleteMissing));
    } catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }

  const ready = preview?.plans.filter((p) => p.status === "ready") ?? [];
  const writes = preview?.plans.filter((p) => p.action !== "delete") ?? [];
  const counts = writes.reduce<Record<string, number>>((n, p) => ({ ...n, [p.status]: (n[p.status] ?? 0) + 1 }), {});
  const toDelete = ready.filter((p) => p.action === "delete").length;
  const toWrite = ready.length - toDelete;
  const blocked = (preview?.plans ?? []).filter((p) => !["ready", "noop"].includes(p.status)).length;
  const deleted = applied?.results.filter((r) => r.action === "delete" && r.status === "applied").length ?? 0;
  const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;

  return (
    <section className="card transfer-card" aria-label="Import">
      <h2>Import into a Vault</h2>
      <p className="subtle">Write an export into a mount, after leaving out and changing what you choose. Like copying: values are merged into each target secret with check-and-set, and keys only on the target are kept, unless you choose to delete what isn’t in the file.</p>

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

      <h3 className="editor-h">4. Delete what isn’t in the file <span className="subtle">(optional)</span></h3>
      <label className="inline-check">
        <input type="checkbox" checked={deleteMissing} onChange={(e) => { setDeleteMissing(e.target.checked); stale(); }} />
        Make the target match the file: remove keys the file doesn’t have, and delete secrets under the target that aren’t in it
      </label>
      {deleteMissing && (
        <div className="notice warn">
          Secrets are soft-deleted (<span className="mono">vault kv undelete</span> restores them) and removed keys stay in the version history.
          To protect a secret, add it to the file with no data: <span className="mono">{'{"path": "…", "keep": true}'}</span>.
          The preview lists everything before anything changes.
        </div>
      )}

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
            {deleteMissing && `, ${toDelete} to delete`}
            {blocked > 0 && `, ${blocked} can’t be done`}.
            {preview.prepared.kept > 0 && ` ${plural(preview.prepared.kept, "secret")} kept as they are.`}
          </div>
          {toDelete > 0 && <div className="notice warn">{plural(toDelete, "secret")} on the target {toDelete === 1 ? "isn’t" : "aren’t"} in the file and will be deleted.</div>}
          {preview.warnings.map((w) => <div key={w} className="notice warn">{w}</div>)}
          {preview.prepared.problems.map((p) => <div key={p.path} className="notice error">Left out <span className="mono">{p.path}</span>: {p.message}</div>)}
          <PlanList plans={preview.plans.filter((p) => p.status !== "noop")} reveal={reveal} />
          {ready.length > 0 && (
            <div className="row">
              <label className="confirm"><input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
                {toWrite > 0 ? `Write ${plural(toWrite, "secret")}` : ""}{toWrite > 0 && toDelete > 0 ? " and " : ""}{toDelete > 0 ? `${toWrite > 0 ? "delete" : "Delete"} ${plural(toDelete, "secret")}` : ""} {toDelete > 0 ? "in" : "to"} <strong>{target?.label}</strong></label>
              <span className="spacer" />
              <button type="button" className="btn primary" disabled={!confirmed || busy} onClick={runImport}>{busy && <span className="spinner" />} Import</button>
            </div>
          )}
        </div>
      )}
      {applied && (
        <div className="import-preview" role="status">
          <div className={`notice ${applied.summary.applied ? "info" : "warn"}`}>
            {applied.summary.applied - deleted} written{deleted > 0 && `, ${deleted} deleted`}{applied.summary.conflict + applied.summary.denied + applied.summary.error > 0 &&
              `, ${applied.summary.conflict + applied.summary.denied + applied.summary.error} not written`}.
          </div>
          <ul className="plan-list">
            {applied.results.map((r) => (
              <li key={r.path} className="plan"><div className="plan-head"><span className="mono">{r.target}</span>
                <span className={`badge ${r.status === "applied" ? "equal" : r.status === "noop" ? "unknown" : r.status === "conflict" ? "different" : "error"}`}>
                  {r.action === "delete" && r.status === "applied" ? "Deleted" : { applied: "Written", noop: "No change", conflict: "Conflict: not written", denied: "Denied", invalid: "Skipped", error: "Failed", skipped: "Not attempted" }[r.status]}
                </span></div>
                <div className="subtle">{r.status !== "applied" ? r.message : r.action === "delete" ? `v${r.old_version} deleted` : `v${r.old_version ?? "—"} → v${r.new_version} · ${r.keys.join(", ")}`}</div></li>
            ))}
          </ul>
          {applied.summary.applied > 0 && (
            <div className="row">
              <button type="button" className="btn ghost" disabled={Boolean(undoFile)}
                      title="A signed file that puts back what the import wrote and deleted, for you or someone else to apply in Sync plans"
                      onClick={async () => { try { setUndoFile(await downloadUndoPlan(applied.results)); } catch (e) { setError((e as Error).message); } }}>
                {undoFile ? `Undo plan saved as ${undoFile}` : "Make an undo plan"}</button>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

const PLAN_LABEL: Record<string, string> = {
  ready: "Will be written", delete: "Will be deleted", noop: "Already the same", conflict: "Changed", denied: "No permission", invalid: "Can’t import", error: "Error",
};

function PlanList({ plans, reveal }: { plans: ChangePlan[]; reveal: boolean }) {
  if (!plans.length) return <div className="subtle">Nothing to do: the target already matches.</div>;
  return (
    <ul className="plan-list">
      {plans.map((p) => (
        <li key={p.path} className={`plan ${p.status}`}>
          <div className="plan-head">
            <span className="mono"><span className="muted">{p.source.path}</span> <span className="dir-r">→</span> {p.target.name} · {p.target.mount}/{p.target.path}</span>
            <span className={`badge ${p.status === "ready" && p.action !== "delete" ? "equal" : p.status === "conflict" || p.status === "ready" ? "different" : "error"}`}>
              {PLAN_LABEL[p.status === "ready" && p.action === "delete" ? "delete" : p.status]}</span>
          </div>
          <div className="subtle">{p.action === "delete" ? `Not in the file: target v${p.target.version ?? "—"} is soft-deleted`
            : p.target.state === "absent" ? "New secret on the target" : `Target v${p.target.version ?? "—"} → v${(p.target.version ?? 0) + 1}`}</div>
          {p.problems.map((m) => <div key={m} className="notice error">{m}</div>)}
          {p.warnings.map((m) => <div key={m} className="notice warn">{m}</div>)}
          <table className="plan-keys"><tbody>
            {p.keys.filter((k) => k.action !== "unchanged").map((k) => (
              <tr key={k.key} className={k.action}>
                <td className="mono">{k.key}</td>
                <td><span className={`action ${k.action}`}>{k.action}</span>{k.type_change && <span className="type-tag">type changes</span>}</td>
                {reveal && <td className="mono vals">{k.action === "remove" ? <s>{formatValue(k.target_value, false)}</s>
                  : <>{k.action === "update" && <><s>{formatValue(k.target_value, k.type_change)}</s> → </>}{formatValue(k.source_value, k.type_change)}</>}</td>}
              </tr>
            ))}
          </tbody></table>
        </li>
      ))}
    </ul>
  );
}
