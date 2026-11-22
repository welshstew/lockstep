import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { absoluteTime, relativeTime } from "../time";
import type { BrowseSecret } from "../types";
import { formatValue } from "./ValueCell";

/** A secret as YAML: values shown only where `shown` allows, masked otherwise. */
export function toYaml(data: Record<string, unknown>, shown: (k: string) => boolean): string {
  const scalar = (v: unknown): string => {
    if (v === null || v === undefined) return "null";
    if (typeof v === "number" || typeof v === "boolean") return String(v);
    const s = String(v);
    if (s.includes("\n")) return "|\n" + s.split("\n").map((l) => `    ${l}`).join("\n");
    return /^[\w./@:+-][\w ./@:+=-]*$/.test(s) && !/^(true|false|null|yes|no|~|[-+]?\d[\d.e+-]*)$/i.test(s) && !s.endsWith(" ")
      ? s : JSON.stringify(s);
  };
  const block = (v: unknown, indent: string): string => {
    if (Array.isArray(v)) return v.length ? v.map((x) => `\n${indent}- ${typeof x === "object" && x ? block(x, indent + "  ").trimStart() : scalar(x)}`).join("") : " []";
    if (v && typeof v === "object") {
      const e = Object.entries(v as Record<string, unknown>);
      return e.length ? e.map(([k, x]) => `\n${indent}${k}:${typeof x === "object" && x ? block(x, indent + "  ") : ` ${scalar(x)}`}`).join("") : " {}";
    }
    return ` ${scalar(v)}`;
  };
  return Object.entries(data).map(([k, v]) => !shown(k) ? `${k}: "••••••••"`
    : `${k}:${typeof v === "object" && v ? block(v, "  ") : ` ${scalar(v)}`}`).join("\n") + "\n";
}

/** A random value for a new password or key: 24 random bytes, base64url (32 characters). */
export function randomValue(bytes = 24): string {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const sh = (s: string) => (/^[A-Za-z0-9_./:@-]+$/.test(s) ? s : `'${s.replace(/'/g, "'\\''")}'`);

/** CLI, API and Terraform snippets for this secret, with placeholders instead of values. */
export function Snippets({ mount, path, keys, url, pending }: {
  mount: string; path: string; keys: string[]; url?: string | null;
  pending?: { set: string[]; remove: string[] };
}) {
  const [copied, setCopied] = useState<string | null>(null);
  const tf = path.replace(/[^A-Za-z0-9_]/g, "_").replace(/^(\d)/, "_$1");
  const ph = (k: string) => `${k}=<${k}>`;
  const items: [string, string][] = [
    ["Vault CLI: read", `vault kv get -mount=${sh(mount)} ${sh(path)}`],
    ["Vault CLI: write every key", `vault kv put -mount=${sh(mount)} ${sh(path)} ${keys.map((k) => sh(ph(k))).join(" ") || "key=<value>"}`],
  ];
  if (pending && (pending.set.length || pending.remove.length)) {
    if (pending.set.length && !pending.remove.length) {
      items.push(["Vault CLI: this change (patch)", `vault kv patch -mount=${sh(mount)} ${sh(path)} ${pending.set.map((k) => sh(ph(k))).join(" ")}`]);
    } else {
      const kept = keys.filter((k) => !pending.remove.includes(k));
      items.push(["Vault CLI: this change (a full write: keys are removed)",
        `vault kv put -mount=${sh(mount)} ${sh(path)} ${[...new Set([...kept, ...pending.set])].map((k) => sh(ph(k))).join(" ")}`]);
    }
  }
  items.push(
    ["Vault CLI: versions and metadata", `vault kv metadata get -mount=${sh(mount)} ${sh(path)}`],
    ["HTTP API (curl)", `curl -s -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/${mount}/data/${path}"`],
    ["Terraform (hashicorp/vault)", `resource "vault_kv_secret_v2" "${tf}" {\n  mount = "${mount}"\n  name  = "${path}"\n  data_json = jsonencode({\n${keys.map((k) => `    ${JSON.stringify(k)} = var.${k.replace(/[^A-Za-z0-9_]/g, "_")}`).join("\n")}\n  })\n}`],
  );
  const copy = (label: string, text: string) => navigator.clipboard?.writeText(text).then(() => { setCopied(label); setTimeout(() => setCopied(null), 1500); });
  return (
    <div className="snippets">
      <div className="subtle">{url ? <>For <span className="mono">export VAULT_ADDR={url}</span>; values</> : <>With <span className="mono">VAULT_ADDR</span> set; values</>} are placeholders.</div>
      {items.map(([label, text]) => (
        <div key={label} className="snippet">
          <div className="snippet-head"><span>{label}</span>
            <button type="button" className="btn ghost small" onClick={() => copy(label, text)}>{copied === label ? "Copied" : "Copy"}</button></div>
          <pre className="mono">{text}</pre>
        </div>
      ))}
    </div>
  );
}

/** Edit a secret's version settings and custom metadata. */
export function MetadataEditor({ info, conn_id, onSaved, onCancel }: {
  info: BrowseSecret; conn_id: string; onSaved: (message: string) => void; onCancel: () => void;
}) {
  const m = info.metadata!;
  const [maxVersions, setMaxVersions] = useState(String(m.max_versions ?? 0));
  const [cas, setCas] = useState(!!m.cas_required);
  const [after, setAfter] = useState(m.delete_version_after && m.delete_version_after !== "0s" ? m.delete_version_after : "");
  const [rows, setRows] = useState<[string, string][]>(Object.entries(m.custom_metadata ?? {}));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const custom = Object.fromEntries(rows.filter(([k]) => k.trim()).map(([k, v]) => [k.trim(), v]));
      const res = await api.browseMetadata({ conn_id, mount: info.mount, path: info.path, expected_hash: m.hash,
        max_versions: Number(maxVersions) || 0, cas_required: cas, delete_version_after: after.trim() || "0s", custom_metadata: custom });
      if (res.status === "applied") onSaved("Metadata saved.");
      else setError(res.message || res.status);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="metadata-editor">
      <div className="field-row">
        <label className="field inline"><span>Max versions</span>
          <input type="number" min={0} value={maxVersions} aria-label="Max versions" onChange={(e) => setMaxVersions(e.target.value)} /></label>
        <span className="subtle">0 = the mount’s setting</span>
        <label className="inline-check"><input type="checkbox" checked={cas} onChange={(e) => setCas(e.target.checked)} /> Require check-and-set</label>
        <label className="field inline"><span>Delete versions after</span>
          <input type="text" className="mono" placeholder="never (e.g. 720h)" value={after} aria-label="Delete versions after" onChange={(e) => setAfter(e.target.value)} /></label>
      </div>
      <div className="subtle">Custom metadata (labels such as owner or ticket; not secret, readable by anyone who can see the history)</div>
      {rows.map(([k, v], i) => (
        <div key={i} className="rule-row">
          <input type="text" className="mono" aria-label={`Custom metadata ${i + 1} key`} value={k} placeholder="owner"
                 onChange={(e) => setRows(rows.map((r, j) => (j === i ? [e.target.value, r[1]] : r)))} />
          <input type="text" className="mono" aria-label={`Custom metadata ${i + 1} value`} value={v} placeholder="team-payments"
                 onChange={(e) => setRows(rows.map((r, j) => (j === i ? [r[0], e.target.value] : r)))} />
          <button type="button" className="btn ghost icon small" aria-label="Remove" onClick={() => setRows(rows.filter((_, j) => j !== i))}>×</button>
        </div>
      ))}
      <div className="field-row">
        <button type="button" className="btn ghost small" onClick={() => setRows([...rows, ["", ""]])}>＋ Add label</button>
        <span className="spacer" />
        <button type="button" className="btn ghost small" onClick={onCancel}>Cancel</button>
        <button type="button" className="btn primary small" disabled={busy} onClick={save}>{busy && <span className="spinner" />} Save metadata</button>
      </div>
      {error && <div className="notice error">{error}</div>}
    </div>
  );
}

/** Share some values once: a wrapping token that opens a single time, within a short time. */
export function SharePanel({ conn_id, mount, path, keys, version, onClose }: {
  conn_id: string; mount: string; path: string; keys: string[]; version: number | null; onClose: () => void;
}) {
  const [picked, setPicked] = useState<Set<string>>(new Set(keys));
  const [ttl, setTtl] = useState("15m");
  const [result, setResult] = useState<{ token: string; ttl: number; keys: string[] } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function go() {
    setBusy(true);
    setError(null);
    try {
      setResult(await api.browseShare(conn_id, mount, path, picked.size === keys.length ? null : [...picked], ttl, version));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="share-panel" role="region" aria-label="Share once">
      {!result ? (
        <>
          <div><strong>Share once</strong> <span className="subtle">: put values in a one-time token (Vault response wrapping) instead of pasting them into chat or email.
            The token opens once, then never again, and expires if nobody opens it.</span></div>
          <div className="field-row">
            {keys.map((k) => (
              <label key={k} className="inline-check"><input type="checkbox" checked={picked.has(k)}
                     onChange={() => setPicked((p) => { const n = new Set(p); if (n.has(k)) n.delete(k); else n.add(k); return n; })} /> <span className="mono">{k}</span></label>
            ))}
          </div>
          <div className="field-row">
            <label className="field inline"><span>Expires after</span>
              <select value={ttl} onChange={(e) => setTtl(e.target.value)} aria-label="Expires after">
                <option value="5m">5 minutes</option><option value="15m">15 minutes</option><option value="1h">1 hour</option><option value="24h">24 hours</option>
              </select></label>
            <span className="spacer" />
            <button type="button" className="btn ghost small" onClick={onClose}>Cancel</button>
            <button type="button" className="btn primary small" disabled={busy || !picked.size} onClick={go}>{busy && <span className="spinner" />} Create one-time token</button>
          </div>
        </>
      ) : (
        <>
          <div><strong>One-time token</strong> for {result.keys.join(", ")}, valid for {Math.round(result.ttl / 60)} minutes:</div>
          <div className="field-row">
            <code className="mono share-token" aria-label="Wrapping token">{result.token}</code>
            <button type="button" className="btn small" onClick={() => navigator.clipboard?.writeText(result.token).then(() => setCopied(true))}>{copied ? "Copied" : "Copy"}</button>
          </div>
          <div className="subtle">Send it to the person. They open it in Lockstep (<strong>Browse → Open a shared token…</strong>, signed in to the same Vault)
            or with <span className="mono">vault unwrap {"<token>"}</span>. If they say it was already used, someone else opened it: change the values.</div>
          <div className="field-row"><span className="spacer" /><button type="button" className="btn ghost small" onClick={onClose}>Done</button></div>
        </>
      )}
      {error && <div className="notice error">{error}</div>}
    </div>
  );
}

/** Open a token someone shared: look it up first (doesn't use it), then open it once. */
export function UnwrapDialog({ conn_id, label, onClose }: { conn_id: string; label: string; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const [token, setToken] = useState("");
  const [info, setInfo] = useState<{ creation_time: string; creation_ttl: number; creation_path: string } | null>(null);
  const [data, setData] = useState<Record<string, unknown> | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { ref.current?.showModal(); }, []);

  async function run(open: boolean) {
    setBusy(true);
    setError(null);
    try {
      const r = await api.browseUnwrap(conn_id, token.trim(), open);
      setInfo(r.info);
      if (open) setData(r.data ?? {});
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const expires = info ? new Date(new Date(info.creation_time).getTime() + info.creation_ttl * 1000).toISOString() : null;
  return (
    <dialog ref={ref} className="review" onClose={onClose} aria-label="Open a shared token">
      <header className="review-head">
        <h2>Open a shared token</h2>
        <button type="button" className="btn ghost icon small" aria-label="Close" onClick={() => ref.current?.close()}>✕</button>
      </header>
      <div className="review-body">
        <p className="subtle">A one-time token from <strong>Share once</strong> (or <span className="mono">vault write -wrap-ttl</span>), on <strong>{label}</strong>.
          Checking it doesn’t use it up; opening it does, and nobody can open it again.</p>
        <label className="field"><span>Token</span>
          <input type="text" className="mono" value={token} aria-label="Shared token" autoComplete="off" spellCheck={false}
                 onChange={(e) => { setToken(e.target.value); setInfo(null); setData(null); }} /></label>
        {info && !data && (
          <div className="notice info">Created {relativeTime(info.creation_time)} ({absoluteTime(info.creation_time)}), expires {relativeTime(expires)}
            {info.creation_path !== "sys/wrapping/wrap" && <> · made by <span className="mono">{info.creation_path}</span></>}.</div>
        )}
        {data && (
          <table className="plan-keys">
            <tbody>{Object.entries(data).map(([k, v]) => <tr key={k}><td className="mono">{k}</td><td className="mono vals">{formatValue(v)}</td></tr>)}</tbody>
          </table>
        )}
        {data && <div className="subtle">This token is now used up. Copy what you need before closing.</div>}
        {error && <div className="notice error">{error}</div>}
      </div>
      <footer className="review-foot">
        <span className="spacer" />
        {!data && <button type="button" className="btn" disabled={busy || token.trim().length < 10} onClick={() => run(false)}>Check</button>}
        {!data && <button type="button" className="btn primary" disabled={busy || !info} onClick={() => run(true)}>Open (works once)</button>}
        {data && <button type="button" className="btn primary" onClick={() => ref.current?.close()}>Close</button>}
      </footer>
    </dialog>
  );
}
