import { useEffect, useState } from "react";
import { api } from "../api";

type Overview = Awaited<ReturnType<typeof api.databaseOverview>>;
type Creds = Awaited<ReturnType<typeof api.databaseCreds>>;

const dur = (s?: number) => (!s ? "system default" : s % 3600 === 0 ? `${s / 3600} h` : s % 60 === 0 ? `${s / 60} min` : `${s} s`);

/** Database secrets engine: connections and roles (read-only), and credentials for a dynamic role. */
export function DatabaseTool({ connId, readOnly, allowClipboard }: { connId: string; readOnly: boolean; allowClipboard: boolean }) {
  const [mounts, setMounts] = useState<{ path: string }[] | null>(null);
  const [mount, setMount] = useState("");
  const [ov, setOv] = useState<Overview | null>(null);
  const [role, setRole] = useState("");
  const [creds, setCreds] = useState<Creds | null>(null);
  const [shown, setShown] = useState(false);
  const [revoked, setRevoked] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.databaseMounts(connId).then((m) => { setMounts(m); setMount(m[0]?.path ?? ""); }).catch((e) => setError(e.message));
  }, [connId]);
  useEffect(() => {
    if (!mount) return;
    setOv(null);
    api.databaseOverview(connId, mount).then((o) => { setOv(o); setRole(o.roles[0]?.name ?? ""); }).catch((e) => setError(e.message));
  }, [connId, mount]);

  async function generate() {
    setBusy(true); setError(null); setCreds(null); setShown(false); setRevoked(false);
    try { setCreds(await api.databaseCreds(connId, mount, role)); } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }
  async function revoke() {
    if (!creds) return;
    try { await api.leaseRevoke(connId, [creds.lease_id]); setRevoked(true); } catch (e) { setError((e as Error).message); }
  }

  const r = ov?.roles.find((x) => x.name === role);
  return (
    <div className="card" role="region" aria-label="Database credentials">
      <div className="subtle">
        <strong>Database credentials:</strong> get short-lived credentials from a database role while you develop, and see how the
        engine’s connections and roles are set up. Configuring them stays in the Vault UI or Terraform.
      </div>
      {error && <div className="notice error" role="alert">{error}</div>}
      {mounts && mounts.length === 0 && <div className="notice info">This Vault has no database secrets engine you can see.</div>}
      {mounts && mounts.length > 0 && (
        <div className="field-row">
          <label className="field inline"><span>Database engine</span>
            <select aria-label="Database engine" value={mount} onChange={(e) => setMount(e.target.value)}>{mounts.map((m) => <option key={m.path} value={m.path}>{m.path}/</option>)}</select></label>
          {ov && ov.roles.length > 0 && (
            <label className="field inline"><span>Role</span>
              <select aria-label="Database role" value={role} onChange={(e) => { setRole(e.target.value); setCreds(null); }}>{ov.roles.map((x) => <option key={x.name} value={x.name}>{x.name}</option>)}</select></label>
          )}
        </div>
      )}
      {ov && (
        <>
          {ov.connections.map((c) => (
            <div key={c.name} className="subtle">Connection <strong>{c.name}</strong>{c.plugin_name ? ` · ${c.plugin_name}` : ""}{c.connection_url ? <> · <span className="mono">{c.connection_url}</span></> : ""}
              {c.username ? ` · as ${c.username}` : ""}{c.allowed_roles?.length ? ` · roles ${c.allowed_roles.join(", ")}` : ""}{c.error ? ` · ${c.error}` : ""}</div>
          ))}
          {r && (
            <details>
              <summary>Role {r.name}: database {r.db_name}, {dur(r.default_ttl)} (up to {dur(r.max_ttl)})</summary>
              <pre className="mono share-token">{(r.creation_statements ?? []).join("\n")}</pre>
            </details>
          )}
          {ov.static_roles.length > 0 && (
            <div className="subtle">Static roles: {ov.static_roles.map((s) => `${s.name} (${s.username}, rotated every ${dur(s.rotation_period)})`).join(", ")}</div>
          )}
          {ov.missing.length > 0 && <div className="subtle">Not shown, missing: {ov.missing.join(", ")}.</div>}
          <div className="field-row"><span className="spacer" />
            <button type="button" className="btn primary" disabled={busy || readOnly || !role} onClick={generate}>{busy && <span className="spinner" />} Generate credentials</button>
          </div>
          {readOnly && <div className="subtle">This Lockstep server is read-only, so it can’t generate credentials.</div>}
        </>
      )}
      {creds && (
        <div className="share-panel" role="region" aria-label="Generated credentials">
          <div className="field-row"><strong>{revoked ? "Revoked" : `Valid for ${dur(creds.ttl)}`}</strong>
            <span className="subtle mono">{creds.lease_id}</span><span className="spacer" />
            <button type="button" className="btn ghost small" onClick={() => setShown((s) => !s)}>{shown ? "Hide" : "Show"}</button>
            {!revoked && <button type="button" className="btn ghost small" onClick={revoke}>Revoke now</button>}
          </div>
          {Object.entries(creds.data).map(([k, v]) => (
            <div key={k} className="field-row"><span className="subtle">{k}</span>
              <code className="mono" aria-label={k}>{shown || k === "username" ? v : "••••••••"}</code>
              {allowClipboard && <button type="button" className="btn ghost small" onClick={() => navigator.clipboard?.writeText(v)}>Copy</button>}
            </div>
          ))}
          <div className="notice warn">Shown only now. They stop working when the lease ends; revoke them when you’re done.</div>
        </div>
      )}
    </div>
  );
}
