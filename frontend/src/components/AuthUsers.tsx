import { Fragment, useEffect, useState } from "react";
import { api } from "../api";
import type { AuthUserMount, AuthUserPair, AuthUsersCompare, AuthUsersList } from "../types";

const show = (v: unknown): string => {
  if (v === undefined || v === null) return "—";
  if (Array.isArray(v)) return v.join(", ") || "—";
  if (typeof v === "boolean") return v ? "yes" : "no";
  if (typeof v === "number" && v > 0 && v % 60 === 0) return v % 3600 === 0 ? `${v / 3600}h` : `${v / 60}m`;
  return String(v);
};
const LABELS: Record<string, string> = {
  token_policies: "Policies", policies: "Policies", groups: "LDAP groups", token_ttl: "Token TTL", token_max_ttl: "Max TTL",
  token_bound_cidrs: "Allowed from", token_no_default_policy: "Without default policy", token_type: "Token type",
  token_period: "Period", token_num_uses: "Uses", token_explicit_max_ttl: "Explicit max TTL",
};
const label = (k: string) => LABELS[k] ?? k;

function Fields({ entry }: { entry: Record<string, unknown> }) {
  const keys = Object.keys(entry).filter((k) => k !== "name" && k !== "error");
  if (entry.error) return <span className="subtle">{String(entry.error)}</span>;
  if (!keys.length) return <span className="subtle">Vault’s defaults</span>;
  return <>{keys.map((k) => <span key={k} className="field-chip"><span className="subtle">{label(k)}</span> <span className="mono">{show(entry[k])}</span></span>)}</>;
}

/** Users of a userpass mount, or an LDAP mount's group and user mappings: read, compare, and
 * (userpass, when the server allows it) create users and reset passwords. */
export function AuthUsers({ connId, mount, label: where, other, canWrite }: {
  connId: string; mount: AuthUserMount; label: string; other?: { conn_id: string; label: string }; canWrite: boolean;
}) {
  const [data, setData] = useState<AuthUsersList | null>(null);
  const [gen, setGen] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [compared, setCompared] = useState<AuthUsersCompare | null>(null);
  const [writing, setWriting] = useState<{ action: "create" | "reset"; username: string } | null>(null);
  useEffect(() => {
    setData(null);
    api.authUsers(connId, mount.path).then(setData).catch((e) => setError(e.message));
  }, [connId, mount.path, gen]);

  async function compare() {
    setError(null);
    try { setCompared(await api.compareAuthUsers({ conn_id: connId, mount: mount.path }, { conn_id: other!.conn_id, mount: mount.path })); }
    catch (e) { setError((e as Error).message); }
  }

  if (!data) return error ? <div className="notice error">{error}</div> : <div className="empty"><span className="spinner" /></div>;
  const userpass = data.type === "userpass";
  return (
    <div className="auth-users">
      <div className="card">
        <div className="field-row">
          <div className="subtle">
            {userpass ? <>Users of <span className="mono">auth/{data.mount}</span> and the tokens they get. Vault never returns passwords.</>
              : <>How <span className="mono">auth/{data.mount}</span> maps directory groups and users to policies. Lockstep reads the mappings, not the directory.</>}
          </div>
          <span className="spacer" />
          {other && <button type="button" className="btn small" onClick={compare}>Compare with {other.label}</button>}
          {userpass && canWrite && <button type="button" className="btn small" onClick={() => setWriting({ action: "create", username: "" })}>＋ New user</button>}
        </div>
        {error && <div className="notice error" role="alert">{error}</div>}
        {data.missing.length > 0 && <div className="notice warn">Missing rights: <span className="mono">{data.missing.join(", ")}</span></div>}
        {data.config && (
          <details className="metadata"><summary>LDAP connection settings</summary>
            <dl>{Object.entries(data.config).map(([k, v]) => <Fragment key={k}><dt className="mono">{k}</dt><dd className="mono">{show(v)}</dd></Fragment>)}</dl>
          </details>
        )}
      </div>

      {!userpass && (
        <section className="card" aria-label="LDAP group mappings">
          <h3>Groups <span className="subtle">({data.groups?.length ?? 0})</span></h3>
          <table className="plan-keys role-fields"><tbody>
            {(data.groups ?? []).map((g) => <tr key={g.name}><td className="mono">{g.name}</td><td><Fields entry={g} /></td></tr>)}
            {!data.groups?.length && <tr><td colSpan={2} className="subtle">No group mappings.</td></tr>}
          </tbody></table>
        </section>
      )}
      <section className="card" aria-label={userpass ? "Userpass users" : "LDAP user mappings"}>
        <h3>{userpass ? "Users" : "User mappings"} <span className="subtle">({data.users.length})</span></h3>
        <table className="plan-keys role-fields"><tbody>
          {data.users.map((u) => (
            <tr key={u.name}>
              <td className="mono">{u.name}</td>
              <td><Fields entry={u} /></td>
              {userpass && canWrite && <td><button type="button" className="btn ghost small" onClick={() => setWriting({ action: "reset", username: u.name })}>Reset password…</button></td>}
            </tr>
          ))}
          {!data.users.length && <tr><td colSpan={3} className="subtle">None.</td></tr>}
        </tbody></table>
      </section>

      {compared && other && <CompareUsers result={compared} left={where} right={other.label} onClose={() => setCompared(null)} />}
      {writing && <UserWrite connId={connId} mount={data.mount} initial={writing} onClose={(done) => { setWriting(null); if (done) setGen(gen + 1); }} />}
    </div>
  );
}

const STATUS: Record<AuthUserPair["status"], [string, string]> = {
  equal: ["Equal", "equal"], different: ["Different", "different"], left_only: ["Left only", "left_only"], right_only: ["Right only", "right_only"],
};

function PairTable({ title, pairs }: { title: string; pairs: AuthUserPair[] }) {
  if (!pairs.length) return null;
  return (
    <>
      <h4>{title}</h4>
      <table className="plan-keys role-fields"><tbody>
        {pairs.map((p) => (
          <tr key={p.name}>
            <td className="mono">{p.name}</td>
            <td><span className={`badge ${STATUS[p.status][1]}`}>{STATUS[p.status][0]}</span></td>
            <td>{p.fields.map((f) => <div key={f.field}><span className="subtle">{label(f.field)}:</span> <span className="mono">{show(f.left)}</span> → <span className="mono">{show(f.right)}</span></div>)}</td>
          </tr>
        ))}
      </tbody></table>
    </>
  );
}

function CompareUsers({ result, left, right, onClose }: { result: AuthUsersCompare; left: string; right: string; onClose: () => void }) {
  const s = result.summary;
  return (
    <section className="card" aria-label="Compared users">
      <div className="field-row">
        <h3>{left} → {right}</h3>
        <span className="subtle">{s.equal} equal · {s.different} different · {s.left_only} left only · {s.right_only} right only</span>
        <span className="spacer" />
        <button type="button" className="btn ghost icon small" aria-label="Close the comparison" onClick={onClose}>✕</button>
      </div>
      {result.config && result.config.length > 0 && (
        <div className="notice warn">Connection settings differ: {result.config.map((c) => <span key={c.field} className="mono"> {c.field} {show(c.left)} → {show(c.right)};</span>)}</div>
      )}
      {(result.missing.left.length > 0 || result.missing.right.length > 0) && (
        <div className="notice warn">Missing rights: <span className="mono">{[...result.missing.left, ...result.missing.right].join(", ")}</span></div>
      )}
      {result.groups && <PairTable title="Groups" pairs={result.groups} />}
      <PairTable title={result.type === "userpass" ? "Users" : "User mappings"} pairs={result.users} />
    </section>
  );
}

function UserWrite({ connId, mount, initial, onClose }: { connId: string; mount: string; initial: { action: "create" | "reset"; username: string };
                                                         onClose: (done: boolean) => void }) {
  const [username, setUsername] = useState(initial.username);
  const [policies, setPolicies] = useState("");
  const [ttl, setTtl] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<{ password?: string } | null>(null);
  const create = initial.action === "create";

  async function go() {
    setBusy(true);
    setError(null);
    try {
      setDone(await api.writeAuthUser({ conn_id: connId, mount, username: username.trim(), action: initial.action,
        ...(password ? { password } : {}),
        ...(create ? { policies: policies.split(",").map((x) => x.trim()).filter(Boolean), ...(ttl.trim() ? { token_ttl: ttl.trim() } : {}) } : {}) }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card" aria-label={create ? "New userpass user" : `Reset ${username}'s password`}>
      <h3>{create ? `New user on auth/${mount}` : <>Reset the password of <span className="mono">{username}</span></>}</h3>
      {done ? (
        <>
          <div className="notice info" role="status">
            {create ? "Created." : "Password reset."}{" "}
            {done.password ? <>The password, shown once: <code className="mono reveal-once">{done.password}</code></> : "It has the password you typed."}
          </div>
          <button type="button" className="btn small" onClick={() => onClose(true)}>Done</button>
        </>
      ) : (
        <>
          {create && (
            <>
              <label className="field"><span>Username</span><input type="text" className="mono" value={username} onChange={(e) => setUsername(e.target.value)} /></label>
              <label className="field"><span>Policies <span className="subtle">(comma separated)</span></span><input type="text" className="mono" value={policies} onChange={(e) => setPolicies(e.target.value)} /></label>
              <label className="field"><span>Token TTL <span className="subtle">(optional, e.g. 1h)</span></span><input type="text" className="mono" value={ttl} onChange={(e) => setTtl(e.target.value)} /></label>
            </>
          )}
          <label className="field"><span>Password <span className="subtle">(leave empty to generate one)</span></span>
            <input type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
          {error && <div className="notice error" role="alert">{error}</div>}
          <div className="field-row">
            <button type="button" className="btn primary small" disabled={busy || !username.trim() || (password.length > 0 && password.length < 8)} onClick={go}>
              {busy && <span className="spinner" />} {create ? "Create user" : "Reset password"}
            </button>
            <button type="button" className="btn ghost small" onClick={() => onClose(false)} disabled={busy}>Cancel</button>
          </div>
        </>
      )}
    </section>
  );
}
