import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { AuthMount, ExplainResult, PolicyProfile, RoleDraft, RoleFinding, RoleKind, RolePair, RolesList, RoleTemplate } from "../types";
import type { ScanTarget } from "./ExpiryView";
import type { CompareSides } from "./PolicyCompare";
import { AccessApply } from "./AccessApply";
import { saveAccessPlan } from "../accessPlan";
import { ExplainResultView } from "./PoliciesView";
import { AuthUsers } from "./AuthUsers";
import { PolicySelect } from "./PolicySelect";
import type { AuthUserMount } from "../types";

type View = "mount" | "compare" | "new";
const DRAFTS_KEY = "lockstep.roleDrafts";
const PROFILES_KEY = "lockstep.policyProfiles";

// The fields a builder shows, per kind: [field, label, type, help]
type FieldType = "list" | "text" | "duration" | "bool" | "map" | "choice";
const COMMON: [string, string, FieldType, string][] = [
  ["token_policies", "Policies", "list", ""],
  ["token_ttl", "Token TTL", "duration", "e.g. 15m, 1h"],
  ["token_max_ttl", "Max TTL", "duration", "how long tokens can be renewed"],
  ["token_bound_cidrs", "Allowed from (CIDR)", "list", "optional, comma separated"],
  ["token_no_default_policy", "Without the default policy", "bool", ""],
];
const BUILDER: Record<RoleKind, [string, string, FieldType, string][]> = {
  approle: [
    ["secret_id_ttl", "Secret ID TTL", "duration", "how long an issued secret ID works (e.g. 24h)"],
    ["secret_id_num_uses", "Uses per secret ID", "text", "0 = unlimited"],
    ["secret_id_bound_cidrs", "Secret IDs usable from (CIDR)", "list", "optional, comma separated"],
    ["bind_secret_id", "Needs a secret ID", "bool", "off only with CIDR limits"],
    ...COMMON,
  ],
  kubernetes: [
    ["bound_service_account_names", "Service accounts", "list", "comma separated; * means any"],
    ["bound_service_account_namespaces", "Namespaces", "list", "comma separated; * means any"],
    ["audience", "Audience", "text", "e.g. vault: only tokens issued for Vault"],
    ...COMMON,
  ],
  jwt: [
    ["role_type", "Role type", "choice", "jwt: a workload's token; oidc: people signing in through a browser"],
    ["user_claim", "User claim", "text", "the claim that names who logged in"],
    ["bound_audiences", "Audiences", "list", "comma separated"],
    ["bound_subject", "Subject", "text", "optional: the exact sub claim"],
    ["bound_claims", "Bound claims", "map", "one per line: claim=value (several values: a,b)"],
    ["bound_claims_type", "Bound claims match", "choice", "string: exact; glob: * wildcards"],
    ["groups_claim", "Groups claim", "text", "optional"],
    ["allowed_redirect_uris", "Redirect URIs", "list", "OIDC only, comma separated"],
    ["oidc_scopes", "OIDC scopes", "list", "OIDC only"],
    ...COMMON,
  ],
};
const CHOICES: Record<string, string[]> = { role_type: ["jwt", "oidc"], bound_claims_type: ["string", "glob"] };

function load<T>(key: string, fallback: T): T {
  try { const v = localStorage.getItem(key); return v === null ? fallback : JSON.parse(v); } catch { return fallback; }
}
function save(key: string, v: unknown) {
  try { localStorage.setItem(key, JSON.stringify(v)); } catch { /* ignore */ }
}

export const showValue = (v: unknown): string => {
  if (v === undefined || v === null) return "—";
  if (Array.isArray(v)) return v.join(", ");
  if (typeof v === "object") return Object.entries(v as Record<string, unknown>).map(([k, x]) => `${k}=${Array.isArray(x) ? x.join("|") : x}`).join(", ");
  if (typeof v === "boolean") return v ? "yes" : "no";
  return String(v);
};
const duration = (s: unknown) => (typeof s === "number" && s ? (s % 3600 === 0 ? `${s / 3600}h` : s % 60 === 0 ? `${s / 60}m` : `${s}s`) : showValue(s));

function Findings({ items }: { items: RoleFinding[] }) {
  if (!items.length) return <div className="subtle">No findings.</div>;
  return (
    <ul className="build-findings">
      {items.map((f, i) => (
        <li key={i}><span className={`badge ${f.level === "error" ? "error" : f.level === "warn" ? "different" : "unknown"}`}>{f.level}</span> {f.message}</li>
      ))}
    </ul>
  );
}

/** Kubernetes and JWT/OIDC roles: read and explain them, compare them across Vaults, build new ones. */
export function PolicyRoles({ targets, sides, canApply = false, userWrite = false }: { targets: ScanTarget[]; sides: CompareSides; canApply?: boolean; userWrite?: boolean }) {
  const [view, setView] = useState<View>("mount");
  const conns = (["left", "right"] as const).filter((s) => sides[s]).map((s) => ({ side: s, ...sides[s]! }));
  const [sideId, setSideId] = useState<"left" | "right">(conns[0]?.side ?? "left");
  const conn = conns.find((c) => c.side === sideId) ?? conns[0];
  const [mounts, setMounts] = useState<AuthMount[] | null>(null);
  const [userMounts, setUserMounts] = useState<AuthUserMount[]>([]);
  const [mount, setMount] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [granting, setGranting] = useState("");
  const [grantResult, setGrantResult] = useState<{ policy: string; roles: { mount: string; kind: RoleKind; role: string }[]; unreadable_mounts: string[];
                                                   groups: string[]; groups_missing: string[] } | null>(null);

  useEffect(() => {
    if (!conn) return;
    setMounts(null);
    api.authUserMounts(conn.conn_id).then(setUserMounts).catch(() => setUserMounts([]));
    api.roleMounts(conn.conn_id).then((m) => { setMounts(m); setMount((cur) => (cur.startsWith("__") || m.some((x) => x.path === cur) ? cur : m[0]?.path ?? "")); })
      .catch((e) => setError(e.message));
  }, [conn?.conn_id]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!conns.length) return <div className="notice info">Connect a Vault on a side to see its auth roles.</div>;

  return (
    <div className="policy-roles">
      <div className="card policies-head">
        <div className="subtle">
          Kubernetes and JWT/OIDC <strong>roles</strong> decide who gets which policies when they log in. See them in plain terms, what they
          allow on real secrets, what looks risky, how two Vaults differ, and build new ones to hand to an admin.
        </div>
        <div className="field-row">
          <div className="segmented small" role="tablist" aria-label="Roles view">
            {([["mount", "On a mount"], ["compare", "Compare across Vaults"], ["new", "New role"]] as const).map(([id, label]) => (
              <button key={id} type="button" role="tab" aria-selected={view === id} aria-pressed={view === id} onClick={() => setView(id)}>{label}</button>
            ))}
          </div>
          {view !== "compare" && conns.length > 1 && (
            <div className="segmented small" role="group" aria-label="Which side">
              {conns.map((c) => <button key={c.side} type="button" aria-pressed={c.side === conn.side} onClick={() => setSideId(c.side)}>
                <span className={`side-dot ${c.side}`} /> {c.label}</button>)}
            </div>
          )}
          {view === "mount" && mounts && (
            <label className="field inline"><span>Auth mount</span>
              <select value={mount} onChange={(e) => setMount(e.target.value)} aria-label="Auth mount for roles">
                {mounts.map((m) => <option key={m.path} value={m.path}>{m.path}/ ({m.type})</option>)}
                <option value="__groups__">Identity groups</option>
                {userMounts.map((m) => <option key={m.path} value={`__users__:${m.path}`}>{m.path}/ ({m.type === "ldap" ? "LDAP group mappings" : "userpass users"})</option>)}
              </select></label>
          )}
          <span className="spacer" />
          <form className="field-row" onSubmit={async (e) => {
            e.preventDefault();
            if (!granting.trim()) return;
            try { setGrantResult(await api.roleGranting(conn.conn_id, granting.trim())); } catch (err) { setError((err as Error).message); }
          }}>
            <input type="search" className="search mono" placeholder="Which roles grant policy…" aria-label="Which roles grant a policy"
                   value={granting} onChange={(e) => { setGranting(e.target.value); if (!e.target.value) setGrantResult(null); }} />
          </form>
        </div>
        {grantResult && (
          <div className="notice info">
            <strong>{grantResult.policy}</strong> is given by {grantResult.roles.length || grantResult.groups.length
              ? <>{grantResult.roles.map((r) => <span key={`${r.mount}/${r.role}`} className="mono grant">auth/{r.mount}/role/{r.role}</span>)}
                  {grantResult.groups.map((g) => <span key={g} className="mono grant">group {g}</span>)}</>
              : "no Kubernetes or JWT/OIDC role and no identity group"}
            {grantResult.unreadable_mounts.length > 0 && <> · couldn’t read {grantResult.unreadable_mounts.join(", ")}</>}
            {grantResult.groups_missing.length > 0 && <> · couldn’t read the identity groups</>}
            <span className="subtle"> (entities and token roles can grant it too)</span>
          </div>
        )}
      </div>
      {error && <div className="notice error" role="alert">{error}</div>}
      {mounts && mounts.length === 0 && view === "mount" && <div className="notice info">This Vault has no Kubernetes, JWT or OIDC auth mount you can see.</div>}
      {view === "mount" && conn && mount === "__groups__" && <Groups key={conn.conn_id} connId={conn.conn_id} target={targets.find((t) => t.side === conn.side)} canApply={canApply} label={conn.label} />}
      {view === "mount" && conn && mount.startsWith("__users__:") && (() => {
        const um = userMounts.find((m) => `__users__:${m.path}` === mount);
        const other = conns.find((c) => c.side !== conn.side);
        return um ? <AuthUsers key={`${conn.conn_id}|${mount}`} connId={conn.conn_id} mount={um} label={conn.label} canWrite={userWrite}
                               other={other ? { conn_id: other.conn_id, label: other.label } : undefined} /> : null;
      })()}
      {view === "mount" && conn && mount && mount !== "__groups__" && !mount.startsWith("__users__:") && <MountRoles key={`${conn.conn_id}|${mount}`} connId={conn.conn_id} mount={mount}
                                                       target={targets.find((t) => t.side === conn.side)} canApply={canApply} label={conn.label} />}
      {view === "compare" && <CompareRoles sides={sides} />}
      {view === "new" && conn && <NewRole connId={conn.conn_id} mounts={mounts ?? []} canApply={canApply} label={conn.label} />}
    </div>
  );
}

function Groups({ connId, target, canApply, label }: { connId: string; target?: ScanTarget; canApply: boolean; label: string }) {
  const [gen, setGen] = useState(0);
  const [editing, setEditing] = useState<string[] | null>(null);  // the policies being chosen
  const [writing, setWriting] = useState(false);
  const [data, setData] = useState<{ name: string; type?: string; policies?: string[]; members?: string[]; member_groups?: number; alias?: string }[] | null>(null);
  const [missing, setMissing] = useState<string[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [explained, setExplained] = useState<ExplainResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { api.identityGroups(connId).then((d) => { setData(d.groups); setMissing(d.missing); setSelected(d.groups[0]?.name ?? null); }).catch((e) => setError(e.message)); }, [connId, gen]);
  useEffect(() => { setExplained(null); setEditing(null); }, [selected]);
  const g = data?.find((x) => x.name === selected);
  if (error) return <div className="notice error">{error}</div>;
  if (!data) return <div className="empty"><span className="spinner" /></div>;
  return (
    <>
      {missing.length > 0 && <div className="notice warn">Missing rights: {missing.join(", ")}</div>}
      <div className="build-layout">
        <nav className="card build-drafts" aria-label="Groups">
          <div className="tree-head">identity groups <span className="subtle">({data.length})</span></div>
          {data.map((x) => <button key={x.name} type="button" className="tree-row secret" aria-current={x.name === selected} onClick={() => setSelected(x.name)}><span className="mono">{x.name}</span></button>)}
          {!data.length && <div className="tree-note subtle">No groups.</div>}
        </nav>
        {g ? (
          <div className="card build-editor" aria-label={`Group ${g.name}`}>
            <h3 className="mono role-title">group {g.name}</h3>
            <table className="plan-keys role-fields"><tbody>
              <tr><td>Type</td><td>{g.type ?? "internal"}{g.alias ? ` (from the identity provider’s group ${g.alias})` : ""}</td></tr>
              <tr><td>Policies</td><td className={editing !== null ? undefined : "mono"}>{editing !== null
                ? <PolicySelect connId={connId} value={editing} onChange={setEditing} label="Group policies" />
                : g.policies?.join(", ") || "—"}</td></tr>
              <tr><td>Members</td><td className="mono">{g.members?.join(", ") || "—"}{g.member_groups ? ` · ${g.member_groups} member group(s)` : ""}</td></tr>
            </tbody></table>
            {target && (
              <div className="field-row">
                <button type="button" className="btn" onClick={() => api.explainPolicies({ conn_id: connId, mount: target.mount, prefix: target.prefix, identity: { kind: "group", name: g.name } })
                  .then(setExplained).catch((e) => setError(e.message))}>What can its members do on {target.mount}?</button>
              </div>
            )}
            {canApply && (
              <div className="field-row">
                {editing === null
                  ? <button type="button" className="btn ghost small" onClick={() => setEditing([...(g.policies ?? [])])}>Edit policies</button>
                  : <>
                      <button type="button" className="btn primary small" onClick={() => setWriting(true)}>Review…</button>
                      <button type="button" className="btn ghost small" onClick={() => setEditing(null)}>Cancel</button>
                    </>}
              </div>
            )}
          </div>
        ) : <div className="card empty">Choose a group.</div>}
      </div>
      {explained && <ExplainResultView key={selected ?? ""} result={explained} />}
      {writing && g && editing !== null && (
        <AccessApply label={label}
          changes={{ conn_id: connId, group_policies: [{ name: g.name, policies: editing }] }}
          onClose={(done) => { setWriting(false); if (done) { setEditing(null); setGen(gen + 1); } }} />
      )}
    </>
  );
}

function MountRoles({ connId, mount, target, canApply, label }: { connId: string; mount: string; target?: ScanTarget; canApply: boolean; label: string }) {
  const [deleting, setDeleting] = useState<string | null>(null);
  const [issuing, setIssuing] = useState(false);
  const [issued, setIssued] = useState<{ role_id: string; wrapping_token: string; ttl: number } | null>(null);
  const [issueTtl, setIssueTtl] = useState("15m");
  const [gen, setGen] = useState(0);
  const [data, setData] = useState<RolesList | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [explained, setExplained] = useState<ExplainResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api.roles(connId, mount).then((d) => { setData(d); setSelected((s) => (d.roles.some((r) => r.name === s) ? s : d.roles[0]?.name ?? null)); })
      .catch((e) => setError(e.message));
  }, [connId, mount, gen]);
  const role = data?.roles.find((r) => r.name === selected);
  useEffect(() => { setExplained(null); setIssuing(false); setIssued(null); }, [selected]);

  async function explain() {
    if (!target || !selected) return;
    setBusy(true);
    setError(null);
    try { setExplained(await api.roleExplain(connId, mount, selected, target.mount, target.prefix)); }
    catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }
  if (error) return <div className="notice error">{error}</div>;
  if (!data) return <div className="empty"><span className="spinner" /></div>;
  return (
    <>
      <div className="build-layout">
        <nav className="card build-drafts" aria-label="Roles">
          <div className="tree-head">auth/{mount}/role/ <span className="subtle">({data.roles.length})</span></div>
          {data.roles.map((r) => {
            const worst = r.findings?.some((f) => f.level === "error") ? "error" : r.findings?.some((f) => f.level === "warn") ? "different" : null;
            return (
              <button key={r.name} type="button" className="tree-row secret" aria-current={r.name === selected} onClick={() => setSelected(r.name)}>
                <span className="mono">{r.name}</span>{worst && <span className={`badge ${worst}`}>{r.findings!.filter((f) => f.level !== "info").length}</span>}
              </button>
            );
          })}
          {!data.roles.length && <div className="tree-note subtle">No roles here.</div>}
        </nav>
        {role ? (
          <div className="card build-editor" aria-label={`Role ${role.name}`}>
            <h3 className="mono role-title">auth/{mount}/role/{role.name}</h3>
            {role.error ? <div className="notice error">Can’t read it: {role.error}</div> : (
              <>
                <div className="subtle">Logins get: {role.policies!.map((p) => <span key={p} className="mono grant">{p}</span>)}</div>
                <table className="plan-keys role-fields"><tbody>
                  {Object.entries(role.role!).map(([k, v]) => (
                    <tr key={k}><td>{data.labels[k] ?? k}</td><td className="mono">{k.includes("ttl") || k === "token_period" ? duration(v) : showValue(v)}</td></tr>
                  ))}
                </tbody></table>
                <Findings items={role.findings ?? []} />
                {!data.policies_known && <div className="subtle">Your sign-in can’t list policies, so missing policies aren’t flagged.</div>}
                <div className="field-row">
                  {target ? (
                    <button type="button" className="btn" onClick={explain} disabled={busy}>
                      {busy && <span className="spinner" />} What can it do on {target.mount}{target.prefix ? `/${target.prefix.replace(/^\/+|\/+$/g, "")}` : ""}?
                    </button>
                  ) : <span className="subtle">Choose a KV v2 mount on this side to see what the role allows there.</span>}
                  <span className="spacer" />
                  {data.kind === "approle" && canApply && <button type="button" className="btn small" onClick={() => setIssuing(!issuing)}>Issue a secret ID…</button>}
                  {canApply && <button type="button" className="btn ghost small danger" onClick={() => setDeleting(role.name)}>Delete role…</button>}
                </div>
                {issuing && !issued && (
                  <div className="share-panel" role="region" aria-label="Issue a secret ID">
                    <div><strong>Issue a secret ID</strong> <span className="subtle">: it’s handed over wrapped in a one-time token, never in plain text. Give the
                      token and the role ID to the app or pipeline; it unwraps the secret ID once (<span className="mono">vault unwrap</span>) and logs in.</span></div>
                    <div className="field-row">
                      <label className="field inline"><span>Token expires after</span>
                        <select aria-label="Wrapping TTL" value={issueTtl} onChange={(e) => setIssueTtl(e.target.value)}>
                          <option value="5m">5 minutes</option><option value="15m">15 minutes</option><option value="1h">1 hour</option><option value="24h">24 hours</option></select></label>
                      <span className="spacer" />
                      <button type="button" className="btn primary small" onClick={() => api.issueSecretId(connId, mount, role.name, issueTtl).then(setIssued).catch((e) => setError(e.message))}>Issue</button>
                    </div>
                  </div>
                )}
                {issued && (
                  <div className="share-panel" role="region" aria-label="Issued secret ID">
                    <div>Role ID: <code className="mono share-token">{issued.role_id}</code></div>
                    <div>Wrapped secret ID (opens once, within {Math.round(issued.ttl / 60)} minutes): <code className="mono share-token" aria-label="Wrapped secret ID">{issued.wrapping_token}</code></div>
                    <div className="subtle mono">vault unwrap -field=secret_id {"<token>"}  # then: vault write auth/{mount}/login role_id=… secret_id=…</div>
                  </div>
                )}
              </>
            )}
          </div>
        ) : <div className="card empty">Choose a role.</div>}
      </div>
      {explained && <ExplainResultView key={selected ?? ""} result={explained} />}
      {deleting && <AccessApply changes={{ conn_id: connId, delete_roles: [{ mount, name: deleting }] }} label={label}
                                onClose={(done) => { setDeleting(null); if (done) setGen((g) => g + 1); }} />}
    </>
  );
}

function CompareRoles({ sides }: { sides: CompareSides }) {
  const [lm, setLm] = useState<AuthMount[]>([]);
  const [rm, setRm] = useState<AuthMount[]>([]);
  const [left, setLeft] = useState("");
  const [right, setRight] = useState("");
  const [profiles] = useState<PolicyProfile[]>(() => load(PROFILES_KEY, []));
  const [profile, setProfile] = useState("");
  const [result, setResult] = useState<{ pairs: RolePair[]; summary: Record<string, number> } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [onlyDiff, setOnlyDiff] = useState(true);
  useEffect(() => { if (sides.left) api.roleMounts(sides.left.conn_id).then((m) => { setLm(m); setLeft(m[0]?.path ?? ""); }).catch(() => setLm([])); }, [sides.left?.conn_id]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (sides.right) api.roleMounts(sides.right.conn_id).then((m) => { setRm(m); setRight(m.find((x) => x.path === left)?.path ?? m[0]?.path ?? ""); }).catch(() => setRm([])); }, [sides.right?.conn_id]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!sides.left || !sides.right) return <div className="notice info">Connect a Vault on both sides to compare their roles.</div>;

  async function run() {
    setError(null);
    try {
      setResult(await api.roleCompare({ conn_id: sides.left!.conn_id, mount: left }, { conn_id: sides.right!.conn_id, mount: right },
                                      profiles.find((p) => p.name === profile) ?? null));
    } catch (e) { setError((e as Error).message); setResult(null); }
  }
  const shown = (result?.pairs ?? []).filter((p) => !onlyDiff || p.status !== "equal");
  return (
    <div className="card policies-head">
      <div className="field-row">
        <label className="field inline"><span className="scope left">{sides.left.label}</span>
          <select aria-label="Left auth mount" value={left} onChange={(e) => setLeft(e.target.value)}>{lm.map((m) => <option key={m.path} value={m.path}>{m.path}/ ({m.type})</option>)}</select></label>
        <span>⇄</span>
        <label className="field inline"><span className="scope right">{sides.right.label}</span>
          <select aria-label="Right auth mount" value={right} onChange={(e) => setRight(e.target.value)}>{rm.map((m) => <option key={m.path} value={m.path}>{m.path}/ ({m.type})</option>)}</select></label>
        <label className="field inline"><span>Policy profile</span>
          <select aria-label="Role profile" value={profile} onChange={(e) => setProfile(e.target.value)}>
            <option value="">None (pair by name)</option>{profiles.map((p) => <option key={p.name} value={p.name}>{p.name}</option>)}
          </select></label>
        <span className="spacer" />
        <button type="button" className="btn primary" disabled={!left || !right} onClick={run}>Compare roles</button>
        <button type="button" className="btn" onClick={async () => {
          setError(null);
          try {
            const r = await api.compareGroups(sides.left!.conn_id, sides.right!.conn_id, profiles.find((p) => p.name === profile) ?? null);
            setResult({ pairs: r.pairs.map((p) => ({ ...p, mapped: false, note: "", fields: p.fields.map((f) => ({ ...f, label: f.field })) })), summary: r.summary });
          } catch (e) { setError((e as Error).message); }
        }}>Compare identity groups</button>
      </div>
      <div className="subtle">A policy profile from <strong>Compare across Vaults</strong> pairs role names (<span className="mono">*-dev</span> ⇄ <span className="mono">*-prod</span>) and rewrites values (namespaces, claims, policies) before comparing.</div>
      {error && <div className="notice error">{error}</div>}
      {result && (
        <>
          <div className="field-row">
            {Object.entries(result.summary).filter(([, n]) => n).map(([s, n]) => <span key={s} className={`badge ${s === "equal" ? "equal" : s === "different" ? "different" : s}`}>{n} {s.replace("_", " ")}</span>)}
            <label className="inline-check"><input type="checkbox" checked={onlyDiff} onChange={(e) => setOnlyDiff(e.target.checked)} /> Only differences</label>
          </div>
          <ul className="plan-list role-pairs">
            {shown.map((p) => (
              <li key={`${p.left}|${p.right}`} className="plan">
                <div className="plan-head">
                  <span className="mono">{p.left && p.right && p.left !== p.right ? `${p.left} ⇄ ${p.right}` : p.left ?? p.right}</span>
                  <span className={`badge ${p.status === "equal" ? "equal" : p.status === "different" ? "different" : p.status}`}>{p.status.replace("_", " ")}</span>
                </div>
                {p.note && <div className="subtle">{p.note}</div>}
                {p.fields.length > 0 && (
                  <table className="plan-keys rule-diff"><thead><tr><th>Field</th><th className="l">{sides.left!.label}</th><th className="r">{sides.right!.label}</th></tr></thead>
                    <tbody>{p.fields.map((f) => <tr key={f.field} className="changed"><td>{f.label}</td><td className="mono">{showValue(f.left)}</td><td className="mono">{showValue(f.right)}</td></tr>)}</tbody></table>
                )}
              </li>
            ))}
            {!shown.length && <li className="empty">No differences.</li>}
          </ul>
        </>
      )}
    </div>
  );
}

function NewRole({ connId, mounts, canApply, label }: { connId: string; mounts: AuthMount[]; canApply: boolean; label: string }) {
  const [writing, setWriting] = useState(false);
  const [savedPlan, setSavedPlan] = useState<string | null>(null);
  const [templates, setTemplates] = useState<RoleTemplate[]>([]);
  const [drafts, setDraftsState] = useState<RoleDraft[]>(() => load(DRAFTS_KEY, []));
  const [current, setCurrent] = useState(0);
  const [checked, setChecked] = useState<{ role: Record<string, unknown>; policies: string[]; findings: RoleFinding[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [withPolicies, setWithPolicies] = useState(false);
  const setDrafts = (d: RoleDraft[]) => { setDraftsState(d); save(DRAFTS_KEY, d); };
  const draft = drafts[current] ?? null;
  const update = (d: RoleDraft) => setDrafts(drafts.map((x, i) => (i === current ? d : x)));
  useEffect(() => { api.roleTemplates().then(setTemplates).catch(() => setTemplates([])); }, []);
  useEffect(() => {
    if (!draft) { setChecked(null); return; }
    const t = setTimeout(() => api.roleCheck(draft.kind, draft.body, connId).then(setChecked).catch((e) => setError(e.message)), 250);
    return () => clearTimeout(t);
  }, [JSON.stringify(draft), connId]); // eslint-disable-line react-hooks/exhaustive-deps

  const fromTemplate = (t: RoleTemplate) => {
    const m = mounts.find((x) => x.kind === t.kind);
    const d: RoleDraft = { kind: t.kind, mount: m?.path ?? (t.kind === "kubernetes" ? "kubernetes" : "jwt"), name: `new-${t.id}`, body: structuredClone(t.body) };
    setDrafts([...drafts, d]);
    setCurrent(drafts.length);
  };
  const setField = (k: string, type: FieldType, raw: string | boolean) => {
    if (!draft) return;
    const body = { ...draft.body };
    let v: unknown = raw;
    if (type === "list") v = String(raw).split(",").map((x) => x.trim()).filter(Boolean);
    if (type === "map") v = Object.fromEntries(String(raw).split("\n").map((l) => l.split("=")).filter((p) => p[0]?.trim())
      .map(([a, ...b]) => { const val = b.join("=").trim(); return [a.trim(), val.includes(",") ? val.split(",").map((x) => x.trim()) : val]; }));
    if (v === "" || (Array.isArray(v) && !v.length) || (typeof v === "object" && v && !Array.isArray(v) && !Object.keys(v).length)) delete body[k];
    else body[k] = v;
    update({ ...draft, body });
  };
  const fieldText = (k: string, type: FieldType) => {
    const v = draft?.body[k];
    if (v === undefined || v === null) return "";
    if (type === "list") return (v as string[]).join(", ");
    if (type === "map") return Object.entries(v as Record<string, unknown>).map(([a, b]) => `${a}=${Array.isArray(b) ? b.join(",") : b}`).join("\n");
    return String(v);
  };
  const policyDrafts = useMemo(() => load<{ name: string; mount: string; rules: unknown[]; hcl?: string }[]>("lockstep.policyDrafts", []), []);

  async function download() {
    setBusy(true);
    setError(null);
    try {
      const policies = withPolicies ? await Promise.all(policyDrafts.map(async (d) => ({
        name: d.name, text: d.hcl ?? (await api.buildPolicy(d.mount, d.name, d.rules as never)).hcl }))) : [];
      const { blob, name } = await api.policyBundle(policies, null, connId, drafts);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = name; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }

  return (
    <div className="build-layout">
      <nav className="card build-drafts" aria-label="My roles">
        <div className="tree-head">My roles <span className="subtle">(kept in this browser)</span></div>
        {drafts.map((d, i) => (
          <button key={i} type="button" className="tree-row secret" aria-current={i === current} onClick={() => setCurrent(i)}>
            <span className="mono">{d.mount}/{d.name}</span>
          </button>
        ))}
        <div className="tree-note subtle">Start from:</div>
        {templates.map((t) => <button key={t.id} type="button" className="tree-row add" onClick={() => fromTemplate(t)}>＋ {t.label}</button>)}
        {drafts.length > 0 && (
          <div className="tree-note">
            {policyDrafts.length > 0 && <label className="inline-check"><input type="checkbox" checked={withPolicies} onChange={(e) => setWithPolicies(e.target.checked)} /> with my {policyDrafts.length} policies</label>}
            <button type="button" className="btn primary small" disabled={busy} onClick={download}>{busy && <span className="spinner" />} Download for an admin…</button>
            {canApply && <button type="button" className="btn small" onClick={() => setWriting(true)}>Write to {label}…</button>}
            <button type="button" className="btn ghost small" title="A signed file with these roles, for someone with the rights to check and apply in Lockstep"
                    onClick={async () => { try { setSavedPlan(await saveAccessPlan({ conn_id: connId, roles: drafts })); } catch (e) { setError((e as Error).message); } }}>Save as access plan</button>
            {savedPlan && <div className="subtle" role="status">Saved access plan {savedPlan}.</div>}
          </div>
        )}
      </nav>
      {draft ? (
        <div className="card build-editor" aria-label="Role editor">
          <div className="field-row">
            <label className="field inline"><span>Mount</span>
              <input type="text" className="mono" aria-label="Role mount" value={draft.mount} onChange={(e) => update({ ...draft, mount: e.target.value.replace(/^\/+|\/+$/g, "") })} /></label>
            <label className="field inline"><span>Name</span>
              <input type="text" className="mono" aria-label="Role name" value={draft.name} onChange={(e) => update({ ...draft, name: e.target.value })} /></label>
            <span className="subtle">{{ kubernetes: "Kubernetes", jwt: "JWT/OIDC", approle: "AppRole" }[draft.kind]}</span>
            <span className="spacer" />
            <button type="button" className="btn ghost small danger" onClick={() => { setDrafts(drafts.filter((_, i) => i !== current)); setCurrent(Math.max(0, current - 1)); }}>Delete</button>
          </div>
          <table className="plan-keys role-form"><tbody>
            {BUILDER[draft.kind].map(([k, label, type, help]) => (
              <tr key={k}>
                <td>{k === "token_policies" ? <span id={`rf-${k}-label`}>{label}</span> : <label htmlFor={`rf-${k}`}>{label}</label>}</td>
                <td>
                  {k === "token_policies" ? <PolicySelect connId={connId} value={(draft.body[k] as string[] | undefined) ?? []} label="Role policies"
                                                          onChange={(v) => setField(k, type, v.join(","))} />
                    : type === "bool" ? <input id={`rf-${k}`} type="checkbox" checked={!!draft.body[k]} onChange={(e) => setField(k, type, e.target.checked)} />
                    : type === "choice" ? (
                      <select id={`rf-${k}`} value={String(draft.body[k] ?? CHOICES[k][0])} onChange={(e) => setField(k, type, e.target.value)}>
                        {CHOICES[k].map((c) => <option key={c} value={c}>{c}</option>)}</select>)
                    : type === "map" ? <textarea id={`rf-${k}`} className="mono" rows={3} value={fieldText(k, type)} onChange={(e) => setField(k, type, e.target.value)} />
                    : <input id={`rf-${k}`} type="text" className="mono" value={fieldText(k, type)} onChange={(e) => setField(k, type, e.target.value)} />}
                  {help && <div className="subtle">{help}</div>}
                </td>
              </tr>
            ))}
          </tbody></table>
          {checked && <Findings items={checked.findings} />}
          {checked && <pre className="mono hcl-preview" aria-label="Role JSON">{`vault write auth/${draft.mount}/role/${draft.name} @role.json\n\n${JSON.stringify(checked.role, null, 2)}`}</pre>}
          {error && <div className="notice error">{error}</div>}
        </div>
      ) : <div className="card empty">Start a role from a template on the left.</div>}
      {writing && <AccessApply changes={{ conn_id: connId, roles: drafts }} label={label} onClose={() => setWriting(false)} />}
    </div>
  );
}
