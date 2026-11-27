import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { ConfigCompare, ConfigPair, PolicyProfile, VaultOverview } from "../types";
import type { CompareSides } from "./PolicyCompare";
import { AccessApply } from "./AccessApply";
import type { AccessChanges } from "../types";

type Source = "mount" | "auth" | "engine";
function copyable(source: Source, p: ConfigPair, to: "left" | "right"): boolean {
  const from = to === "right" ? p.left : p.right;
  if (!from || p.status === "equal" || p.system) return false;
  if (source !== "engine") return p.status === "different";  // tuning: the mount must exist on both sides
  return !!p.copyable;  // the server says which roles and keys it can copy
}

const LABEL: Record<ConfigPair["status"], string> = { equal: "Equal", different: "Different", left_only: "Left only", right_only: "Right only" };
const show = (v: unknown) => (v === undefined || v === null ? "—" : typeof v === "object" ? JSON.stringify(v) : String(v));

function Overview({ o, label, side, other }: { o: VaultOverview; label: string; side: "left" | "right"; other: VaultOverview }) {
  const diff = (k: keyof VaultOverview) => (JSON.stringify(o[k]) !== JSON.stringify(other[k]) ? " differs" : "");
  return (
    <div className={`card overview ${side}`}>
      <div className={`scope ${side}`}>{label}</div>
      <dl>
        <dt>Product</dt><dd className={diff("product")}>{o.product ?? "—"}</dd>
        <dt>Version</dt><dd className={`mono${diff("version")}`}>{o.version ?? "—"}</dd>
        <dt>Cluster</dt><dd className="mono">{o.cluster_name ?? "—"}</dd>
        <dt>Sealed</dt><dd className={diff("sealed")}>{o.sealed === null ? "—" : o.sealed ? "yes" : "no"}</dd>
        <dt>Seal</dt><dd className={`mono${diff("seal_type")}`}>{o.seal_type ?? "—"}</dd>
        <dt>Storage</dt><dd className={`mono${diff("storage_type")}`}>{o.storage_type ?? "—"}</dd>
        <dt>High availability</dt><dd className={diff("ha_enabled")}>{o.ha_enabled ? "yes" : "no"}</dd>
        <dt>Replication</dt><dd className={diff("replication")}>{o.replication === null ? (o.product === "OpenBao" ? "not in OpenBao" : "not available (Community Edition, or no access)")
          : Object.keys(o.replication).length ? Object.entries(o.replication).map(([k, m]) => `${k}: ${m}`).join(", ") : "off"}</dd>
      </dl>
    </div>
  );
}

function Section({ title, rows, sides, source, onCopy }: { title: string; rows: ConfigPair[]; sides: CompareSides; source: Source;
                                                           onCopy?: (source: Source, p: ConfigPair, to: "left" | "right") => void }) {
  const [open, setOpen] = useState<Set<string>>(new Set());
  return (
    <section className="card config-section" aria-label={title}>
      <h3>{title} <span className="subtle">({rows.length})</span></h3>
      {rows.length === 0 && <div className="empty">Nothing to show with these filters.</div>}
      {rows.map((p) => (
        <div key={p.path} className="secret policy-pair">
          <button type="button" className="pair-head" aria-expanded={open.has(p.path)}
                  onClick={() => setOpen((o) => { const n = new Set(o); if (n.has(p.path)) n.delete(p.path); else n.add(p.path); return n; })}>
            <span className="caret">▸</span> <span className="mono pair-name">{p.path}</span>
            {p.right_path && <span className="mono subtle" title="Paired by the configuration profile">⇄ {p.right_path}</span>}
            <span className="subtle">{p.type}</span>
            {p.mapped_to && <span className="subtle" title="The profile maps it here, but the other Vault has nothing at that path">(→ {p.mapped_to} missing)</span>}
            {p.status === "different" && <span className="subtle">{p.fields.length} field{p.fields.length === 1 ? "" : "s"}</span>}
            <span className="spacer" />
            <span className={`badge ${p.status === "equal" ? "equal" : p.status === "different" ? "different" : p.status}`}>{LABEL[p.status]}</span>
          </button>
          {open.has(p.path) && (
            <div className="keys">
              {p.status === "different" ? (
                <table className="plan-keys rule-diff">
                  <thead><tr><th>Setting</th><th className="l">{sides.left?.label}</th><th className="r">{sides.right?.label}</th></tr></thead>
                  <tbody>{p.fields.map((f) => <tr key={f.field} className="changed"><td className="mono">{f.field}</td><td className="mono">{show(f.left)}</td><td className="mono">{show(f.right)}</td></tr>)}</tbody>
                </table>
              ) : (
                <pre className="mono hcl-preview">{JSON.stringify(p.left ?? p.right, null, 2)}</pre>
              )}
              {p.set_aside && p.set_aside.length > 0 && (
                <div className="subtle set-aside" title="These servers return different sets of fields (Vault and OpenBao, or different versions)">
                  Not compared, as only one server has them or one leaves them automatic:{" "}
                  {p.set_aside.map((f, i) => <span key={f.field}>{i > 0 && ", "}<span className="mono">{f.field}</span> ({show(f.left)} / {show(f.right)})</span>)}
                </div>
              )}
              {p.not_compared && p.not_compared.length > 0 && (
                <div className="subtle set-aside" title="Lockstep never compares, shows or copies secret values, even when Vault returns them">
                  Not compared, as they hold secrets:{" "}
                  {p.not_compared.map((f, i) => <span key={f.field}>{i > 0 && ", "}<span className="mono">{f.field}</span>
                    {f.reason !== "sensitive" && " (the name looks secret)"}</span>)}
                </div>
              )}
              {onCopy && (copyable(source, p, "right") || copyable(source, p, "left")) && (
                <div className="field-row">
                  {copyable(source, p, "right") && <button type="button" className="btn small" onClick={() => onCopy(source, p, "right")}>
                    Copy {source === "engine" ? "" : "tuning "}to {sides.right?.label}…</button>}
                  {copyable(source, p, "left") && <button type="button" className="btn small" onClick={() => onCopy(source, p, "left")}>
                    Copy {source === "engine" ? "" : "tuning "}to {sides.left?.label}…</button>}
                </div>
              )}
            </div>
          )}
        </div>
      ))}
    </section>
  );
}

/** Two Vaults' configuration side by side: overview, secrets engines, auth methods. Read-only. */
const PROFILES_KEY = "lockstep.configProfiles";
const loadPersonal = (): PolicyProfile[] => { try { return JSON.parse(localStorage.getItem(PROFILES_KEY) ?? "[]"); } catch { return []; } };
const lines = (t: string) => t.split("\n").map((l) => l.trim()).filter(Boolean);
const pairs = (t: string) => lines(t).map((l) => l.split(/\s*(?:=>|→)\s*/)).filter((x) => x.length === 2 && x[0]);

/** Choose, write and keep configuration profiles: mount paths to pair, values to rewrite, paths to leave out. */
function ProfilePicker({ value, onChange }: { value: PolicyProfile | null; onChange: (p: PolicyProfile | null) => void }) {
  const [shared, setShared] = useState<PolicyProfile[]>([]);
  const [personal, setPersonal] = useState<PolicyProfile[]>(loadPersonal);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState({ name: "", mappings: "", rewrites: "", ignore: "" });
  useEffect(() => { api.configProfiles().then(setShared).catch(() => setShared([])); }, []);
  const all = [...shared.map((p) => ["shared", p] as const), ...personal.map((p) => ["personal", p] as const)];
  const key = value ? `${shared.includes(value) ? "shared" : "personal"}:${value.name}` : "";
  const fromDraft = (): PolicyProfile => ({
    name: draft.name.trim() || "unsaved", mappings: pairs(draft.mappings).map(([left, right]) => ({ left, right })),
    rewrites: pairs(draft.rewrites).map(([find, replace]) => ({ find, replace })), ignore: lines(draft.ignore) });
  const edit = (p: PolicyProfile | null) => {
    setDraft({ name: p?.name ?? "", mappings: (p?.mappings ?? []).map((m) => `${m.left} => ${m.right}`).join("\n"),
               rewrites: (p?.rewrites ?? []).map((r) => `${r.find} => ${r.replace}`).join("\n"), ignore: (p?.ignore ?? []).join("\n") });
    setEditing(true);
  };
  const save = () => {
    const p = fromDraft();
    if (p.name === "unsaved") return;
    const next = [...personal.filter((x) => x.name !== p.name), p];
    setPersonal(next);
    try { localStorage.setItem(PROFILES_KEY, JSON.stringify(next)); } catch { /* ignore */ }
    onChange(p);
    setEditing(false);
  };
  return (
    <div className="config-profile">
      <div className="field-row">
        <label className="field inline"><span>Configuration profile</span>
          <select aria-label="Configuration profile" value={key} onChange={(e) => {
            const hit = all.find(([src, p]) => `${src}:${p.name}` === e.target.value);
            onChange(hit ? hit[1] : null);
          }}>
            <option value="">None: pair by path</option>
            {all.map(([src, p]) => <option key={`${src}:${p.name}`} value={`${src}:${p.name}`}>{p.name}{src === "shared" ? " (shared)" : ""}</option>)}
          </select></label>
        <button type="button" className="btn ghost small" aria-expanded={editing} onClick={() => (editing ? setEditing(false) : edit(value))}>
          {editing ? "Hide rules" : value ? "Edit rules" : "New profile…"}</button>
      </div>
      {editing && (
        <div className="profile-rules config-rules">
          <label className="field"><span>Name</span><input type="text" value={draft.name} placeholder="dev vs prod" onChange={(e) => setDraft({ ...draft, name: e.target.value })} /></label>
          <label className="field"><span>Pair mounts <span className="subtle">(left =&gt; right, one per line, * allowed)</span></span>
            <textarea className="mono" rows={3} aria-label="Mount mappings" placeholder={"kv-dev => kv-prod\nkubernetes-* => k8s-*"} value={draft.mappings}
                      onChange={(e) => setDraft({ ...draft, mappings: e.target.value })} /></label>
          <label className="field"><span>Rewrite left values first <span className="subtle">(find =&gt; replace)</span></span>
            <textarea className="mono" rows={2} aria-label="Value rewrites" placeholder="dev.example.com => prod.example.com" value={draft.rewrites}
                      onChange={(e) => setDraft({ ...draft, rewrites: e.target.value })} /></label>
          <label className="field"><span>Leave out <span className="subtle">(paths, one per line, * allowed)</span></span>
            <textarea className="mono" rows={2} aria-label="Paths to leave out" placeholder="sandbox-*" value={draft.ignore}
                      onChange={(e) => setDraft({ ...draft, ignore: e.target.value })} /></label>
          <div className="field-row">
            <button type="button" className="btn small" onClick={() => { onChange(fromDraft()); }}>Use without saving</button>
            <button type="button" className="btn primary small" disabled={!draft.name.trim()} onClick={save}>Save profile</button>
            {value && personal.some((p) => p.name === value.name) && (
              <button type="button" className="btn ghost small danger" onClick={() => {
                const next = personal.filter((p) => p.name !== value.name);
                setPersonal(next);
                try { localStorage.setItem(PROFILES_KEY, JSON.stringify(next)); } catch { /* ignore */ }
                onChange(null); setEditing(false);
              }}>Delete profile</button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export function ConfigView({ sides, canApply = false }: { sides: CompareSides; canApply?: boolean }) {
  const [profile, setProfile] = useState<PolicyProfile | null>(null);
  const [copying, setCopying] = useState<{ changes: AccessChanges; label: string; notes: string[] } | null>(null);
  async function copy(source: Source, p: ConfigPair, to: "left" | "right") {
    const from = to === "right" ? "left" : "right";
    const fromPath = from === "left" ? p.path : p.right_path ?? p.path;
    const toPath = to === "right" ? p.right_path ?? p.path : p.path;
    setError(null);
    try {
      const r = await api.configCopy({ conn_id: sides[from]!.conn_id, source, path: fromPath, to_path: toPath });
      setCopying({ changes: { conn_id: sides[to]!.conn_id, ...(r.tunes ? { tunes: r.tunes } : {}), ...(r.engine_objects ? { engine_objects: r.engine_objects } : {}) },
                   label: sides[to]!.label, notes: r.notes });
    } catch (e) { setError((e as Error).message); }
  }
  const [result, setResult] = useState<ConfigCompare | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [onlyDiff, setOnlyDiff] = useState(true);
  const [system, setSystem] = useState(false);
  const [query, setQuery] = useState("");
  const filter = useMemo(() => (rows: ConfigPair[]) => rows.filter((p) => (system || !p.system) && (!onlyDiff || p.status !== "equal")
    && (!query.trim() || p.path.includes(query.trim()) || (p.type ?? "").includes(query.trim()))), [onlyDiff, system, query]);

  if (!sides.left || !sides.right) return <section className="config"><div className="notice info">Connect a Vault on both sides to compare their configuration.</div></section>;
  async function run() {
    setBusy(true);
    setError(null);
    try { setResult(await api.configCompare(sides.left!.conn_id, sides.right!.conn_id, profile)); }
    catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }
  return (
    <section className="config">
      <div className="card policies-head">
        <div className="subtle">Compares the two Vaults’ secrets engines and auth methods: type, plugin version, tuning (TTLs, listing visibility, audit settings),
          options, each auth method’s configuration, the roles and keys of engines both have (PKI, database, Transit, SSH, Kubernetes, AWS, Azure, GCP, LDAP, and others such as TOTP, Consul and Nomad compared generically),
          and system settings: audit devices, password policies, token roles, quotas, MFA, registered plugins and identity entities, by name. Secrets are left out. A configuration profile pairs mounts whose paths differ. Read-only. On the command line: <span className="mono">lockstep config compare</span>.</div>
        <div className="field-row"><ProfilePicker value={profile} onChange={setProfile} /><span className="spacer" />
          <button type="button" className="btn primary" onClick={run} disabled={busy}>{busy && <span className="spinner" />} {result ? "Compare again" : "Compare configuration"}</button>
        </div>
      </div>
      {error && <div className="notice error" role="alert">{error}</div>}
      {result && (
        <>
          <div className="overview-row">
            <Overview o={result.overview.left} other={result.overview.right} label={sides.left.label} side="left" />
            <Overview o={result.overview.right} other={result.overview.left} label={sides.right.label} side="right" />
          </div>
          {(["left", "right"] as const).map((s) => result.missing[s].length > 0 && (
            <div key={s} className="notice warn"><span className={`scope ${s}`}>{sides[s]!.label}</span> is missing rights: {result.missing[s].join(", ")}.
              {result.missing[s].some((m) => m.includes("sys/mounts")) && " The engines shown come from the UI listing, without their tuning."}</div>
          ))}
          {(["left", "right"] as const).flatMap((s) => (result.warnings?.[s] ?? []).map((w) => (
            <div key={`w${s}${w}`} className="notice warn config-warning"><span className={`scope ${s}`}>{sides[s]!.label}</span> {w}</div>
          )))}
          {(["left", "right"] as const).map((s) => (result.truncated?.[s] ?? []).length > 0 && (
            <div key={`t${s}`} className="notice info"><span className={`scope ${s}`}>{sides[s]!.label}</span> has more than Lockstep compares at once, so these lists were cut off: {result.truncated[s].join("; ")}.</div>
          ))}
          <div className="results-head">
            <div className="filters">
              {Object.entries(result.summary).filter(([, n]) => n).map(([s, n]) => <span key={s} className={`badge ${s === "equal" ? "equal" : s === "different" ? "different" : s}`}>{n} {LABEL[s as ConfigPair["status"]].toLowerCase()}</span>)}
              <label className="inline-check chip-like"><input type="checkbox" checked={onlyDiff} onChange={(e) => setOnlyDiff(e.target.checked)} /> Only differences</label>
              <label className="inline-check chip-like"><input type="checkbox" checked={system} onChange={(e) => setSystem(e.target.checked)} /> Built-in mounts</label>
            </div>
            <input type="search" className="search" placeholder="Filter by path or type…" value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          {copying && copying.notes.length > 0 && <div className="notice warn" role="status">{copying.notes.join(" ")}</div>}
          <Section title="Secrets engines" rows={filter(result.mounts)} sides={sides} source="mount" onCopy={canApply ? copy : undefined} />
          <Section title="Auth methods" rows={filter(result.auth)} sides={sides} source="auth" onCopy={canApply ? copy : undefined} />
          <Section title="Engine roles and keys" rows={filter(result.engines ?? [])} sides={sides} source="engine" onCopy={canApply ? copy : undefined} />
          <Section title="System settings" rows={filter(result.system ?? [])} sides={sides} source="mount" />
          {copying && <AccessApply changes={copying.changes} label={copying.label}
                                   onClose={(done) => { setCopying(null); if (done) run(); }} />}
        </>
      )}
    </section>
  );
}
