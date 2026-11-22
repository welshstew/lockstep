import { useEffect, useState } from "react";
import { api } from "../api";
import { absoluteTime, relativeTime } from "../time";
import type { ScanTarget } from "./ExpiryView";
import type { InspectTarget } from "./Inspector";

type Issued = Awaited<ReturnType<typeof api.pkiIssue>>;

function download(text: string, name: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "application/x-pem-file" }));
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Issue a development certificate from a PKI role, to download or store in a KV secret. */
export function PkiIssue({ targets, readOnly, onInspect }: { targets: ScanTarget[]; readOnly: boolean; onInspect: (t: InspectTarget[]) => void }) {
  const [sideId, setSideId] = useState(targets[0]?.side ?? "left");
  const target = targets.find((t) => t.side === sideId) ?? targets[0];
  const [mounts, setMounts] = useState<{ path: string; description: string }[] | null>(null);
  const [mount, setMount] = useState("");
  const [overview, setOverview] = useState<Awaited<ReturnType<typeof api.pkiOverview>> | null>(null);
  const [role, setRole] = useState("");
  const [cn, setCn] = useState("");
  const [sans, setSans] = useState("");
  const [ttl, setTtl] = useState("24h");
  const [store, setStore] = useState(false);
  const [path, setPath] = useState("");
  const [issued, setIssued] = useState<Issued | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!target) return;
    setMounts(null);
    api.pkiMounts(target.conn_id).then((m) => { setMounts(m); setMount(m[0]?.path ?? ""); }).catch(() => setMounts([]));
  }, [target?.conn_id]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (!target || !mount) { setOverview(null); return; }
    api.pkiOverview(target.conn_id, mount).then((o) => { setOverview(o); setRole(o.roles[0]?.name ?? ""); }).catch((e) => setError(e.message));
  }, [target?.conn_id, mount]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    const prefix = target?.prefix.replace(/^\/+|\/+$/g, "");
    if (cn) setPath(`${prefix ? `${prefix}/` : ""}certs/${cn}`);
  }, [cn, target?.prefix]);

  if (!target || !mounts?.length) return null;
  const r = overview?.roles.find((x) => x.name === role);

  async function issue() {
    setBusy(true);
    setError(null);
    try {
      setIssued(await api.pkiIssue({ conn_id: target.conn_id, mount, role, common_name: cn.trim(),
        alt_names: sans.split(",").map((x) => x.trim()).filter(Boolean), ttl, ...(store ? { store: { mount: target.mount, path: path.trim() } } : {}) }));
    } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }

  return (
    <details className="card pki-issue">
      <summary><strong>Issue a development certificate</strong> <span className="subtle">from a PKI role on {target.label.split(" · ")[0]}</span></summary>
      <div className="pki-body">
        <div className="field-row">
          {targets.length > 1 && (
            <div className="segmented small" role="group" aria-label="PKI side">
              {targets.map((t) => <button key={t.side} type="button" aria-pressed={t.side === target.side} onClick={() => setSideId(t.side)}><span className={`side-dot ${t.side}`} /> {t.label.split(" · ")[0]}</button>)}
            </div>
          )}
          <label className="field inline"><span>PKI engine</span>
            <select aria-label="PKI engine" value={mount} onChange={(e) => setMount(e.target.value)}>{mounts.map((m) => <option key={m.path} value={m.path}>{m.path}/</option>)}</select></label>
          <label className="field inline"><span>Role</span>
            <select aria-label="PKI role" value={role} onChange={(e) => setRole(e.target.value)}>{overview?.roles.map((x) => <option key={x.name} value={x.name}>{x.name}</option>)}</select></label>
        </div>
        {overview && overview.issuers.length > 0 && (
          <div className="subtle">Issued by {overview.issuers.map((i) => i.subject ? `${i.subject}${i.not_after ? ` (expires ${relativeTime(i.not_after)})` : ""}` : i.id).join(", ")}.</div>
        )}
        {r && <div className="subtle">Role {r.name}: {r.allowed_domains?.length ? `${r.allow_subdomains ? "subdomains of " : ""}${r.allowed_domains.join(", ")}` : "any name"}
          {r.max_ttl ? ` · up to ${Math.round(r.max_ttl / 3600)} h` : ""}{r.key_type ? ` · ${r.key_type} keys` : ""}</div>}
        <div className="field-row">
          <label className="field inline"><span>Common name</span>
            <input type="text" className="mono" aria-label="Common name" placeholder="api.dev.internal" value={cn} onChange={(e) => setCn(e.target.value)} /></label>
          <label className="field inline"><span>Other names</span>
            <input type="text" className="mono" aria-label="Other names" placeholder="www.dev.internal, …" value={sans} onChange={(e) => setSans(e.target.value)} /></label>
          <label className="field inline"><span>Valid for</span>
            <select aria-label="Valid for" value={ttl} onChange={(e) => setTtl(e.target.value)}>
              {["1h", "8h", "24h", "72h", "720h"].map((x) => <option key={x} value={x}>{x}</option>)}</select></label>
        </div>
        {!readOnly && (
          <div className="field-row">
            <label className="inline-check"><input type="checkbox" checked={store} onChange={(e) => setStore(e.target.checked)} /> Also store it in</label>
            <span className="mono subtle">{target.mount}/</span>
            <input type="text" className="mono" aria-label="Store at path" value={path} disabled={!store} onChange={(e) => setPath(e.target.value)} />
          </div>
        )}
        <div className="field-row"><span className="spacer" />
          <button type="button" className="btn primary" disabled={busy || readOnly || !cn.trim() || !role} onClick={issue}>{busy && <span className="spinner" />} Issue certificate</button>
        </div>
        {readOnly && <div className="subtle">This Lockstep server is read-only, so it can’t issue certificates.</div>}
        {error && <div className="notice error" role="alert">{error}</div>}
        {issued && (
          <div className="share-panel" role="region" aria-label="Issued certificate">
            <div><strong>{issued.info.subject}</strong> <span className="subtle">issued by {issued.info.issuer} · serial {issued.serial}</span></div>
            <div className="subtle">Valid {absoluteTime(issued.info.not_before)} to {absoluteTime(issued.info.not_after)} ({relativeTime(issued.info.not_after)}) · {issued.info.key}
              {issued.info.sans.length ? ` · names: ${issued.info.sans.join(", ")}` : ""}</div>
            <div className="notice warn">The private key is shown only now{issued.stored ? ` (and stored in ${issued.stored.mount}/${issued.stored.path})` : ""}: download what you need before closing.</div>
            <div className="field-row">
              <button type="button" className="btn small" onClick={() => download(issued.certificate + "\n", `${issued.info.subject}.crt.pem`)}>Certificate</button>
              <button type="button" className="btn small" onClick={() => download(issued.private_key + "\n", `${issued.info.subject}.key.pem`)}>Private key</button>
              <button type="button" className="btn small" onClick={() => download(issued.ca_chain.join("\n") + "\n", `${issued.info.subject}.chain.pem`)}>CA chain</button>
              <button type="button" className="btn small" onClick={() => download([issued.certificate, ...issued.ca_chain].join("\n") + "\n", `${issued.info.subject}.fullchain.pem`)}>Full chain</button>
              {issued.stored && <button type="button" className="btn ghost small" onClick={() => onInspect([{ side: target.side, title: `${issued.stored!.path} · certificate`,
                loc: { conn_id: target.conn_id, mount: issued.stored!.mount, path: issued.stored!.path, key: "certificate" } }])}>Inspect</button>}
            </div>
          </div>
        )}
      </div>
    </details>
  );
}
