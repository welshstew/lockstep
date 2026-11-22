import { useEffect, useState } from "react";
import { api } from "../api";
import { absoluteTime, relativeTime } from "../time";

type Info = Awaited<ReturnType<typeof api.leaseLookup>>["leases"][number];

/** Browse a Vault's leases by path, see when each expires, renew or revoke. */
export function LeasesTool({ connId, readOnly }: { connId: string; readOnly: boolean }) {
  const [prefix, setPrefix] = useState("");
  const [level, setLevel] = useState<Awaited<ReturnType<typeof api.leases>> | null>(null);
  const [info, setInfo] = useState<Record<string, Info>>({});
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load(p: string) {
    setError(null);
    setPicked(new Set());
    setConfirm("");
    try {
      const l = await api.leases(connId, p);
      setLevel(l);
      setPrefix(l.prefix);
      setInfo({});
      for (let i = 0; i < l.leases.length; i += 100) {  // 100 per request
        const out = await api.leaseLookup(connId, l.leases.slice(i, i + 100));
        setInfo((m) => ({ ...m, ...Object.fromEntries(out.leases.map((x) => [x.id, x])) }));
      }
    } catch (e) { setLevel(null); setError((e as Error).message); }
  }
  useEffect(() => { load(""); }, [connId]); // eslint-disable-line react-hooks/exhaustive-deps

  const crumbs = prefix.split("/").filter(Boolean);
  const phrase = `revoke ${picked.size} lease${picked.size === 1 ? "" : "s"}`;

  async function revoke() {
    setBusy(true);
    try {
      const out = await api.leaseRevoke(connId, [...picked]);
      const failed = out.results.filter((r) => !r.revoked);
      setNotice(`Revoked ${out.revoked} lease${out.revoked === 1 ? "" : "s"}.${failed.length ? ` ${failed.length} failed: ${failed[0].error}` : ""}`);
      await load(prefix);
    } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }
  async function renew(id: string) {
    try {
      const r = await api.leaseRenew(connId, id);
      setNotice(`Renewed ${id.split("/").pop()}: ${Math.round(r.ttl / 60)} minutes left.`);
      const out = await api.leaseLookup(connId, [id]);
      setInfo((m) => ({ ...m, [id]: out.leases[0] }));
    } catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="card" role="region" aria-label="Leases">
      <div className="subtle">
        <strong>Leases</strong> are what Vault hands out with dynamic credentials and tokens. Browse them by path, see when each expires,
        and renew or revoke them. Listing needs <code>sudo</code> on <code>sys/leases/lookup</code>.
      </div>
      <nav className="field-row" aria-label="Lease path">
        <button type="button" className="btn ghost small" onClick={() => load("")}>leases</button>
        {crumbs.map((c, i) => (
          <span key={i}>/ <button type="button" className="btn ghost small" onClick={() => load(crumbs.slice(0, i + 1).join("/") + "/")}>{c}</button></span>
        ))}
      </nav>
      {error && <div className="notice error" role="alert">{error}</div>}
      {notice && <div className="notice info" role="status">{notice}</div>}
      {level && (
        <>
          {level.folders.map((f) => (
            <button key={f} type="button" className="tree-row folder" onClick={() => load(prefix + f)}><span className="mono">{f}</span></button>
          ))}
          {level.leases.length > 0 && (
            <table className="expiry-table">
              <thead><tr><th />{["Lease", "Issued", "Expires", "Renewable", ""].map((h) => <th key={h}>{h}</th>)}</tr></thead>
              <tbody>
                {level.leases.map((id) => {
                  const x = info[id];
                  return (
                    <tr key={id}>
                      <td><input type="checkbox" aria-label={`Select ${id}`} disabled={readOnly} checked={picked.has(id)} onChange={(e) => {
                        const n = new Set(picked); if (e.target.checked) n.add(id); else n.delete(id); setPicked(n);
                      }} /></td>
                      <td className="mono">{id.slice(prefix.length)}</td>
                      <td>{x?.issue_time ? absoluteTime(x.issue_time) : ""}</td>
                      <td>{x?.error ? <span className="subtle">{x.error}</span> : x?.expire_time ? `${relativeTime(x.expire_time)}` : x ? "never" : ""}</td>
                      <td>{x?.renewable ? "yes" : x ? "no" : ""}</td>
                      <td>{x?.renewable && !readOnly && <button type="button" className="btn ghost small" onClick={() => renew(id)}>Renew</button>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
          {level.note && <div className="subtle">{level.note}</div>}
          {level.truncated && <div className="subtle">Only the first 2,000 leases here are shown.</div>}
          {!level.folders.length && !level.leases.length && <div className="subtle">No leases here.</div>}
          {picked.size > 0 && (
            <div className="notice warn">
              Revoking ends the credentials or tokens straight away; apps using them lose access. Type <strong className="mono">{phrase}</strong> to confirm.
              <div className="field-row">
                <input type="text" className="mono" aria-label="Confirm revoke" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
                <button type="button" className="btn danger-solid" disabled={busy || confirm !== phrase} onClick={revoke}>Revoke</button>
              </div>
            </div>
          )}
        </>
      )}
      {readOnly && <div className="subtle">This Lockstep server is read-only: renew and revoke are off.</div>}
    </div>
  );
}
