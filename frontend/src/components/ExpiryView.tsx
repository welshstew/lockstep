import { useMemo, useState } from "react";
import { api } from "../api";
import { absoluteTime, relativeTime } from "../time";
import type { CertRow, ExpiryResult } from "../types";
import type { InspectTarget } from "./Inspector";

export interface ScanTarget {
  side: "left" | "right";
  conn_id: string;
  mount: string;
  prefix: string;
  label: string;
}

type Window = "expired" | "30" | "90" | "later" | "all";

const STATUS: Record<CertRow["status"], [string, string]> = {
  expired: ["Expired", "error"],
  not_yet_valid: ["Not yet valid", "error"],
  expiring: ["Expiring", "different"],
  valid: ["Valid", "equal"],
};

/** Exclusive buckets: each certificate counts (and filters) in exactly one tile. */
function bucket(r: CertRow): Exclude<Window, "all"> {
  if (r.status === "expired" || r.status === "not_yet_valid") return "expired";
  if (r.days_left <= 30) return "30";
  if (r.days_left <= 90) return "90";
  return "later";
}

function csv(rows: CertRow[], labels: Record<string, string>): string {
  const cols = ["side", "vault", "mount", "path", "key", "container", "alias", "subject", "issuer_cn", "not_before",
                "not_after", "days_left", "status", "is_ca", "self_signed", "opened_with", "serial", "sha256"] as const;
  const esc = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  return [cols.join(","), ...rows.map((r) => cols.map((c) => esc(c === "vault" ? labels[r.side] : r[c as keyof CertRow])).join(","))].join("\n");
}

export function ExpiryView({ targets, onInspect }: { targets: ScanTarget[]; onInspect: (t: InspectTarget[]) => void }) {
  const [result, setResult] = useState<ExpiryResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [win, setWin] = useState<Window>("all");
  const [side, setSide] = useState<"both" | "left" | "right">("both");
  const [hideCa, setHideCa] = useState(false);
  const [query, setQuery] = useState("");
  const labels = Object.fromEntries(targets.map((t) => [t.side, t.label]));

  async function scan() {
    setBusy(true);
    setError(null);
    try {
      setResult(await api.expiry(targets.map(({ side, conn_id, mount, prefix }) => ({ side, conn_id, mount, prefix }))));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const counts = useMemo(() => {
    const c = { expired: 0, "30": 0, "90": 0, later: 0 };
    for (const r of result?.certificates ?? []) c[bucket(r)]++;
    return c;
  }, [result]);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (result?.certificates ?? []).filter((r) => {
      if (win !== "all" && bucket(r) !== win) return false;
      if (side !== "both" && r.side !== side) return false;
      if (hideCa && r.is_ca) return false;
      return !q || [r.subject, r.issuer_cn, r.path, r.key].some((x) => x.toLowerCase().includes(q));
    });
  }, [result, win, side, hideCa, query]);

  const inspect = (r: CertRow) => onInspect([{ side: r.side, title: `${labels[r.side]} · ${r.key}`,
                                               loc: { conn_id: r.conn_id, mount: r.mount, path: r.path, key: r.key } }]);

  return (
    <section className="expiry">
      <div className="expiry-head">
        <div className="subtle">
          Scans {targets.map((t) => <span key={t.side} className={`scope ${t.side}`}>{t.label}</span>)} for certificates in every
          value, including PEM bundles, DER, base64, PKCS#12 and Java keystores. Keystores are opened only with a password stored
          next to them in the same secret. Only certificate details come back, never secret values.
        </div>
        <button type="button" className="btn primary big" onClick={scan} disabled={busy || targets.length === 0}>
          {busy && <span className="spinner" />} {result ? "Scan again" : "Scan for certificates"}
        </button>
      </div>
      {targets.length === 0 && <div className="notice info">Choose a connection and a KV v2 mount on at least one side.</div>}
      {error && <div className="notice error" role="alert">{error}</div>}

      {result && (
        <>
          <div className="tiles">
            {([["expired", "Expired or not yet valid", counts.expired, "error"], ["30", "Within 30 days", counts["30"], "different"],
               ["90", "In 31–90 days", counts["90"], "different"], ["later", "Later", counts.later, "equal"]] as const).map(([w, label, n, tone]) => (
              <button key={w} type="button" className={`tile ${tone}`} aria-pressed={win === w} onClick={() => setWin(win === w ? "all" : w)}>
                <span className="tile-n">{n}</span><span className="tile-l">{label}</span>
              </button>
            ))}
            <button type="button" className="tile neutral" aria-pressed={win === "all"} onClick={() => setWin("all")}>
              <span className="tile-n">{result.certificates.length}</span><span className="tile-l">All certificates</span>
            </button>
          </div>
          {result.sides.map((s) => (s.denied.length > 0 || s.truncated || s.unreadable > 0) && (
            <div key={s.side} className="notice warn">
              {labels[s.side]}: {s.denied.length > 0 && `couldn't list ${s.denied.join(", ")}. `}
              {s.unreadable > 0 && `${s.unreadable} secret(s) couldn't be read. `}
              {s.truncated && "Too many secrets: the scan was cut short; use a path prefix."}
            </div>
          ))}

          <div className="results-head">
            <div className="filters">
              {(["both", "left", "right"] as const).filter((x) => x === "both" || targets.some((t) => t.side === x)).map((x) => (
                <button key={x} type="button" className="chip" aria-pressed={side === x} onClick={() => setSide(x)}>
                  {x === "both" ? "Both sides" : labels[x]}
                </button>
              ))}
              <label className="inline-check chip-like"><input type="checkbox" checked={hideCa} onChange={(e) => setHideCa(e.target.checked)} /> Hide CA certificates</label>
            </div>
            <div className="row">
              <input type="search" className="search" placeholder="Filter by name, path or key…" value={query} onChange={(e) => setQuery(e.target.value)} />
              <button type="button" className="btn small" disabled={!shown.length} onClick={() => {
                const url = URL.createObjectURL(new Blob([csv(shown, labels)], { type: "text/csv" }));
                const a = document.createElement("a");
                a.href = url; a.download = "lockstep-certificate-expiry.csv"; a.click();
                setTimeout(() => URL.revokeObjectURL(url), 1000);
              }}>Export CSV</button>
            </div>
          </div>

          <div className="card table-wrap">
            <table className="expiry-table">
              <thead><tr><th>Status</th><th>Expires</th><th>Certificate</th><th>Where</th><th /></tr></thead>
              <tbody>
                {shown.map((r, i) => (
                  <tr key={`${r.side}${r.path}${r.key}${r.sha256}${i}`}>
                    <td><span className={`badge ${STATUS[r.status][1]}`}>{r.status === "valid" && r.days_left <= 90 ? "Soon" : STATUS[r.status][0]}</span></td>
                    <td title={absoluteTime(r.not_after)}>
                      <div>{new Date(r.not_after).toLocaleDateString(undefined, { dateStyle: "medium" })}</div>
                      <div className="subtle">{r.status === "not_yet_valid" ? `valid from ${relativeTime(r.not_before)}` : relativeTime(r.not_after)}</div>
                    </td>
                    <td>
                      <div className="cert-name">{r.subject_cn}{r.is_ca && <span className="badge unknown">CA</span>}{r.self_signed && <span className="badge unknown">self-signed</span>}</div>
                      <div className="subtle">issued by {r.issuer_cn}</div>
                    </td>
                    <td>
                      <div><span className={`side-dot ${r.side}`} title={labels[r.side]} /> <span className="mono">{r.path}</span> · <span className="mono">{r.key}</span></div>
                      <div className="subtle">{r.container}{r.alias ? ` · alias ${r.alias}` : ""}{r.opened_with ? ` · opened with “${r.opened_with}”` : ""}</div>
                    </td>
                    <td><button type="button" className="btn ghost small" onClick={() => inspect(r)}>Inspect</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
            {shown.length === 0 && <div className="empty">{result.certificates.length ? "No certificates match these filters." : "No certificates found."}</div>}
          </div>

          {result.locked.length > 0 && (
            <details className="locked">
              <summary>{result.locked.length} keystore{result.locked.length === 1 ? "" : "s"} not fully checked</summary>
              <ul>
                {result.locked.map((l, i) => (
                  <li key={i}><span className={`side-dot ${l.side}`} /> <span className="mono">{l.path} · {l.key}</span> <span className="subtle">({l.container}): {l.reason}</span></li>
                ))}
              </ul>
            </details>
          )}
        </>
      )}
    </section>
  );
}
