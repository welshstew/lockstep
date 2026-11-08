import { absoluteTime } from "../time";
import type { CertInfo, Chain } from "../types";

const STATUS: Record<CertInfo["status"], [string, string]> = {
  valid: ["Valid", "equal"],
  expiring: ["Expiring soon", "different"],
  expired: ["Expired", "error"],
  not_yet_valid: ["Not yet valid", "error"],
};

const VERDICT: Record<Chain["verdict"], [string, string]> = {
  trusted: ["Chain trusted", "equal"],
  untrusted_root: ["Untrusted root", "different"],
  incomplete: ["Chain incomplete", "different"],
  invalid: ["Chain invalid", "error"],
};

function days(c: CertInfo) {
  if (c.status === "expired") return `expired ${Math.abs(c.days_left)} day${Math.abs(c.days_left) === 1 ? "" : "s"} ago`;
  if (c.status === "not_yet_valid") return `valid from ${absoluteTime(c.not_before)}`;
  return `${c.days_left} day${c.days_left === 1 ? "" : "s"} left`;
}

function Check({ ok, label }: { ok: boolean | null; label: string }) {
  if (ok === null) return null;
  return <span className={`check ${ok ? "ok" : "bad"}`}>{ok ? "✓" : "✗"} {label}</span>;
}

export function ChainView({ chain, onTrust }: { chain: Chain; onTrust?: (sha256: string) => void }) {
  const [label, tone] = VERDICT[chain.verdict];
  const last = chain.links[chain.links.length - 1];
  return (
    <div className="chain">
      <div className={`chain-verdict ${tone}`}>
        <span className={`badge ${tone}`}>{label}</span>
        <span>{chain.reason}</span>
        {chain.verdict === "untrusted_root" && last?.self_signed && onTrust && (
          <button type="button" className="btn small" onClick={() => onTrust(last.sha256)}
                  title="Treat this root as trusted for this check only. Nothing is saved.">
            Trust this root
          </button>
        )}
      </div>
      <ol className="chain-links">
        {chain.links.map((l, i) => (
          <li key={l.sha256 + i} className={l.problem ? "bad" : ""}>
            <span className="chain-subject">{l.subject}</span>
            <span className="chain-checks">
              <span className={`badge ${STATUS[l.status][1]}`}>{STATUS[l.status][0]}</span>
              {l.anchor && <span className="badge equal">Trust anchor</span>}
              {l.self_signed && !l.anchor && <span className="badge unknown">Self-signed</span>}
              <Check ok={l.signature_ok} label="signed by next" />
              <Check ok={l.issuer_is_ca} label="issuer is a CA" />
            </span>
            {l.problem && <span className="chain-problem">{l.problem}</span>}
          </li>
        ))}
      </ol>
    </div>
  );
}

export function CertCard({ cert, chain, onTrust }: { cert: CertInfo; chain?: Chain; onTrust?: (sha256: string) => void }) {
  const [label, tone] = STATUS[cert.status];
  return (
    <div className="cert-card">
      <div className="cert-status">
        <span className={`badge ${tone}`}>{label}</span>
        <span className="muted">{days(cert)}</span>
        {cert.is_ca && <span className="badge unknown">CA{cert.path_length != null ? ` · path ≤ ${cert.path_length}` : ""}</span>}
      </div>
      {chain && <ChainView chain={chain} onTrust={onTrust} />}
      <dl className="cert-fields">
        <dt>Subject</dt><dd className="mono">{cert.subject}</dd>
        <dt>Issuer</dt><dd className="mono">{cert.issuer}</dd>
        <dt>Valid</dt><dd>{absoluteTime(cert.not_before)} → {absoluteTime(cert.not_after)}</dd>
        {cert.sans.length > 0 && <><dt>Names</dt><dd className="mono">{cert.sans.join(", ")}</dd></>}
        <dt>Key</dt><dd>{cert.public_key} · signed with {cert.signature_algorithm}</dd>
        {cert.key_usage.length > 0 && <><dt>Key usage</dt><dd>{cert.key_usage.join(", ")}</dd></>}
        {cert.extended_key_usage.length > 0 && <><dt>Extended</dt><dd>{cert.extended_key_usage.join(", ")}</dd></>}
        <dt>Serial</dt><dd className="mono">{cert.serial}</dd>
        <dt>SHA-256</dt><dd className="mono fp">{cert.sha256.match(/.{2}/g)?.join(":")}</dd>
      </dl>
    </div>
  );
}

/** Field-by-field comparison of the first certificate on each side. */
export function CertDiff({ left, right }: { left: CertInfo; right: CertInfo }) {
  const rows: [string, string, string][] = [
    ["Subject", left.subject, right.subject],
    ["Issuer", left.issuer, right.issuer],
    ["Serial", left.serial, right.serial],
    ["Expires", absoluteTime(left.not_after), absoluteTime(right.not_after)],
    ["Names", left.sans.join(", "), right.sans.join(", ")],
    ["Key", left.public_key, right.public_key],
    ["Status", STATUS[left.status][0], STATUS[right.status][0]],
    ["SHA-256", left.sha256.slice(0, 16) + "…", right.sha256.slice(0, 16) + "…"],
  ];
  return (
    <table className="cert-diff">
      <thead><tr><th /><th className="l">Left</th><th className="r">Right</th></tr></thead>
      <tbody>
        {rows.map(([name, l, r]) => (
          <tr key={name} className={l === r ? "same" : "diff"}>
            <th>{name}</th><td className="mono">{l || "—"}</td><td className="mono">{r || "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
