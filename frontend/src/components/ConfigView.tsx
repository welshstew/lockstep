import { useMemo, useState } from "react";
import { api } from "../api";
import type { ConfigCompare, ConfigPair, VaultOverview } from "../types";
import type { CompareSides } from "./PolicyCompare";

const LABEL: Record<ConfigPair["status"], string> = { equal: "Equal", different: "Different", left_only: "Left only", right_only: "Right only" };
const show = (v: unknown) => (v === undefined || v === null ? "—" : typeof v === "object" ? JSON.stringify(v) : String(v));

function Overview({ o, label, side, other }: { o: VaultOverview; label: string; side: "left" | "right"; other: VaultOverview }) {
  const diff = (k: keyof VaultOverview) => (JSON.stringify(o[k]) !== JSON.stringify(other[k]) ? " differs" : "");
  return (
    <div className={`card overview ${side}`}>
      <div className={`scope ${side}`}>{label}</div>
      <dl>
        <dt>Version</dt><dd className={`mono${diff("version")}`}>{o.version ?? "—"}</dd>
        <dt>Cluster</dt><dd className="mono">{o.cluster_name ?? "—"}</dd>
        <dt>Sealed</dt><dd className={diff("sealed")}>{o.sealed === null ? "—" : o.sealed ? "yes" : "no"}</dd>
        <dt>Seal</dt><dd className={`mono${diff("seal_type")}`}>{o.seal_type ?? "—"}</dd>
        <dt>Storage</dt><dd className={`mono${diff("storage_type")}`}>{o.storage_type ?? "—"}</dd>
        <dt>High availability</dt><dd className={diff("ha_enabled")}>{o.ha_enabled ? "yes" : "no"}</dd>
        <dt>Replication</dt><dd className={diff("replication")}>{o.replication === null ? "not available (Community Edition, or no access)"
          : Object.keys(o.replication).length ? Object.entries(o.replication).map(([k, m]) => `${k}: ${m}`).join(", ") : "off"}</dd>
      </dl>
    </div>
  );
}

function Section({ title, rows, sides }: { title: string; rows: ConfigPair[]; sides: CompareSides }) {
  const [open, setOpen] = useState<Set<string>>(new Set());
  return (
    <section className="card config-section" aria-label={title}>
      <h3>{title} <span className="subtle">({rows.length})</span></h3>
      {rows.length === 0 && <div className="empty">Nothing to show with these filters.</div>}
      {rows.map((p) => (
        <div key={p.path} className="secret policy-pair">
          <button type="button" className="pair-head" aria-expanded={open.has(p.path)}
                  onClick={() => setOpen((o) => { const n = new Set(o); if (n.has(p.path)) n.delete(p.path); else n.add(p.path); return n; })}>
            <span className="caret">▸</span> <span className="mono pair-name">{p.path}</span> <span className="subtle">{p.type}</span>
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
            </div>
          )}
        </div>
      ))}
    </section>
  );
}

/** Two Vaults' configuration side by side: overview, secrets engines, auth methods. Read-only. */
export function ConfigView({ sides }: { sides: CompareSides }) {
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
    try { setResult(await api.configCompare(sides.left!.conn_id, sides.right!.conn_id)); }
    catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }
  return (
    <section className="config">
      <div className="card policies-head">
        <div className="subtle">Compares the two Vaults’ secrets engines and auth methods: type, plugin version, tuning (TTLs, listing visibility, audit settings),
          options, each auth method’s configuration, and the roles and keys of engines both have (PKI, database, Transit, SSH, Kubernetes, AWS), with secrets left out. Read-only. On the command line: <span className="mono">lockstep config compare</span>.</div>
        <div className="field-row"><span className="spacer" />
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
          <div className="results-head">
            <div className="filters">
              {Object.entries(result.summary).filter(([, n]) => n).map(([s, n]) => <span key={s} className={`badge ${s === "equal" ? "equal" : s === "different" ? "different" : s}`}>{n} {LABEL[s as ConfigPair["status"]].toLowerCase()}</span>)}
              <label className="inline-check chip-like"><input type="checkbox" checked={onlyDiff} onChange={(e) => setOnlyDiff(e.target.checked)} /> Only differences</label>
              <label className="inline-check chip-like"><input type="checkbox" checked={system} onChange={(e) => setSystem(e.target.checked)} /> Built-in mounts</label>
            </div>
            <input type="search" className="search" placeholder="Filter by path or type…" value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          <Section title="Secrets engines" rows={filter(result.mounts)} sides={sides} />
          <Section title="Auth methods" rows={filter(result.auth)} sides={sides} />
          <Section title="Engine roles and keys" rows={filter(result.engines ?? [])} sides={sides} />
        </>
      )}
    </section>
  );
}
