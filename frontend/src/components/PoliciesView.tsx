import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { ExplainResult, PolicyCell, PolicyColumn, PolicyFinding } from "../types";
import type { ScanTarget } from "./ExpiryView";
import { PolicyBuild } from "./PolicyBuild";
import { PolicyRoles } from "./PolicyRoles";
import { type CompareSides, PolicyCompare } from "./PolicyCompare";
import { AccessApply } from "./AccessApply";

type Source = "token" | "vault" | "paste" | "someone";
const SOURCE_KEY = "lockstep.policySource";
const MODE_KEY = "lockstep.policyMode";

const LEVEL: Record<PolicyFinding["level"], [string, string]> = {
  error: ["Error", "error"], warn: ["Warning", "different"], info: ["Note", "unknown"],
};

const COLUMN_HELP: Record<PolicyColumn, string> = {
  names: "list on <mount>/metadata/<folder>/: the secret shows when its folder is listed",
  read: "read on <mount>/data/<path>: read the values",
  write: "create or update on <mount>/data/<path>",
  delete: "delete on <mount>/data/<path>: soft-delete the latest version",
  destroy: "delete on <mount>/metadata/<path>: every version and the metadata, no undo",
  history: "read on <mount>/metadata/<path>: versions and dates",
};

function loadSource(): Source {
  try {
    const v = localStorage.getItem(SOURCE_KEY);
    return v === "vault" || v === "paste" || v === "someone" ? v : "token";
  } catch { return "token"; }
}

function Mark({ cell }: { cell: PolicyCell }) {
  if (cell.ok) return <span className="pmark ok" aria-label="allowed">✓</span>;
  if (cell.deny) return <span className="pmark deny" aria-label="denied by a deny rule">✗</span>;
  return <span className="pmark no" aria-label="not allowed">·</span>;
}

/** The Policies tab: explain policies on a mount, or compare policies across the two Vaults. */
export function PoliciesView({ targets, sides, canApply = false, userWrite = false }: { targets: ScanTarget[]; sides: CompareSides; canApply?: boolean; userWrite?: boolean }) {
  type Mode = "explain" | "build" | "roles" | "compare";
  const [mode, setModeState] = useState<Mode>(() => {
    try { const v = localStorage.getItem(MODE_KEY); return v === "compare" || v === "build" || v === "roles" ? v : "explain"; } catch { return "explain"; }
  });
  const setMode = (m: Mode) => {
    setModeState(m);
    try { localStorage.setItem(MODE_KEY, m); } catch { /* ignore */ }
  };
  const [plan, setPlan] = useState<Record<string, unknown> | null>(null);
  const [planError, setPlanError] = useState<string | null>(null);
  const connIds = (["left", "right"] as const).flatMap((s) => (sides[s] ? [sides[s]!.conn_id] : []));
  async function openPlan(file: File | undefined) {
    setPlanError(null);
    if (!file) return;
    if (!connIds.length) { setPlanError("Sign in to the plan’s Vault on a side first."); return; }
    try { setPlan(JSON.parse(await file.text())); } catch { setPlanError("That file isn’t an access plan (it isn’t JSON)."); }
  }
  return (
    <section className="policies">
      <div className="segmented policy-mode" role="tablist" aria-label="Policies mode">
        <button type="button" role="tab" aria-selected={mode === "explain"} aria-pressed={mode === "explain"} onClick={() => setMode("explain")}>Explain on a mount</button>
        <button type="button" role="tab" aria-selected={mode === "build"} aria-pressed={mode === "build"} onClick={() => setMode("build")}>Build &amp; suggest</button>
        <button type="button" role="tab" aria-selected={mode === "roles"} aria-pressed={mode === "roles"} onClick={() => setMode("roles")}>Roles</button>
        <button type="button" role="tab" aria-selected={mode === "compare"} aria-pressed={mode === "compare"} onClick={() => setMode("compare")}>Compare across Vaults</button>
      </div>
      <label className="btn ghost small open-plan" title="Check and apply a saved access plan (policy and role changes someone prepared)">
        Open an access plan…
        <input type="file" accept="application/json,.json" aria-label="Open an access plan" hidden
               onChange={(e) => { openPlan(e.target.files?.[0]); e.target.value = ""; }} />
      </label>
      {planError && <div className="notice error" role="alert">{planError}</div>}
      {plan && <AccessApply plan={plan} connIds={connIds} canApply={canApply} onClose={() => setPlan(null)} />}
      {mode === "explain" ? <ExplainPolicies targets={targets} /> : mode === "build" ? <PolicyBuild targets={targets} canApply={canApply} />
        : mode === "roles" ? <PolicyRoles targets={targets} sides={sides} canApply={canApply} userWrite={userWrite} />
        : <PolicyCompare sides={sides} targets={targets} canApply={canApply} />}
    </section>
  );
}

/** Explain Vault ACL policies on one side's KV v2 mount: what they allow on each secret, and why. */
function ExplainPolicies({ targets }: { targets: ScanTarget[] }) {
  const [sideId, setSideId] = useState<"left" | "right">(targets[0]?.side ?? "left");
  const target = targets.find((t) => t.side === sideId) ?? targets[0];
  const [source, setSourceState] = useState<Source>(loadSource);
  const [names, setNames] = useState<string[] | null>(null);
  const [namesError, setNamesError] = useState<string | null>(null);
  const [picked, setPicked] = useState<string[]>([]);
  const [typedNames, setTypedNames] = useState("");
  const [pasteName, setPasteName] = useState("pasted");
  const [pasteText, setPasteText] = useState("");
  const [whoKind, setWhoKind] = useState<"entity" | "group" | "token">("entity");
  const [whoName, setWhoName] = useState("");
  const [result, setResult] = useState<ExplainResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [nameQuery, setNameQuery] = useState("");

  const setSource = (s: Source) => {
    setSourceState(s);
    try { localStorage.setItem(SOURCE_KEY, s); } catch { /* ignore */ }
  };

  // The connection's policy names, when the token may list them
  useEffect(() => {
    if (!target || source !== "vault") return;
    let live = true;
    setNames(null);
    setNamesError(null);
    api.policyNames(target.conn_id)
      .then((r) => { if (live) setNames(r.names); })
      .catch((e) => { if (live) setNamesError(e.message); });
    return () => { live = false; };
  }, [target?.conn_id, source]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { setResult(null); }, [target?.conn_id, target?.mount, target?.prefix]);

  const chosen = source === "vault"
    ? [...picked, ...typedNames.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)]
    : [];
  const canRun = !!target && (source === "token" || (source === "vault" && chosen.length > 0) || (source === "paste" && pasteText.trim()) || (source === "someone" && whoName.trim()));

  async function run() {
    if (!target) return;
    setBusy(true);
    setError(null);
    try {
      setResult(await api.explainPolicies({
        conn_id: target.conn_id, mount: target.mount, prefix: target.prefix,
        ...(source === "token" ? { token: "self" as const } : {}),
        ...(source === "vault" ? { names: [...new Set(chosen)] } : {}),
        ...(source === "paste" ? { pasted: [{ name: pasteName.trim() || "pasted", text: pasteText }] } : {}),
        ...(source === "someone" ? { identity: { kind: whoKind, name: whoName.trim() } } : {}),
      }));
    } catch (e) {
      setError((e as Error).message);
      setResult(null);
    } finally {
      setBusy(false);
    }
  }

  const shownNames = (names ?? []).filter((n) => !nameQuery.trim() || n.includes(nameQuery.trim()));

  if (!targets.length) {
    return <div className="notice info">Choose a connection and a KV v2 mount on at least one side.</div>;
  }

  return (
    <>
      <div className="policies-head card">
        <div className="subtle">
          See what Vault policies allow on every secret of a mount, in plain terms, and which rule decides each answer.
          Nothing is written and no secret values are read: only policy texts and secret names.
        </div>

        <div className="policies-form">
          {targets.length > 1 && (
            <div className="field-row" role="group" aria-label="Which side">
              <span className="subtle">On</span>
              {targets.map((t) => (
                <button key={t.side} type="button" className="chip" aria-pressed={t.side === target.side} onClick={() => setSideId(t.side)}>
                  <span className={`side-dot ${t.side}`} /> {t.label}
                </button>
              ))}
            </div>
          )}
          {targets.length === 1 && <div className="field-row"><span className="subtle">On</span> <span className={`scope ${target.side}`}>{target.label}</span></div>}

          <div className="field-row" role="tablist" aria-label="Which policies">
            <span className="subtle">Explain</span>
            {([["token", "My token’s policies"], ["someone", "Someone else"], ["vault", "Policies in Vault"], ["paste", "Paste a policy"]] as const).map(([id, label]) => (
              <button key={id} type="button" role="tab" className="chip" aria-selected={source === id} aria-pressed={source === id}
                      onClick={() => setSource(id)}>{label}</button>
            ))}
          </div>

          {source === "token" && (
            <p className="subtle">
              Everything your sign-in on this side has, including policies from identity groups. If you may not read some of them, the answers
              come straight from Vault instead, without the deciding rules.
            </p>
          )}
          {source === "vault" && (
            <div className="policy-picker">
              {namesError ? <div className="notice warn">{namesError}</div>
                : names === null ? <div className="subtle"><span className="spinner" /> Listing policies…</div>
                : (
                  <>
                    {names.length > 12 && <input type="search" className="search" placeholder="Find a policy…" value={nameQuery}
                                                  onChange={(e) => setNameQuery(e.target.value)} aria-label="Find a policy" />}
                    <div className="chips-wrap" role="group" aria-label="Policies">
                      {shownNames.map((n) => (
                        <button key={n} type="button" className="chip mono" aria-pressed={picked.includes(n)}
                                onClick={() => setPicked(picked.includes(n) ? picked.filter((x) => x !== n) : [...picked, n])}>{n}</button>
                      ))}
                    </div>
                  </>
                )}
              <label className="field">
                <span className="subtle">{namesError ? "Policy names" : "Or type names"} (comma or space separated)</span>
                <input type="text" className="mono" value={typedNames} onChange={(e) => setTypedNames(e.target.value)} placeholder="payments-dev, default" />
              </label>
            </div>
          )}
          {source === "someone" && (
            <div className="field-row">
              <select aria-label="Who" value={whoKind} onChange={(e) => setWhoKind(e.target.value as typeof whoKind)}>
                <option value="entity">An entity (a person or workload)</option>
                <option value="group">An identity group</option>
                <option value="token">A token (by accessor)</option>
              </select>
              <input type="text" className="mono" aria-label="Name or accessor" placeholder={whoKind === "token" ? "token accessor" : "name"}
                     value={whoName} onChange={(e) => setWhoName(e.target.value)} />
              <span className="subtle">Their own policies plus their groups’ (and parent groups’). Reading them needs rights on <span className="mono">identity/</span>; what’s missing is listed.</span>
            </div>
          )}
          {source === "paste" && (
            <div className="policy-paste">
              <label className="field"><span className="subtle">Name</span>
                <input type="text" className="mono" value={pasteName} onChange={(e) => setPasteName(e.target.value)} /></label>
              <label className="field"><span className="subtle">Policy (HCL or JSON)</span>
                <textarea className="mono" rows={8} value={pasteText} spellCheck={false} aria-label="Policy text"
                          placeholder={'path "app-config/data/payments/*" {\n  capabilities = ["read"]\n}'}
                          onChange={(e) => setPasteText(e.target.value)} /></label>
            </div>
          )}

          <div className="field-row">
            <button type="button" className="btn primary" onClick={run} disabled={!canRun || busy}>
              {busy && <span className="spinner" />} {result ? "Explain again" : "Explain"}
            </button>
          </div>
        </div>
      </div>

      {error && <div className="notice error" role="alert">{error}</div>}

      {result && <ExplainResultView key={JSON.stringify(result.policies) + result.rows.length} result={result} />}
    </>
  );
}

/** The result of an explain: policies read, notices, findings and the grid with "why". */
export function ExplainResultView({ result }: { result: ExplainResult }) {
  const [query, setQuery] = useState("");
  const [allowedOnly, setAllowedOnly] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return result.rows.filter((r) => (!q || r.path.toLowerCase().includes(q))
      && (!allowedOnly || Object.values(r.cells).some((c) => c.ok)));
  }, [result, query, allowedOnly]);
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const r of result.rows) for (const [k, v] of Object.entries(r.cells)) if (v.ok) c[k] = (c[k] ?? 0) + 1;
    return c;
  }, [result]);
  const row = result.rows.find((r) => r.path === selected);
  return (
    <>
      {result.identity && (
        <div className="notice info identity-sources">
          <strong>{result.identity.label}</strong> gets:
          <ul>{result.identity.sources.map((x, i) => <li key={i}>{x.note ?? <>{x.from}: {x.policies.length ? x.policies.map((p) => <span key={p} className="mono grant">{p}</span>) : <span className="subtle">no policies</span>}</>}</li>)}</ul>
        </div>
      )}
      <div className="policy-sources">
        {result.root && <div className="notice warn">This token has the <strong>root</strong> policy: everything is allowed everywhere.</div>}
        {result.evaluation && <span className="subtle eval-note" title="Vault 2.2.2 changed how some paths match (trailing slashes, case-insensitive deny); Lockstep follows the rules of the Vault it reads">
          Matched like {result.vault_version ? `Vault ${result.vault_version}` : "the latest Vault"} ({result.evaluation})</span>}
        {result.policies.map((p) => (
          <span key={`${p.origin}${p.name}`} className={`policy-chip${p.error ? " bad" : ""}`} title={p.error ?? `${p.rules} rules`}>
            <span className="mono">{p.name}</span> <span className="subtle">{p.error ? p.error : `${p.rules} rule${p.rules === 1 ? "" : "s"}`}</span>
          </span>
        ))}
      </div>
      {result.temporary_policy ? (
        <div className={`notice ${result.disagreements?.length ? "warn" : "info"}`} role="status">
          <strong>Tried for real:</strong> Vault answered for a two-minute token holding only this draft
          {result.with_default ? " and the default policy" : ""} (<span className="mono">{result.temporary_policy}</span>,
          removed again).{" "}
          {result.disagreements?.length
            ? <>Lockstep’s reading of the policy differs from Vault’s on {result.disagreements.length} cell{result.disagreements.length === 1 ? "" : "s"}:
                <ul>{result.disagreements.slice(0, 20).map((d) => <li key={d.path + d.column}><span className="mono">{d.path}</span> {d.column}: Vault says {d.vault ? "allowed" : "denied"}</li>)}</ul></>
            : "Lockstep’s reading of the policy agrees with Vault everywhere."}
        </div>
      ) : result.mode === "vault" && (
        <div className="notice info">
          You may not read every policy of your token, so these answers come from Vault itself (<span className="mono">sys/capabilities-self</span>).
          They’re complete, but the rule behind each one can’t be shown.
        </div>
      )}
      {!result.complete && <div className="notice warn">Some policies couldn’t be read or parsed, so this answer may be incomplete.</div>}
      {result.missing.length > 0 && (
        <div className="notice warn">
          <strong>Your sign-in is missing rights</strong> to see everything:
          <ul>{result.missing.map((m) => <li key={m} className="mono">{m}</li>)}</ul>
        </div>
      )}
      {result.truncated && <div className="notice warn">Too many secrets: the listing was cut short. Use a path prefix.</div>}

      {result.findings.length > 0 && (
        <details className="card findings" open={result.findings.some((f) => f.level !== "info")}>
          <summary>
            {result.findings.length} finding{result.findings.length === 1 ? "" : "s"}
            {(["error", "warn", "info"] as const).map((l) => {
              const n = result.findings.filter((f) => f.level === l).length;
              return n ? <span key={l} className={`badge ${LEVEL[l][1]}`}>{n} {LEVEL[l][0].toLowerCase()}{n === 1 ? "" : "s"}</span> : null;
            })}
          </summary>
          <ul>
            {result.findings.map((f, i) => (
              <li key={i} className={`finding ${f.level}`}>
                <span className={`badge ${LEVEL[f.level][1]}`}>{LEVEL[f.level][0]}</span>{" "}
                {f.path && <span className="mono">path "{f.path}"</span>}{" "}
                <span className="subtle">{f.policy}{f.line ? `:${f.line}` : ""}</span>
                <div>{f.message}</div>
              </li>
            ))}
          </ul>
        </details>
      )}

      <div className="results-head">
        <div className="filters">
          <label className="inline-check chip-like"><input type="checkbox" checked={allowedOnly} onChange={(e) => setAllowedOnly(e.target.checked)} /> Only where something is allowed</label>
        </div>
        <input type="search" className="search" placeholder="Filter by path…" value={query} onChange={(e) => setQuery(e.target.value)} />
      </div>

      <div className="policy-layout">
        <div className="card table-wrap">
          <table className="policy-table">
            <thead>
              <tr>
                <th>Secret</th>
                {result.columns.map((c) => (
                  <th key={c.id} title={COLUMN_HELP[c.id]}>{c.label}<div className="subtle">{counts[c.id] ?? 0}</div></th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.path} aria-selected={r.path === selected} onClick={() => setSelected(r.path === selected ? null : r.path)}>
                  <td className="mono">
                    <button type="button" className="link-btn" aria-label={`Why: ${r.path}`}>{r.path}</button>
                  </td>
                  {result.columns.map((c) => <td key={c.id} className="pcell"><Mark cell={r.cells[c.id]} /></td>)}
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && <div className="empty">{result.rows.length ? "Nothing matches these filters." : "No secrets listed here."}</div>}
          <div className="subtle legend">✓ allowed;  · not allowed;  ✗ denied by a deny rule. Click a secret to see why.</div>
        </div>

        {row && (
          <aside className="card why" aria-label="Why">
            <header className="why-head">
              <span className="mono">{result.mount}/{row.path}</span>
              <button type="button" className="btn ghost icon small" aria-label="Close" onClick={() => setSelected(null)}>✕</button>
            </header>
            <ul>
              {result.columns.map((c) => {
                const cell = row.cells[c.id];
                const rule = cell.rule !== null ? result.rules[cell.rule] : null;
                return (
                  <li key={c.id}>
                    <div><Mark cell={cell} /> <strong>{c.label}</strong> <span className="subtle">{COLUMN_HELP[c.id].replace("<mount>", result.mount)}</span></div>
                    {rule ? rule.sources.map((s, i) => (
                      <div key={i} className="why-rule">
                        <span className="mono">path "{s.path}"</span> {"{"} {s.capabilities.join(", ") || "nothing"} {"}"}
                        <span className="subtle"> · {s.policy}{s.line ? `:${s.line}` : ""}</span>
                      </div>
                    )) : (
                      <div className="why-rule subtle">{result.mode === "vault" ? `Vault says: ${cell.caps.join(", ")}` : result.root ? "root policy" : "No rule matches: denied by default."}</div>
                    )}
                    {rule && rule.sources.length > 1 && <div className="subtle">These rules have the same path, so Vault adds them up{rule.capabilities.includes("deny") ? " (and deny wins)" : ""}.</div>}
                  </li>
                );
              })}
            </ul>
          </aside>
        )}
      </div>
    </>
  );
}
