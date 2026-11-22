import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { AccessCompareResult, PolicyCompareResult, PolicyPair, PolicyPairStatus, PolicyProfile } from "../types";
import { AccessApply } from "./AccessApply";
import type { ScanTarget } from "./ExpiryView";

const PERSONAL_KEY = "lockstep.policyProfiles";
const EMPTY: PolicyProfile = { name: "", mappings: [], rewrites: [], ignore: ["root"] };
type Filter = "changes" | "all" | PolicyPairStatus;

const LABEL: Record<PolicyPairStatus, string> = {
  equal: "Equal", different: "Different", left_only: "Left only", right_only: "Right only", error: "Error",
};
const CHANGES: PolicyPairStatus[] = ["different", "left_only", "right_only", "error"];

function loadPersonal(): PolicyProfile[] {
  try {
    const v = JSON.parse(localStorage.getItem(PERSONAL_KEY) ?? "[]");
    return Array.isArray(v) ? v : [];
  } catch { return []; }
}

function savePersonal(list: PolicyProfile[]) {
  try { localStorage.setItem(PERSONAL_KEY, JSON.stringify(list)); } catch { /* ignore */ }
}

const caps = (c: string[] | null) => (c === null ? "—" : c.length ? c.join(", ") : "nothing");

export interface CompareSides {
  left?: { conn_id: string; label: string };
  right?: { conn_id: string; label: string };
}

/** Every policy on two Vaults, compared by meaning, paired and rewritten by a policy profile. */
export function PolicyCompare({ sides, targets, canApply = false }: { sides: CompareSides; targets: ScanTarget[]; canApply?: boolean }) {
  const [shared, setShared] = useState<PolicyProfile[]>([]);
  const [personal, setPersonal] = useState<PolicyProfile[]>(loadPersonal);
  const [profile, setProfile] = useState<PolicyProfile>(EMPTY);
  const [chosen, setChosen] = useState("");
  const [editing, setEditing] = useState(false);
  const [result, setResult] = useState<PolicyCompareResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>("changes");
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState<Set<string>>(new Set());

  useEffect(() => { api.policyProfiles().then(setShared).catch(() => setShared([])); }, []);
  useEffect(() => { setResult(null); }, [sides.left?.conn_id, sides.right?.conn_id]);

  const choose = (key: string) => {
    setChosen(key);
    const [src, name] = [key.slice(0, key.indexOf(":")), key.slice(key.indexOf(":") + 1)];
    const p = (src === "shared" ? shared : personal).find((x) => x.name === name);
    setProfile(p ? structuredClone(p) : EMPTY);
  };

  const active = profile.mappings.length || profile.rewrites.length || profile.ignore.join() !== "root" ? profile : null;

  async function run() {
    if (!sides.left || !sides.right) return;
    setBusy(true);
    setError(null);
    try {
      setResult(await api.comparePolicies(sides.left.conn_id, sides.right.conn_id,
        active ? { ...profile, name: profile.name || "unsaved",
                   mappings: profile.mappings.filter((m) => m.left && m.right),
                   rewrites: profile.rewrites.filter((r) => r.find) } : null));
      setOpen(new Set());
    } catch (e) {
      setError((e as Error).message);
      setResult(null);
    } finally {
      setBusy(false);
    }
  }

  const saveProfile = () => {
    const name = profile.name.trim();
    if (!name) { setError("Give the profile a name to save it."); return; }
    const next = [...personal.filter((p) => p.name !== name), { ...profile, name }];
    setPersonal(next);
    savePersonal(next);
    setChosen(`personal:${name}`);
    setError(null);
  };
  const deleteProfile = () => {
    const next = personal.filter((p) => p.name !== profile.name);
    setPersonal(next);
    savePersonal(next);
    setChosen("");
    setProfile(EMPTY);
  };
  const exportProfiles = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify({ profiles: personal }, null, 2)], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url; a.download = "lockstep-policy-profiles.json"; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  const importProfiles = async (f: File) => {
    try {
      const raw = JSON.parse(await f.text());
      const list = (Array.isArray(raw) ? raw : raw.profiles ?? [raw]) as PolicyProfile[];
      const clean = list.filter((p) => p && typeof p.name === "string").map((p) => ({
        name: p.name, description: p.description ?? "", mappings: p.mappings ?? [], rewrites: p.rewrites ?? [], ignore: p.ignore ?? ["root"],
      }));
      if (!clean.length) throw new Error("no profiles in that file");
      const names = new Set(clean.map((p) => p.name));
      const next = [...personal.filter((p) => !names.has(p.name)), ...clean];
      setPersonal(next);
      savePersonal(next);
      choose(`personal:${clean[0].name}`);
    } catch (e) {
      setError(`Couldn't import: ${(e as Error).message}`);
    }
  };

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (result?.pairs ?? []).filter((p) =>
      (filter === "all" || (filter === "changes" ? CHANGES.includes(p.status) : p.status === filter))
      && (!q || [p.left, p.right].some((n) => n?.toLowerCase().includes(q))));
  }, [result, filter, query]);

  if (!sides.left || !sides.right) {
    return <div className="notice info">Connect a Vault on both sides to compare their policies.</div>;
  }
  const key = (p: PolicyPair) => `${p.left ?? ""}|${p.right ?? ""}`;
  const toggle = (k: string) => setOpen((o) => { const n = new Set(o); if (n.has(k)) n.delete(k); else n.add(k); return n; });

  return (
    <div className="policy-compare">
      <div className="card policies-head">
        <div className="subtle">
          Compares every ACL policy on <span className="scope left">{sides.left.label}</span> with
          {" "}<span className="scope right">{sides.right.label}</span> by meaning: comments, whitespace, rule order and how capabilities
          are listed don’t count. A <strong>policy profile</strong> pairs names that differ between the Vaults and rewrites paths first.
        </div>
        <div className="field-row">
          <label className="field inline">
            <span>Policy profile</span>
            <select value={chosen} onChange={(e) => choose(e.target.value)} aria-label="Policy profile">
              <option value="">{active ? "Unsaved rules" : "None (pair by name)"}</option>
              {shared.length > 0 && <optgroup label="Shared">{shared.map((p) => <option key={p.name} value={`shared:${p.name}`}>{p.name}</option>)}</optgroup>}
              {personal.length > 0 && <optgroup label="Mine">{personal.map((p) => <option key={p.name} value={`personal:${p.name}`}>{p.name}</option>)}</optgroup>}
            </select>
          </label>
          <button type="button" className="btn ghost small" aria-expanded={editing} onClick={() => setEditing(!editing)}>
            {editing ? "Hide rules" : chosen ? "Edit rules" : "New profile…"}
          </button>
          <span className="spacer" />
          <button type="button" className="btn primary" onClick={run} disabled={busy}>
            {busy && <span className="spinner" />} {result ? "Compare again" : "Compare policies"}
          </button>
        </div>

        {editing && (
          <div className="profile-rules">
            <label className="field"><span>Name</span>
              <input type="text" value={profile.name} onChange={(e) => setProfile({ ...profile, name: e.target.value })} placeholder="dev vs prod" /></label>
            <div className="rule-group">
              <div className="subtle">Pair names <span className="subtle">(* matches anything; both sides need the same number of *)</span></div>
              {profile.mappings.map((m, i) => (
                <div key={i} className="rule-row">
                  <input type="text" className="mono" aria-label={`Mapping ${i + 1} left`} placeholder="*-dev" value={m.left}
                         onChange={(e) => setProfile({ ...profile, mappings: profile.mappings.map((x, j) => j === i ? { ...x, left: e.target.value } : x) })} />
                  <span>⇄</span>
                  <input type="text" className="mono" aria-label={`Mapping ${i + 1} right`} placeholder="*-prod" value={m.right}
                         onChange={(e) => setProfile({ ...profile, mappings: profile.mappings.map((x, j) => j === i ? { ...x, right: e.target.value } : x) })} />
                  <button type="button" className="btn ghost icon small" aria-label="Remove mapping"
                          onClick={() => setProfile({ ...profile, mappings: profile.mappings.filter((_, j) => j !== i) })}>×</button>
                </div>
              ))}
              <button type="button" className="btn small" onClick={() => setProfile({ ...profile, mappings: [...profile.mappings, { left: "", right: "" }] })}>＋ Add mapping</button>
            </div>
            <div className="rule-group">
              <div className="subtle">Rewrite the left policies’ paths before comparing</div>
              {profile.rewrites.map((r, i) => (
                <div key={i} className="rule-row">
                  <input type="text" className="mono" aria-label={`Rewrite ${i + 1} find`} placeholder="/dev/" value={r.find}
                         onChange={(e) => setProfile({ ...profile, rewrites: profile.rewrites.map((x, j) => j === i ? { ...x, find: e.target.value } : x) })} />
                  <span>→</span>
                  <input type="text" className="mono" aria-label={`Rewrite ${i + 1} replace`} placeholder="/prod/" value={r.replace}
                         onChange={(e) => setProfile({ ...profile, rewrites: profile.rewrites.map((x, j) => j === i ? { ...x, replace: e.target.value } : x) })} />
                  <button type="button" className="btn ghost icon small" aria-label="Remove rewrite"
                          onClick={() => setProfile({ ...profile, rewrites: profile.rewrites.filter((_, j) => j !== i) })}>×</button>
                </div>
              ))}
              <button type="button" className="btn small" onClick={() => setProfile({ ...profile, rewrites: [...profile.rewrites, { find: "", replace: "" }] })}>＋ Add rewrite</button>
            </div>
            <label className="field"><span>Leave out <span className="subtle">(policy names or * patterns, comma separated)</span></span>
              <input type="text" className="mono" aria-label="Leave out" value={profile.ignore.join(", ")}
                     onChange={(e) => setProfile({ ...profile, ignore: e.target.value.split(",").map((x) => x.trim()).filter(Boolean) })} /></label>
            <div className="field-row">
              <button type="button" className="btn small" onClick={saveProfile}>Save to my profiles</button>
              {chosen.startsWith("personal:") && <button type="button" className="btn ghost small danger" onClick={deleteProfile}>Delete</button>}
              <span className="spacer" />
              <label className="btn ghost small file-btn">Import…<input type="file" accept="application/json,.json" hidden
                     onChange={(e) => { const f = e.target.files?.[0]; if (f) importProfiles(f); e.target.value = ""; }} /></label>
              <button type="button" className="btn ghost small" disabled={!personal.length} onClick={exportProfiles}>Export mine</button>
            </div>
          </div>
        )}
      </div>

      {error && <div className="notice error" role="alert">{error}</div>}

      {result && (
        <>
          {(["left", "right"] as const).map((s) => result[s].error && (
            <div key={s} className="notice warn"><span className={`scope ${s}`}>{sides[s]!.label}</span>: {result[s].error}</div>
          ))}
          {result.missing.length > 0 && (
            <div className="notice warn">
              <strong>Your sign-ins are missing rights</strong> to see every policy:
              <ul>{result.missing.slice(0, 20).map((m) => <li key={m} className="mono">{m}</li>)}</ul>
              {result.missing.length > 20 && <div className="subtle">…and {result.missing.length - 20} more</div>}
            </div>
          )}
          <div className="results-head">
            <div className="filters" role="group" aria-label="Filter policies">
              {([["changes", "All changes", CHANGES.reduce((n, s) => n + result.summary[s], 0)],
                 ...(["different", "left_only", "right_only", "error", "equal"] as PolicyPairStatus[])
                   .filter((s) => result.summary[s] > 0).map((s) => [s, LABEL[s], result.summary[s]]),
                 ["all", "Everything", result.pairs.length]] as [Filter, string, number][]).map(([id, label, n]) => (
                <button key={id} type="button" className="chip" aria-pressed={filter === id} onClick={() => setFilter(id)}>
                  {label} <span className="n">{n}</span>
                </button>
              ))}
            </div>
            <input type="search" className="search" placeholder="Filter by name…" value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>

          <div className="card">
            {shown.length === 0 && <div className="empty">{filter === "changes" ? "No differences: the policies match." : "Nothing matches this filter."}</div>}
            {shown.map((p) => (
              <PairRow key={key(p)} pair={p} open={open.has(key(p))} onToggle={() => toggle(key(p))} sides={sides} targets={targets}
                       canApply={canApply} rewrites={active ? profile.rewrites.filter((r) => r.find) : []} onCopied={run} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function PairRow({ pair: p, open, onToggle, sides, targets, canApply, rewrites, onCopied }: {
  pair: PolicyPair; open: boolean; onToggle: () => void; sides: CompareSides; targets: ScanTarget[];
  canApply: boolean; rewrites: { find: string; replace: string }[]; onCopied: () => void;
}) {
  const [copying, setCopying] = useState<"left_to_right" | "right_to_left" | null>(null);
  // Copying applies the profile's rewrites (left → right), or the same rewrites backwards
  const copied = (d: "left_to_right" | "right_to_left") => {
    let text = (d === "left_to_right" ? p.left_text : p.right_text) ?? "";
    for (const r of rewrites) text = d === "left_to_right" ? text.split(r.find).join(r.replace) : r.replace ? text.split(r.replace).join(r.find) : text;
    return { name: (d === "left_to_right" ? p.right ?? p.left : p.left ?? p.right)!, text };
  };
  const [showText, setShowText] = useState(false);
  const [access, setAccess] = useState<AccessCompareResult | null>(null);
  const [accessBusy, setAccessBusy] = useState(false);
  const [accessError, setAccessError] = useState<string | null>(null);
  const [allRows, setAllRows] = useState(false);
  const lt = targets.find((t) => t.side === "left");
  const rt = targets.find((t) => t.side === "right");
  const tone = p.status === "equal" ? "equal" : p.status === "different" ? "different" : p.status === "error" ? "error" : p.status;
  const name = p.left && p.right && p.left !== p.right ? <>{p.left} <span className="subtle">⇄</span> {p.right}</> : (p.left ?? p.right);

  async function compareAccess() {
    if (!lt || !rt || !p.left || !p.right) return;
    setAccessBusy(true);
    setAccessError(null);
    try {
      setAccess(await api.compareAccess({ conn_id: lt.conn_id, mount: lt.mount, prefix: lt.prefix, name: p.left },
                                        { conn_id: rt.conn_id, mount: rt.mount, prefix: rt.prefix, name: p.right }));
    } catch (e) {
      setAccessError((e as Error).message);
    } finally {
      setAccessBusy(false);
    }
  }

  const accessRows = access ? access.rows.filter((r) => allRows || r.differs) : [];
  return (
    <div className="secret policy-pair">
      <div className="secret-head-row">
        <button type="button" className="pair-head" aria-expanded={open} onClick={onToggle}>
          <span className="caret">▸</span>
          <span className="mono pair-name">{name}</span>
          {p.mapped && <span className="badge unknown" title="Paired by the profile's name mapping">mapped</span>}
          {p.formatting && <span className="subtle">formatting differs</span>}
          <span className="spacer" />
          <span className={`badge ${tone}`}>{LABEL[p.status]}</span>
        </button>
      </div>
      {open && (
        <div className="keys">
          {p.note && <div className={`notice ${p.status === "error" ? "error" : "info"}`}>{p.note}</div>}
          {p.rules.length > 0 && (
            <table className="plan-keys rule-diff">
              <thead><tr><th>Path</th><th className="l">{sides.left?.label}</th><th className="r">{sides.right?.label}</th></tr></thead>
              <tbody>
                {p.rules.map((r) => (
                  <tr key={r.path} className={r.change}>
                    <td className="mono">{r.path}</td>
                    <td className="mono">{caps(r.left)}{r.left_extra && <span className="type-tag" title={JSON.stringify(r.left_extra)}>+ fields</span>}</td>
                    <td className="mono">{caps(r.right)}{r.right_extra && <span className="type-tag" title={JSON.stringify(r.right_extra)}>+ fields</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <div className="secret-actions">
            {(p.left_text !== null || p.right_text !== null) && (
              <button type="button" className="btn ghost small" aria-pressed={showText} onClick={() => setShowText(!showText)}>
                {showText ? "Hide text" : "Show text"}
              </button>
            )}
            {p.left && p.right && lt && rt && (
              <button type="button" className="btn small" onClick={compareAccess} disabled={accessBusy}
                      title={`What each policy allows on ${lt.mount} (left) and ${rt.mount} (right), secret by secret`}>
                {accessBusy && <span className="spinner" />} Compare access on {lt.mount} ⇄ {rt.mount}
              </button>
            )}
            {p.left && p.right && (!lt || !rt) && <span className="subtle">Choose a mount on both sides to compare what these policies allow.</span>}
            {canApply && p.status !== "equal" && p.status !== "error" && (
              <>
                {p.left_text !== null && <button type="button" className="btn small to-right-btn" onClick={() => setCopying("left_to_right")}>Copy to right →</button>}
                {p.right_text !== null && <button type="button" className="btn small to-left-btn" onClick={() => setCopying("right_to_left")}>← Copy to left</button>}
              </>
            )}
          </div>
          {showText && (
            <div className="policy-texts">
              <pre className="mono l" aria-label="Left policy text">{p.left_text ?? "—"}</pre>
              <pre className="mono r" aria-label="Right policy text">{p.right_text ?? "—"}</pre>
            </div>
          )}
          {copying && (
            <AccessApply changes={{ conn_id: (copying === "left_to_right" ? sides.right : sides.left)!.conn_id, policies: [copied(copying)] }}
                         label={(copying === "left_to_right" ? sides.right : sides.left)!.label}
                         onClose={(done) => { setCopying(null); if (done) onCopied(); }} />
          )}
          {accessError && <div className="notice error">{accessError}</div>}
          {access && (
            <div className="access-compare">
              <div className="field-row">
                <span className="subtle">{access.rows.filter((r) => r.differs).length} of {access.rows.length} secrets differ</span>
                <label className="inline-check"><input type="checkbox" checked={allRows} onChange={(e) => setAllRows(e.target.checked)} /> Show all</label>
              </div>
              <div className="table-wrap">
                <table className="policy-table access">
                  <thead>
                    <tr><th>Secret</th>{access.columns.map((c) => <th key={c.id}>{c.label}</th>)}</tr>
                  </thead>
                  <tbody>
                    {accessRows.map((r) => (
                      <tr key={r.path}>
                        <td className="mono">{r.path}</td>
                        {access.columns.map((c) => {
                          const a = r.left?.[c.id], b = r.right?.[c.id];
                          const m = (x?: { ok: boolean; deny: boolean }) => (x === undefined ? "–" : x.ok ? "✓" : x.deny ? "✗" : "·");
                          return <td key={c.id} className={`pcell${a?.ok !== b?.ok ? " differs" : ""}`}>
                            <span className="l">{m(a)}</span> <span className="subtle">/</span> <span className="r">{m(b)}</span></td>;
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="subtle legend">left / right: ✓ allowed, · not allowed, ✗ denied, – no such secret on that side.</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
