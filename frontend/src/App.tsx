import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import { ExpiryView, type ScanTarget } from "./components/ExpiryView";
import { Results } from "./components/Results";
import { type InspectTarget, Inspector, type TrustCandidate } from "./components/Inspector";
import { ProfileBar } from "./components/ProfileBar";
import { ProfileEditor } from "./components/ProfileEditor";
import { ReviewDialog } from "./components/ReviewDialog";
import { exportProfiles, loadActive, loadPersonal, type ProfileRef, saveActive, savePersonal } from "./profiles";
import { type Changeset, changesetSize } from "./staging";
import { SideCard } from "./components/SideCard";
import type { AppConfig, CompareResult, Connection, Profile, SideSelection } from "./types";

const EMPTY: SideSelection = { connId: null, mount: null, prefix: "" };
const STORE_KEY = "lockstep.sides";

// Remember which connection/mount each side used (no secrets): a per-browser convenience.
function loadSides(): [SideSelection, SideSelection] {
  try {
    const v = JSON.parse(localStorage.getItem(STORE_KEY) ?? "null");
    if (Array.isArray(v) && v.length === 2) return [{ ...EMPTY, ...v[0] }, { ...EMPTY, ...v[1] }];
  } catch { /* storage unavailable */ }
  return [EMPTY, EMPTY];
}
function saveSides(s: [SideSelection, SideSelection]) {
  try { localStorage.setItem(STORE_KEY, JSON.stringify(s)); } catch { /* ignore */ }
}

/** Keys in this comparison holding certificates: offered as extra trust anchors in the inspector. */
function trustCandidates(result: CompareResult, leftName: string, rightName: string): TrustCandidate[] {
  const out: TrustCandidate[] = [];
  for (const s of result.secrets) {
    for (const [key, b] of Object.entries(s.badges ?? {})) {
      for (const side of ["left", "right"] as const) {
        const badge = b[side];
        if (!badge || badge.status === null || !["pem", "certificate", "pkcs7"].includes(badge.kind)) continue;
        const sum = result[side];
        const rel = (side === "left" ? s.left_path : s.right_path) || s.path;
        const path = sum.prefix ? `${sum.prefix}/${rel}` : rel;
        out.push({ loc: { conn_id: sum.conn_id, mount: sum.mount, path, key },
                   label: `${side === "left" ? leftName : rightName} · ${rel} · ${key}` });
      }
    }
  }
  return out;
}

export function App() {
  const [config, setConfig] = useState<AppConfig | null>(null);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [sides, setSides] = useState<[SideSelection, SideSelection]>(loadSides);
  const [result, setResult] = useState<CompareResult | null>(null);
  const [comparing, setComparing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reveal, setReveal] = useState(false);
  const [changeset, setChangeset] = useState<Changeset>({});
  const [reviewing, setReviewing] = useState(false);
  const [inspecting, setInspecting] = useState<InspectTarget[] | null>(null);
  const [view, setView] = useState<"compare" | "expiry">(() => {
    try { return localStorage.getItem("lockstep.view") === "expiry" ? "expiry" : "compare"; } catch { return "compare"; }
  });
  useEffect(() => { try { localStorage.setItem("lockstep.view", view); } catch { /* ignore */ } }, [view]);
  const [sharedProfiles, setSharedProfiles] = useState<Profile[]>([]);
  const [personal, setPersonal] = useState<Profile[]>(loadPersonal);
  const [activeRef, setActiveRef] = useState<ProfileRef | null>(loadActive);
  const [editing, setEditing] = useState<{ initial: Profile | null } | null>(null);
  const activeProfile = activeRef
    ? (activeRef.source === "shared" ? sharedProfiles : personal).find((p) => p.name === activeRef.name) ?? null
    : null;

  useEffect(() => { api.profiles().then(setSharedProfiles).catch(() => {}); }, []);

  // A review only makes sense with a result and something staged. Clearing either (new
  // profile, swapped sides, another mount…) also ends the review, even if the dialog's own
  // close event never reaches us because it was unmounted first.
  const hasStaged = Object.keys(changeset).length > 0;
  useEffect(() => { if (!result || !hasStaged) setReviewing(false); }, [result, hasStaged]);

  function updatePersonal(list: Profile[]) {
    setPersonal(list);
    savePersonal(list);
  }

  function selectProfile(ref: ProfileRef | null, list?: Profile[]) {
    setActiveRef(ref);
    saveActive(ref);
    setResult(null);
    setChangeset({});
    const p = ref ? ((ref.source === "shared" ? sharedProfiles : list ?? personal).find((x) => x.name === ref.name) ?? null) : null;
    if (p && (p.left_mount || p.right_mount)) {
      // Apply the profile's mounts and prefixes to sides that already have a connection.
      setSides(([l, r]) => [
        l.connId && p.left_mount ? { ...l, mount: p.left_mount, prefix: p.left_prefix ?? "" } : l,
        r.connId && p.right_mount ? { ...r, mount: p.right_mount, prefix: p.right_prefix ?? "" } : r,
      ]);
    }
  }

  const refresh = useCallback(async () => {
    const conns = await api.connections();
    setConnections(conns);
    // Drop selections that point at connections which no longer exist.
    setSides((prev) => prev.map((s) => (s.connId && !conns.some((c) => c.id === s.connId) ? EMPTY : s)) as [SideSelection, SideSelection]);
  }, []);

  useEffect(() => {
    // Back from an OIDC redirect: select the new connection on the side that started it.
    const q = new URLSearchParams(window.location.search);
    const oidcConn = q.get("oidc") === "ok" ? q.get("conn") : null;
    const oidcSide = q.get("side");
    if (q.get("oidc_error")) setError(`OIDC login failed: ${q.get("oidc_error")}`);
    if (q.has("oidc") || q.has("oidc_error")) window.history.replaceState(null, "", window.location.pathname);

    Promise.all([api.config().then(setConfig), refresh()])
      .then(() => {
        if (oidcConn && (oidcSide === "left" || oidcSide === "right")) {
          setSides((prev) => {
            const next: [SideSelection, SideSelection] = [prev[0], prev[1]];
            next[oidcSide === "left" ? 0 : 1] = { connId: oidcConn, mount: null, prefix: "" };
            return next;
          });
        }
      })
      .catch((e) => setError(e.message));
  }, [refresh]);

  useEffect(() => saveSides(sides), [sides]);

  const setSide = (i: 0 | 1) => (s: SideSelection) => {
    setSides((prev) => (i === 0 ? [s, prev[1]] : [prev[0], s]));
    setResult(null);
    setChangeset({});
  };

  const label = (s: SideSelection) => {
    const c = connections.find((x) => x.id === s.connId);
    return c ? `${c.name} · ${s.mount ?? "?"}${s.prefix ? `/${s.prefix.replace(/^\/+|\/+$/g, "")}` : ""}` : "";
  };

  const ready = sides.every((s) => s.connId && s.mount);

  async function runCompare() {
    const [l, r] = sides;
    setComparing(true);
    setError(null);
    setChangeset({});
    try {
      setResult(await api.compare(
        { conn_id: l.connId!, mount: l.mount!, prefix: l.prefix },
        { conn_id: r.connId!, mount: r.mount!, prefix: r.prefix },
        activeProfile?.rules ?? null));
    } catch (e) {
      setError((e as Error).message);
      setResult(null);
      refresh().catch(() => {});
    } finally {
      setComparing(false);
    }
  }

  async function disconnect(id: string) {
    await api.disconnect(id).catch(() => {});
    setResult(null);
    await refresh();
  }

  if (!config) {
    return <div className="app"><div className="empty">{error ? <div className="notice error">{error}</div> : <span className="spinner" />}</div></div>;
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand"><span className="brand-mark"><i /><i /></span> Lockstep <span className="brand-sub">compatible with HashiCorp Vault</span></div>
        <div className="spacer" />
        <label className="toggle" title="Values are always compared on the server. This only controls whether they are shown.">
          <input type="checkbox" checked={reveal} onChange={(e) => setReveal(e.target.checked)} />
          <span className="track" />
          Show values
        </label>
      </header>
      {config.demo_banner && <div className="demo-banner" role="note">{config.demo_banner}</div>}

      <div className="sides">
        <SideCard side="left" config={config} connections={connections} selection={sides[0]}
                  onChange={setSide(0)} onConnected={() => refresh()} onDisconnect={disconnect} />
        <div className="swap-col">
          <button type="button" className="btn icon" title="Swap left and right" aria-label="Swap sides"
                  onClick={() => { setSides(([a, b]) => [b, a]); setResult(null); setChangeset({}); }}>⇄</button>
        </div>
        <SideCard side="right" config={config} connections={connections} selection={sides[1]}
                  onChange={setSide(1)} onConnected={() => refresh()} onDisconnect={disconnect} />
      </div>

      <nav className="tabs" role="tablist" aria-label="View">
        <button type="button" role="tab" aria-selected={view === "compare"} onClick={() => setView("compare")}>Compare</button>
        <button type="button" role="tab" aria-selected={view === "expiry"} onClick={() => setView("expiry")}>Certificate expiry</button>
      </nav>

      {view === "expiry" ? (
        <ExpiryView
          targets={sides.flatMap((s, i): ScanTarget[] => (s.connId && s.mount
            ? [{ side: i === 0 ? "left" : "right", conn_id: s.connId, mount: s.mount, prefix: s.prefix, label: label(s) }] : []))}
          onInspect={setInspecting} />
      ) : (<>
      <ProfileBar
        shared={sharedProfiles} personal={personal} active={activeProfile ? activeRef : null}
        onSelect={(ref) => selectProfile(ref)}
        onNew={() => setEditing({ initial: null })}
        onEdit={(p, source) => setEditing({ initial: source === "shared" ? { ...p, name: `${p.name} (copy)` } : p })}
        onDelete={(name) => {
          updatePersonal(personal.filter((p) => p.name !== name));
          selectProfile(null);
        }}
        onImport={(list) => {
          const names = new Set(personal.map((p) => p.name));
          const added = list.map((p) => {
            let n = p.name, i = 2;
            while (names.has(n)) n = `${p.name} (${i++})`;
            names.add(n);
            return { ...p, name: n };
          });
          const next = [...personal, ...added];
          updatePersonal(next);
          selectProfile({ source: "personal", name: added[0].name }, next);
        }}
        onExport={(list) => exportProfiles(list)}
      />

      {editing && (
        <ProfileEditor
          initial={editing.initial}
          takenNames={personal.map((p) => p.name)}
          current={{ left_mount: sides[0].mount, left_prefix: sides[0].prefix, right_mount: sides[1].mount, right_prefix: sides[1].prefix }}
          onClose={() => setEditing(null)}
          onSave={(p) => {
            const replacing = editing.initial && personal.some((x) => x.name === editing.initial!.name);
            const next = replacing ? personal.map((x) => (x.name === editing.initial!.name ? p : x)) : [...personal, p];
            updatePersonal(next);
            selectProfile({ source: "personal", name: p.name }, next);
          }}
        />
      )}

      <div className="compare-bar">
        <button type="button" className="btn primary big" disabled={!ready || comparing} onClick={runCompare}>
          {comparing && <span className="spinner" />} {result ? "Compare again" : "Compare"}
        </button>
      </div>

      {error && <div className="notice error" role="alert">{error}</div>}
      {result && activeProfile && (
        <div className="notice info profile-effect">
          Profile <strong>{activeProfile.name}</strong>: {result.summary.mapped ?? 0} pair{result.summary.mapped === 1 ? "" : "s"} matched by a mapping
          · {result.summary.ignored_keys ?? 0} key difference{result.summary.ignored_keys === 1 ? "" : "s"} ignored
          · {result.summary.ignored_paths ?? 0} path{result.summary.ignored_paths === 1 ? "" : "s"} left out
        </div>
      )}
      {result && <Results result={result} reveal={reveal} leftLabel={label(sides[0])} rightLabel={label(sides[1])}
                          changeset={changeset} onChangeset={setChangeset} onInspect={setInspecting} />}


      {result && Object.keys(changeset).length > 0 && (() => {
        const n = changesetSize(changeset, result);
        return (
          <div className="changeset-bar" role="region" aria-label="Staged changes">
            <span><strong>{n.keys}</strong> key{n.keys === 1 ? "" : "s"} staged in <strong>{n.secrets}</strong> secret{n.secrets === 1 ? "" : "s"}</span>
            <span className="spacer" />
            <button type="button" className="btn ghost" onClick={() => setChangeset({})}>Clear</button>
            <button type="button" className="btn primary" onClick={() => setReviewing(true)}>Review &amp; apply…</button>
          </div>
        );
      })()}

      {reviewing && result && hasStaged && (
        <ReviewDialog result={result} changeset={changeset} reveal={reveal}
                      onClose={(applied) => {
                        setReviewing(false);
                        if (applied) { setChangeset({}); runCompare(); }
                      }} />
      )}
      </>)}

      {inspecting && (
        <Inspector targets={inspecting} reveal={reveal}
                   trustCandidates={result ? trustCandidates(result, label(sides[0]), label(sides[1])) : []}
                   onClose={() => setInspecting(null)} />
      )}
    </div>
  );
}
