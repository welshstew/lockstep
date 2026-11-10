import { useCallback, useEffect, useState } from "react";
import { api, type SideRef } from "./api";
import { ExpiryView, type ScanTarget } from "./components/ExpiryView";
import { PlansView } from "./components/PlansView";
import { Results } from "./components/Results";
import { type InspectTarget, Inspector, type TrustCandidate } from "./components/Inspector";
import { ProfileBar } from "./components/ProfileBar";
import { ProfileEditor } from "./components/ProfileEditor";
import { ReviewDialog } from "./components/ReviewDialog";
import {
  emptyRules, exportProfiles, loadActive, loadPersonal, mergeRules, type ProfileRef, ruleCount, saveActive, savePersonal,
} from "./profiles";
import { type Changeset, changesetSize } from "./staging";
import { SideCard } from "./components/SideCard";
import { TransferView } from "./components/TransferView";
import type { AppConfig, CompareResult, Connection, LoadedFile, Profile, ProfileRules, SideSelection } from "./types";

const EMPTY: SideSelection = { connId: null, mount: null, prefix: "" };
const STORE_KEY = "lockstep.sides";

// Remember which connection/mount each side used (no secrets): a per-browser convenience.
function loadSides(): [SideSelection, SideSelection] {
  try {
    const v = JSON.parse(localStorage.getItem(STORE_KEY) ?? "null");
    // Opened export files live in memory only, so a remembered file side starts empty
    if (Array.isArray(v) && v.length === 2) return [{ ...EMPTY, ...v[0], fileId: null }, { ...EMPTY, ...v[1], fileId: null }];
  } catch { /* storage unavailable */ }
  return [EMPTY, EMPTY];
}
function saveSides(s: [SideSelection, SideSelection]) {
  const plain = s.map(({ fileId: _f, ...rest }) => rest);
  try { localStorage.setItem(STORE_KEY, JSON.stringify(plain)); } catch { /* ignore */ }
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
  const [view, setView] = useState<"compare" | "expiry" | "plans" | "transfer">(() => {
    try {
      const v = localStorage.getItem("lockstep.view");
      return v === "expiry" || v === "plans" || v === "transfer" ? v : "compare";
    } catch { return "compare"; }
  });
  // Export files opened in this page: in memory only (they hold values), gone on reload
  const [files, setFiles] = useState<LoadedFile[]>([]);
  const addFile = (f: LoadedFile) => setFiles((fs) => [...fs, f]);
  const fileOf = (s: SideSelection) => files.find((f) => f.id === s.fileId) ?? null;
  const sideRef = (s: SideSelection): SideRef => {
    const f = fileOf(s);
    return f ? { export: f.doc, name: f.name, prefix: s.prefix } : { conn_id: s.connId!, mount: s.mount!, prefix: s.prefix };
  };
  useEffect(() => { try { localStorage.setItem("lockstep.view", view); } catch { /* ignore */ } }, [view]);
  const [sharedProfiles, setSharedProfiles] = useState<Profile[]>([]);
  const [personal, setPersonal] = useState<Profile[]>(loadPersonal);
  const [activeRef, setActiveRef] = useState<ProfileRef | null>(loadActive);
  const [editing, setEditing] = useState<{ initial: Profile | null; fromDraft?: boolean } | null>(null);
  // Ignore mode: rules picked from the results, not saved yet ("draft"), used by Compare again
  const [ignoreMode, setIgnoreMode] = useState(false);
  const [draft, setDraft] = useState<ProfileRules>(emptyRules);
  const draftRules = ruleCount(draft);
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
    const f = fileOf(s);
    if (f) return `${f.name}${s.prefix ? `/${s.prefix.replace(/^\/+|\/+$/g, "")}` : ""}`;
    const c = connections.find((x) => x.id === s.connId);
    return c ? `${c.name} · ${s.mount ?? "?"}${s.prefix ? `/${s.prefix.replace(/^\/+|\/+$/g, "")}` : ""}` : "";
  };

  const ready = sides.every((s) => fileOf(s) || (s.connId && s.mount));

  async function runCompare() {
    const [l, r] = sides;
    setComparing(true);
    setError(null);
    setChangeset({});
    try {
      setResult(await api.compare(sideRef(l), sideRef(r),
        draftRules ? mergeRules(activeProfile?.rules, draft) : activeProfile?.rules ?? null));
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
                  onChange={setSide(0)} onConnected={() => refresh()} onDisconnect={disconnect}
                  files={files} onFile={addFile} />
        <div className="swap-col">
          <button type="button" className="btn icon" title="Swap left and right" aria-label="Swap sides"
                  onClick={() => { setSides(([a, b]) => [b, a]); setResult(null); setChangeset({}); }}>⇄</button>
        </div>
        <SideCard side="right" config={config} connections={connections} selection={sides[1]}
                  onChange={setSide(1)} onConnected={() => refresh()} onDisconnect={disconnect}
                  files={files} onFile={addFile} />
      </div>

      <nav className="tabs" role="tablist" aria-label="View">
        <button type="button" role="tab" aria-selected={view === "compare"} onClick={() => setView("compare")}>Compare</button>
        <button type="button" role="tab" aria-selected={view === "expiry"} onClick={() => setView("expiry")}>Certificate expiry</button>
        <button type="button" role="tab" aria-selected={view === "plans"} onClick={() => setView("plans")}>Sync plans</button>
        <button type="button" role="tab" aria-selected={view === "transfer"} onClick={() => setView("transfer")}>Export &amp; import</button>
      </nav>

      {view === "transfer" ? (
        <TransferView config={config} reveal={reveal} files={files} onFile={addFile}
                      sides={sides.map((s, i) => ({ side: i === 0 ? "left" as const : "right" as const, label: label(s),
                        ref: s.connId && s.mount && !s.fileId ? { conn_id: s.connId, mount: s.mount, prefix: s.prefix } : null }))}
                      profiles={[...sharedProfiles, ...personal]} />
      ) : view === "plans" ? (
        <PlansView connections={connections} leftConnId={sides[0].connId} rightConnId={sides[1].connId} />
      ) : view === "expiry" ? (
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
            if (editing.fromDraft) { setDraft(emptyRules()); setIgnoreMode(false); }
          }}
        />
      )}

      <div className="compare-bar">
        <button type="button" className="btn primary big" disabled={!ready || comparing} onClick={runCompare}>
          {comparing && <span className="spinner" />} {result ? "Compare again" : "Compare"}
        </button>
        {result && (
          <button type="button" className="btn big" aria-pressed={ignoreMode} onClick={() => setIgnoreMode(!ignoreMode)}
                  title="Pick secrets and keys to ignore, and save them as a comparison profile">
            {ignoreMode ? "Done picking" : "Pick what to ignore…"}
          </button>
        )}
      </div>

      {result && (ignoreMode || draftRules > 0) && (
        <section className="draft-bar card" aria-label="Profile draft">
          <div>
            <strong>{ignoreMode ? "Ignore mode" : "Unsaved ignore rules"}</strong>{" "}
            <span className="subtle">
              {ignoreMode && "Use Ignore on secrets, folders and keys below. "}
              {draftRules === 0 ? "Nothing picked yet."
                : `${draft.ignore_paths.length} secret/folder rule${draft.ignore_paths.length === 1 ? "" : "s"}, ${draft.ignore_keys.length} key rule${draft.ignore_keys.length === 1 ? "" : "s"}${activeProfile ? `, on top of “${activeProfile.name}”` : ""}.`}
            </span>
          </div>
          {draftRules > 0 && (
            <ul className="draft-rules">
              {draft.ignore_paths.map((p) => <li key={`p${p}`}><span className="mono">{p}</span> <span className="subtle">left out</span></li>)}
              {draft.ignore_keys.map((k) => <li key={`k${k.key}|${k.path}`}><span className="mono">{k.key}</span> <span className="subtle">ignored {k.path === "**" ? "everywhere" : <>in <span className="mono">{k.path}</span></>}</span></li>)}
            </ul>
          )}
          <div className="draft-actions">
            <button type="button" className="btn small" disabled={!draftRules || comparing} onClick={runCompare}>Compare with these rules</button>
            <button type="button" className="btn primary small" disabled={!draftRules} onClick={() => {
              const rules = mergeRules(activeProfile?.rules, draft);
              const base: Profile = activeProfile && activeRef?.source === "personal" ? activeProfile
                : activeProfile ? { ...activeProfile, name: `${activeProfile.name} (copy)` }
                  : { name: "", description: "", rules };
              setEditing({ initial: { ...base, rules }, fromDraft: true });
            }}>{activeProfile && activeRef?.source === "personal" ? `Add to “${activeProfile.name}”…` : "Save as profile…"}</button>
            <button type="button" className="btn ghost small" disabled={!draftRules} onClick={() => setDraft(emptyRules())}>Discard</button>
          </div>
        </section>
      )}

      {error && <div className="notice error" role="alert">{error}</div>}
      {result && (activeProfile || draftRules > 0) && (
        <div className="notice info profile-effect">
          {activeProfile ? <>Profile <strong>{activeProfile.name}</strong>{draftRules > 0 && " plus unsaved rules"}</> : "Unsaved rules"}: {result.summary.mapped ?? 0} pair{result.summary.mapped === 1 ? "" : "s"} matched by a mapping
          · {result.summary.ignored_keys ?? 0} key difference{result.summary.ignored_keys === 1 ? "" : "s"} ignored
          · {result.summary.ignored_paths ?? 0} path{result.summary.ignored_paths === 1 ? "" : "s"} left out
        </div>
      )}
      {result && <Results result={result} reveal={reveal} leftLabel={label(sides[0])} rightLabel={label(sides[1])}
                          fileDocs={{ left: fileOf(sides[0])?.doc, right: fileOf(sides[1])?.doc }}
                          changeset={changeset} onChangeset={setChangeset} onInspect={setInspecting}
                          ignoreMode={ignoreMode} draft={draft} onDraft={setDraft} />}


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
        <ReviewDialog result={result} changeset={changeset} reveal={reveal} profile={activeProfile?.name ?? null}
                      sides={{ left: sideRef(sides[0]), right: sideRef(sides[1]) }}
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
