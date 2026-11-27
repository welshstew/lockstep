import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import { absoluteTime, relativeTime } from "../time";
import type { AppConfig, BrowseDiff, BrowseEdit, BrowseEditResult, BrowseList, BrowseSecret, KeyHistory } from "../types";
import { MetadataEditor, randomValue, SharePanel, Snippets, toYaml, UnwrapDialog } from "./BrowseExtras";
import { DestroyDialog } from "./DestroyDialog";
import type { InspectTarget } from "./Inspector";
import { formatValue, typeName } from "./ValueCell";
import { browseUndoWrites, downloadUndo } from "../plans";

export interface BrowseTarget {
  conn_id: string;
  mount: string;
  prefix: string;
  label: string;
  url?: string | null; // the Vault's address, for snippets
  writes?: "all" | "some" | "none"; // the preset's write policy
  destroy?: boolean; // destroying allowed here
  export?: "any" | "encrypted" | "off"; // exports allowed from here
}

type Go = (view: "compare" | "expiry" | "policies" | "policy-build" | "transfer", folder: string) => void;

interface Props {
  config: AppConfig;
  /** The connection and mount chosen in the Connections list; null until both are */
  target: BrowseTarget | null;
  reveal: boolean;
  onInspect: (t: InspectTarget[]) => void;
  onGo: Go;
}

interface Draft { set: Record<string, unknown>; remove: string[]; isNew: boolean }
interface Staged { edit: BrowseEdit; label: string }

const STAGE_KEY = "lockstep.browse.stage";
const CLIPBOARD_CLEAR_MS = 30_000;

const clean = (p: string) => p.replace(/^\/+|\/+$/g, "");
const parentOf = (p: string) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
const asText = (v: unknown) => (v === undefined ? "" : typeof v === "string" ? v : JSON.stringify(v, null, 2));

/** A link to a secret: #/browse/<mount>/<path>. Older links also named a side (left/ or right/ first). */
export function readHash(): { mount: string; path: string } | null {
  const m = /^#\/browse\/(?:(?:left|right)\/)?([^/]+)\/(.+)$/.exec(window.location.hash);
  return m ? { mount: decodeURIComponent(m[1]), path: decodeURIComponent(m[2]) } : null;
}

function load<T>(key: string, fallback: T): T {
  try { const v = localStorage.getItem(key); return v === null ? fallback : JSON.parse(v); } catch { return fallback; }
}
function save(key: string, v: unknown) {
  try { localStorage.setItem(key, JSON.stringify(v)); } catch { /* ignore */ }
}

/** Browse one connection's KV v2 mount as a tree, and edit it with check-and-set. */
export function BrowseView({ config, target, reveal, onInspect, onGo }: Props) {
  const hash = useMemo(readHash, []);
  const root = target ? clean(target.prefix) : "";
  const [folders, setFolders] = useState<Record<string, BrowseList | "loading" | { error: string }>>({});
  const [open, setOpen] = useState<Set<string>>(new Set([""]));
  const [selected, setSelected] = useState<string | null>(null);
  const [newIn, setNewIn] = useState<string | null>(null); // folder where a new secret is being named
  const [query, setQuery] = useState("");
  const [found, setFound] = useState<{ matches: string[]; more: boolean; truncated: boolean } | null>(null);
  const [finding, setFinding] = useState(false);
  const [goTo, setGoTo] = useState("");
  const [stage, setStageState] = useState<boolean>(() => load(STAGE_KEY, false));
  const [staged, setStaged] = useState<Staged[]>([]);
  const [reviewing, setReviewing] = useState(false);
  const [unwrapping, setUnwrapping] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const writable = !config.read_only && target?.writes !== "none";
  const key = target ? `${target.conn_id}|${target.mount}` : "";

  const setStage = (v: boolean) => { setStageState(v); save(STAGE_KEY, v); };

  const loadFolder = useCallback(async (folder: string, offset = 0) => {
    if (!target) return;
    if (!offset) setFolders((f) => ({ ...f, [folder]: "loading" }));
    try {
      const res = await api.browseList(target.conn_id, target.mount, folder, offset);
      setFolders((f) => {
        const prev = f[folder];
        const merged = offset && prev && typeof prev === "object" && "entries" in prev
          ? { ...res, entries: [...prev.entries, ...res.entries] } : res;
        return { ...f, [folder]: merged };
      });
    } catch (e) {
      setFolders((f) => ({ ...f, [folder]: { error: (e as Error).message } }));
    }
  }, [target?.conn_id, target?.mount]); // eslint-disable-line react-hooks/exhaustive-deps

  // A new connection or mount: start again at its prefix (or at the linked path)
  useEffect(() => {
    setFolders({});
    setFound(null);
    setStaged([]);
    if (!target) return;
    const linked = hash && hash.mount === target.mount ? clean(hash.path) : null;
    const opened = new Set([root]);
    if (linked) {
      const parts = linked.split("/");
      for (let i = 1; i < parts.length; i++) opened.add(parts.slice(0, i).join("/"));
    }
    setOpen(opened);
    setSelected(linked);
    opened.forEach((f) => loadFolder(f));
  }, [key, root]); // eslint-disable-line react-hooks/exhaustive-deps

  const select = (path: string | null) => {
    setSelected(path);
    if (path && target) {
      window.history.replaceState(null, "", `#/browse/${encodeURIComponent(target.mount)}/${path}`);
    } else {
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
    }
  };
  const toggle = (folder: string) => {
    setOpen((o) => {
      const n = new Set(o);
      if (n.has(folder)) n.delete(folder);
      else { n.add(folder); if (!folders[folder]) loadFolder(folder); }
      return n;
    });
  };
  // After a write: reload the loaded folders from the secret's parent up to the root
  const refreshFolder = (path: string) => {
    let f = parentOf(path);
    for (;;) {
      if (folders[f] || f === root) loadFolder(f);
      if (f === root || f === "") break;
      f = parentOf(f);
    }
  };
  const [panelGen, setPanelGen] = useState(0);

  async function find() {
    if (!target || !query.trim()) { setFound(null); return; }
    setFinding(true);
    setError(null);
    try {
      setFound(await api.browseFind(target.conn_id, target.mount, root, query.trim()));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setFinding(false);
    }
  }

  if (!target) {
    return <div className="notice info">Choose a connection and a KV v2 secret engine above to browse it.</div>;
  }

  const renderFolder = (folder: string, depth: number) => {
    const f = folders[folder];
    if (!f || f === "loading") return <div className="tree-note" style={{ paddingLeft: depth * 16 + 8 }}><span className="spinner" /></div>;
    if ("error" in f) return <div className="tree-note error" style={{ paddingLeft: depth * 16 + 8 }}>{f.error}</div>;
    if (f.denied) return <div className="tree-note" style={{ paddingLeft: depth * 16 + 8 }}>⊘ You can’t list this folder.</div>;
    return (
      <>
        {f.entries.map((e) => e.folder ? (
          <div key={e.path}>
            <button type="button" className="tree-row folder" style={{ paddingLeft: depth * 16 + 8 }} aria-expanded={open.has(e.path)}
                    onClick={() => toggle(e.path)}>
              <span className="caret">▸</span> <span className="mono">{e.name}/</span>
              {e.caps.list === false && <span className="tree-icon" title="You can’t list this folder">⊘</span>}
            </button>
            {open.has(e.path) && renderFolder(e.path, depth + 1)}
          </div>
        ) : (
          <button key={e.path} type="button" className="tree-row secret" style={{ paddingLeft: depth * 16 + 26 }}
                  aria-current={selected === e.path} onClick={() => { setNewIn(null); select(e.path); }}>
            <span className="mono">{e.name}</span>
            {e.caps.read === false && <span className="tree-icon" title="You can’t read this secret">⊘</span>}
          </button>
        ))}
        {f.entries.length === 0 && <div className="tree-note subtle" style={{ paddingLeft: depth * 16 + 26 }}>Empty</div>}
        {f.entries.length < f.total && (
          <button type="button" className="tree-row more" style={{ paddingLeft: depth * 16 + 26 }}
                  onClick={() => loadFolder(folder, f.entries.length)}>Show {Math.min(200, f.total - f.entries.length)} more of {f.total - f.entries.length}…</button>
        )}
        {writable && (newIn === folder ? (
          <NewSecretRow folder={folder} depth={depth} onCancel={() => setNewIn(null)}
                        onCreate={(path) => { setNewIn(null); select(path); }} />
        ) : (
          <button type="button" className="tree-row add" style={{ paddingLeft: depth * 16 + 26 }} onClick={() => setNewIn(folder)}>
            ＋ New secret{folder ? ` in ${folder.split("/").pop()}/` : ""}
          </button>
        ))}
      </>
    );
  };

  const addStaged = (s: Staged) => setStaged((all) => [...all.filter((x) => !(x.edit.path === s.edit.path && x.edit.action === s.edit.action)), s]);

  return (
    <section className="browse">
      <div className="browse-bar">
        <span className="scope left">{target.label}</span>
        <form className="browse-find" onSubmit={(e) => { e.preventDefault(); find(); }}>
          <input type="search" className="search" placeholder="Find secrets by name…" value={query} aria-label="Find secrets"
                 onChange={(e) => { setQuery(e.target.value); if (!e.target.value) setFound(null); }} />
        </form>
        <form className="browse-find" onSubmit={(e) => {
          e.preventDefault();
          const p = clean(goTo);
          if (!p) return;
          const parts = p.split("/");
          setOpen((o) => { const n = new Set(o); for (let i = 1; i < parts.length; i++) { const f = parts.slice(0, i).join("/"); n.add(f); if (!folders[f]) loadFolder(f); } return n; });
          select(p);
        }}>
          <input type="text" className="mono" placeholder="Go to path…" value={goTo} aria-label="Go to path" onChange={(e) => setGoTo(e.target.value)} />
        </form>
        <button type="button" className="btn ghost small" onClick={() => setUnwrapping(true)}>Open a shared token…</button>
        <span className="spacer" />
        {writable && (
          <label className="inline-check" title="Collect edits and apply them together after a review, instead of saving each one">
            <input type="checkbox" checked={stage} onChange={(e) => setStage(e.target.checked)} /> Stage changes
          </label>
        )}
        {config.read_only && <span className="badge unknown" title="LOCKSTEP_READ_ONLY">read-only server</span>}
        {!config.read_only && target?.writes === "none" && <span className="badge unknown" title="This Vault's preset is read-only on this Lockstep server">read-only here</span>}
        {!config.read_only && target?.writes === "some" && <span className="badge unknown" title="This Vault's preset limits which paths Lockstep may write">writes limited</span>}
      </div>
      {error && <div className="notice error" role="alert">{error}</div>}

      <div className="browse-layout">
        <nav className="card browse-tree" aria-label="Secrets">
          <div className="tree-head mono">{target.mount}/{root ? `${root}/` : ""}</div>
          {found ? (
            <div>
              <div className="tree-note subtle">
                {found.matches.length} match{found.matches.length === 1 ? "" : "es"}{found.more ? " (more not shown)" : ""}
                {found.truncated ? ", listing cut short" : ""} · <button type="button" className="link-btn" onClick={() => { setFound(null); setQuery(""); }}>back to the tree</button>
              </div>
              {found.matches.map((p) => (
                <button key={p} type="button" className="tree-row secret" aria-current={selected === p} onClick={() => select(p)}>
                  <span className="mono">{p}</span>
                </button>
              ))}
            </div>
          ) : renderFolder(root, 0)}
          {finding && <div className="tree-note"><span className="spinner" /> Searching…</div>}
        </nav>

        <div className="browse-detail">
          {selected ? (
            <SecretPanel key={`${key}|${selected}|${panelGen}`} target={target} path={selected} config={config} reveal={reveal}
                         stage={stage} onStage={addStaged} onInspect={onInspect} onGo={onGo}
                         onChanged={() => refreshFolder(selected)} onGone={() => { refreshFolder(selected); select(null); }} />
          ) : (
            <div className="card empty">Choose a secret on the left{writable ? ", or create one with ＋ New secret" : ""}.</div>
          )}
        </div>
      </div>

      {staged.length > 0 && (
        <div className="changeset-bar" role="region" aria-label="Staged edits">
          <span><strong>{staged.length}</strong> change{staged.length === 1 ? "" : "s"} staged in <strong>{new Set(staged.map((s) => s.edit.path)).size}</strong> secret{new Set(staged.map((s) => s.edit.path)).size === 1 ? "" : "s"}</span>
          <span className="spacer" />
          <button type="button" className="btn ghost" onClick={() => setStaged([])}>Clear</button>
          <button type="button" className="btn primary" onClick={() => setReviewing(true)}>Review &amp; apply…</button>
        </div>
      )}
      {unwrapping && <UnwrapDialog conn_id={target.conn_id} label={target.label} onClose={() => setUnwrapping(false)} />}
      {reviewing && (
        <BrowseReview target={target} staged={staged} reveal={reveal}
                      onClose={(done) => {
                        setReviewing(false);
                        if (done) {
                          const paths = new Set(staged.map((s) => s.edit.path));
                          setStaged([]);
                          paths.forEach((p) => refreshFolder(p));
                          setPanelGen((g) => g + 1);
                        }
                      }} />
      )}
    </section>
  );
}

function NewSecretRow({ folder, depth, onCreate, onCancel }: { folder: string; depth: number; onCreate: (p: string) => void; onCancel: () => void }) {
  const [name, setName] = useState("");
  return (
    <form className="tree-row new" style={{ paddingLeft: depth * 16 + 26 }}
          onSubmit={(e) => { e.preventDefault(); const n = clean(name); if (n) onCreate(folder ? `${folder}/${n}` : n); }}>
      <input type="text" className="mono" autoFocus placeholder="name (or sub/path/name)" aria-label="New secret name"
             value={name} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => { if (e.key === "Escape") onCancel(); }} />
      <button type="submit" className="btn small" disabled={!clean(name)}>Create</button>
      <button type="button" className="btn ghost small" onClick={onCancel}>Cancel</button>
    </form>
  );
}

interface PanelProps {
  target: BrowseTarget;
  path: string;
  config: AppConfig;
  reveal: boolean;
  stage: boolean;
  onStage: (s: Staged) => void;
  onInspect: (t: InspectTarget[]) => void;
  onGo: Go;
  onChanged: () => void;
  onGone: () => void;
}

/** One secret: keys, values on request, versions, metadata, and edits. */
function SecretPanel({ target, path, config, reveal, stage, onStage, onInspect, onGo, onChanged, onGone }: PanelProps) {
  const [info, setInfo] = useState<BrowseSecret | null>(null);
  const [missing, setMissing] = useState(false);
  const [version, setVersion] = useState<number | null>(null); // viewing an older version
  const [values, setValues] = useState<Record<string, unknown> | null>(null);
  const [shown, setShown] = useState<Set<string>>(new Set());
  const [history, setHistory] = useState<KeyHistory | null>(null);
  const [draft, setDraft] = useState<Draft>({ set: {}, remove: [], isNew: false });
  const [editing, setEditing] = useState<Record<string, { text: string; json: boolean; error?: string }>>({});
  const [newKey, setNewKey] = useState("");
  const [confirm, setConfirm] = useState<null | { label: string; edit: BrowseEdit; typed?: string; entered?: string }>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [undoable, setUndoable] = useState<BrowseEditResult[] | null>(null);  // the last save, for an undo plan
  const [diff, setDiff] = useState<BrowseDiff | null>(null);
  const [destroying, setDestroying] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const [editingMeta, setEditingMeta] = useState(false);
  const [sharing, setSharing] = useState(false);
  const [snippets, setSnippets] = useState(false);
  const [asYaml, setAsYaml] = useState(false);
  const writable = !config.read_only && target.writes !== "none";

  const loadInfo = useCallback(async (v: number | null) => {
    try {
      const i = await api.browseSecret(target.conn_id, target.mount, path, v);
      setInfo(i);
      setMissing(false);
      setValues(null);
      setShown(new Set());
      setDiff(null);
      if (!v && i.state === "present") {
        api.history(target.conn_id, target.mount, path).then(setHistory).catch(() => setHistory(null));
      }
    } catch (e) {
      if ((e as { status?: number }).status === 404) { setMissing(true); setInfo(null); setDraft((d) => ({ ...d, isNew: true })); }
      else setError((e as Error).message);
    }
  }, [target.conn_id, target.mount, path]);

  useEffect(() => { setError(null); loadInfo(version); }, [version]); // eslint-disable-line react-hooks/exhaustive-deps

  const needValues = reveal || shown.size > 0 || Object.keys(editing).length > 0;
  useEffect(() => {
    if (!needValues || values || !info || info.state !== "present" || info.caps.read === false) return;
    let live = true;
    api.browseValues(target.conn_id, target.mount, path, version)
      .then((r) => { if (live) setValues(r.data); })
      .catch((e) => { if (live) setError(`Couldn’t read values: ${(e as Error).message}`); });
    return () => { live = false; };
  }, [needValues, info]); // eslint-disable-line react-hooks/exhaustive-deps

  // Fill editors that were opened before the values arrived
  useEffect(() => {
    if (!values) return;
    setEditing((ed) => Object.fromEntries(Object.entries(ed).map(([k, d]) => [k, d.text || d.error !== undefined ? d : {
      text: asText(values[k]), json: typeof values[k] !== "string" && values[k] !== undefined,
    }])));
  }, [values]);

  const viewingOld = version !== null && version !== info?.current_version;
  const canWrite = writable && !viewingOld && (info?.caps.write !== false || !!info?.caps.patch);
  const keys = [...new Set([...(info?.keys ?? []), ...Object.keys(draft.set)])].sort();
  const pending = Object.keys(draft.set).length + draft.remove.length;
  const expected = info && (info.state === "present" || info.state === "deleted" || info.keys_only) ? info.current_version : null;

  async function run(edit: BrowseEdit, label: string, after: "reload" | "gone" = "reload") {
    if (stage) {
      onStage({ edit, label });
      setNotice(`Staged: ${label}. Review & apply below.`);
      setConfirm(null);
      setDraft({ set: {}, remove: [], isNew: false });
      setEditing({});
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const [res] = await api.browseApply(target.conn_id, target.mount, [edit]);
      if (res.status === "applied") {
        setNotice(res.new_version ? `Saved as v${res.new_version}.` : `${label}: done.`);
        setUndoable(browseUndoWrites(target.conn_id, target.mount, [res]).length ? [res] : null);
        setDraft({ set: {}, remove: [], isNew: false });
        setEditing({});
        setConfirm(null);
        onChanged();
        if (after === "gone") onGone();
        else { setVersion(null); loadInfo(null); }
      } else {
        if (res.status === "conflict") {
          setError(`Not saved: ${res.message} Your unsaved changes are still here: check the current values, then save again.`);
          setVersion(null);
          loadInfo(null);
        } else {
          setError(res.message || res.status);
        }
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function commitEditor(k: string) {
    const d = editing[k];
    if (!d) return;
    let value: unknown = d.text;
    if (d.json) {
      try { value = JSON.parse(d.text); } catch { setEditing({ ...editing, [k]: { ...d, error: "Not valid JSON" } }); return; }
    }
    const same = values && k in values && JSON.stringify(values[k]) === JSON.stringify(value);
    const set = { ...draft.set };
    if (same) delete set[k]; else set[k] = value;
    setDraft({ ...draft, set, remove: draft.remove.filter((x) => x !== k) });
    const { [k]: _drop, ...rest } = editing;
    setEditing(rest);
  }

  function copy(k: string, v: unknown) {
    const text = asText(v);
    navigator.clipboard?.writeText(text).then(() => {
      setCopied(k);
      setTimeout(() => setCopied((c) => (c === k ? null : c)), 2000);
      setTimeout(async () => {
        try { if ((await navigator.clipboard.readText()) === text) await navigator.clipboard.writeText(""); } catch { /* not allowed: leave it */ }
      }, CLIPBOARD_CLEAR_MS);
    }).catch(() => setError("The browser didn’t allow copying."));
  }

  async function showDiff() {
    if (!info || version === null || !info.current_version) return;
    try {
      setDiff(await api.browseDiff(target.conn_id, target.mount, path, version, info.current_version, reveal));
    } catch (e) {
      setError((e as Error).message);
    }
  }

  const folder = parentOf(path);
  const shownValue = (k: string) => (reveal || shown.has(k)) && values && k in values;
  const loc = (k: string) => ({ conn_id: target.conn_id, mount: target.mount, path, key: k });
  const hist = (k: string) => history?.keys[k];
  const vInfo = info?.versions.find((v) => v.version === (version ?? info.current_version));

  return (
    <div className="card secret-panel">
      <header className="panel-head">
        <div className="mono crumbs">
          <span className="subtle">{target.mount}/</span>
          {path.split("/").map((part, i, all) => <span key={i}>{part}{i < all.length - 1 ? <span className="subtle">/</span> : ""}</span>)}
        </div>
        {info && (
          <span className="subtle" title={absoluteTime(info.updated)}>
            {viewingOld ? `viewing v${version} of ${info.current_version}` : `v${info.current_version ?? "—"}`}
            {info.updated ? ` · ${relativeTime(info.updated)}` : ""}
            {vInfo?.by ? ` · by ${vInfo.by}` : ""}
          </span>
        )}
      </header>

      {notice && <div className="notice info" role="status">{notice}
        {undoable && <button type="button" className="btn ghost small" title="A signed file that puts back what this save changed, for you or someone else to apply in Sync plans"
          onClick={async () => {
            try { setNotice(`Undo plan saved as ${await downloadUndo(browseUndoWrites(target.conn_id, target.mount, undoable))}. Open it in Sync plans to apply it.`); }
            catch (e) { setError((e as Error).message); }
            setUndoable(null);
          }}>Make an undo plan</button>}
        <button type="button" className="btn ghost small" aria-label="Dismiss" onClick={() => { setNotice(null); setUndoable(null); }}>✕</button></div>}
      {error && <div className="notice error" role="alert">{error}</div>}
      {missing && !writable && <div className="notice info">No secret here.</div>}
      {missing && writable && <div className="notice info">A new secret: add its first keys below, then save.</div>}
      {info?.state === "deleted" && !viewingOld && (
        <div className="notice warn">The latest version (v{info.current_version}) is deleted. {info.keys === null && "Older versions may still have data."}</div>
      )}
      {info?.state === "destroyed" && <div className="notice warn">Version {version} was destroyed: its data is gone.</div>}
      {info?.read_error && (info.keys_only
        ? <div className="notice info">You can see the key names but not the values (Vault’s <span className="mono">subkeys</span>).
            {info.caps.patch && " You can still change keys: they’re sent as a patch."}</div>
        : <div className="notice warn">Can’t read the values: {info.read_error}</div>)}
      {(info?.state === "present" || info?.keys_only) && !missing && (
        <div className="field-row view-toggle">
          <div className="segmented small" role="group" aria-label="View">
            <button type="button" aria-pressed={!asYaml} onClick={() => setAsYaml(false)}>Keys</button>
            <button type="button" aria-pressed={asYaml} onClick={() => setAsYaml(true)}>YAML</button>
          </div>
          {asYaml && !reveal && <span className="subtle">Values stay masked unless shown (Show, or Show values at the top).</span>}
        </div>
      )}
      {asYaml && info && (
        <pre className="mono hcl-preview" aria-label="Secret as YAML">{toYaml(
          values ?? Object.fromEntries((info.keys ?? []).map((k) => [k, ""])), (k) => !!values && (reveal || shown.has(k)))}</pre>
      )}

      {(info?.state === "present" || missing || info?.keys_only) && !asYaml && (
        <table className="browse-keys">
          <tbody>
            {keys.map((k) => {
              const removed = draft.remove.includes(k);
              const typed = k in draft.set;
              const ed = editing[k];
              const isNewKey = !info?.keys?.includes(k);
              return (
                <tr key={k} className={removed ? "removed" : typed ? "typed" : ""}>
                  <td className="mono key">{k}{isNewKey && <span className="badge kind equal">new</span>}</td>
                  <td className="bval">
                    {ed ? (
                      <div className="value-editor">
                        <textarea className="mono" rows={Math.min(8, Math.max(1, ed.text.split("\n").length))} value={ed.text}
                                  aria-label={`New value for ${k}`} spellCheck={false}
                                  onChange={(e) => setEditing({ ...editing, [k]: { ...ed, text: e.target.value, error: undefined } })} />
                        <div className="editor-tools">
                          <label className="inline-check"><input type="checkbox" checked={ed.json} onChange={(e) => setEditing({ ...editing, [k]: { ...ed, json: e.target.checked } })} /> JSON</label>
                          {ed.error && <span className="error-text">{ed.error}</span>}
                          <button type="button" className="btn ghost small" title="A random value: 24 random bytes, base64url"
                                  onClick={() => setEditing({ ...editing, [k]: { text: randomValue(), json: false } })}>Generate</button>
                          <button type="button" className="btn small" onClick={() => commitEditor(k)}>Set value</button>
                          <button type="button" className="btn ghost small" onClick={() => { const { [k]: _d, ...rest } = editing; setEditing(rest); }}>Cancel</button>
                        </div>
                      </div>
                    ) : typed ? (
                      <><span className="mono typed-value">{formatValue(draft.set[k])}</span> <span className="badge different">new value</span></>
                    ) : (
                      <>
                        <span className={`mono${removed ? " struck" : ""}`}>
                          {shownValue(k) ? formatValue(values![k]) : "••••••••"}
                        </span>
                        {shownValue(k) && <span className="subtle type"> {typeName(values![k])}</span>}
                      </>
                    )}
                    {hist(k) && !viewingOld && !typed && (
                      <div className="subtle changed" title={absoluteTime(hist(k)!.time)}>
                        changed {hist(k)!.exact ? "" : "≥ "}{relativeTime(hist(k)!.time)} · v{hist(k)!.version}
                      </div>
                    )}
                  </td>
                  <td className="tools">
                    {!typed && !isNewKey && info?.caps.read !== false && !reveal && (
                      <button type="button" className="btn ghost small" aria-pressed={shown.has(k)}
                              onClick={() => setShown((s) => { const n = new Set(s); if (n.has(k)) n.delete(k); else n.add(k); return n; })}>
                        {shown.has(k) ? "Hide" : "Show"}
                      </button>
                    )}
                    {config.allow_clipboard !== false && shownValue(k) && !typed && (
                      <button type="button" className="btn ghost small" onClick={() => copy(k, values![k])}
                              title="Copy to the clipboard (cleared after 30 seconds where the browser allows)">{copied === k ? "Copied" : "Copy"}</button>
                    )}
                    {!typed && !isNewKey && info?.caps.read !== false && (
                      <button type="button" className="btn ghost small" onClick={() => onInspect([{ side: "left", title: `${target.label} · ${path} · ${k}`, loc: loc(k) }])}>Inspect</button>
                    )}
                    {canWrite && !ed && !removed && (
                      <button type="button" className="btn ghost small" onClick={() => setEditing({ ...editing, [k]: typed
                        ? { text: asText(draft.set[k]), json: typeof draft.set[k] !== "string" }
                        : values && k in values ? { text: asText(values[k]), json: typeof values[k] !== "string" } : { text: "", json: false } })}>Edit</button>
                    )}
                    {canWrite && (typed || removed) && (
                      <button type="button" className="btn ghost small" onClick={() => {
                        const { [k]: _d, ...set } = draft.set;
                        setDraft({ ...draft, set, remove: draft.remove.filter((x) => x !== k) });
                      }}>Undo</button>
                    )}
                    {canWrite && !typed && !removed && !isNewKey && (
                      <button type="button" className="btn ghost small danger" onClick={() => setDraft({ ...draft, remove: [...draft.remove, k] })}>Delete</button>
                    )}
                  </td>
                </tr>
              );
            })}
            {keys.length === 0 && <tr><td colSpan={3} className="subtle">No keys yet.</td></tr>}
          </tbody>
        </table>
      )}

      {canWrite && (info?.state === "present" || missing) && (
        <form className="add-key" onSubmit={(e) => {
          e.preventDefault();
          const k = newKey.trim();
          if (!k) return;
          if (keys.includes(k)) { setError(`${k} already exists: use Edit.`); return; }
          setEditing({ ...editing, [k]: { text: "", json: false } });
          setDraft({ ...draft, set: { ...draft.set, [k]: "" } });
          setNewKey("");
        }}>
          <input type="text" className="mono" placeholder="new key name" aria-label="New key name" value={newKey} onChange={(e) => setNewKey(e.target.value)} />
          <button type="submit" className="btn small" disabled={!newKey.trim()}>＋ Add key</button>
        </form>
      )}

      {pending > 0 && (
        <div className="inline-confirm" role="region" aria-label="Unsaved changes">
          <div>
            <strong>{pending} unsaved change{pending === 1 ? "" : "s"}</strong>{" "}
            <span className="subtle">
              {[...Object.keys(draft.set).map((k) => (info?.keys?.includes(k) ? `${k} changed` : `${k} added`)), ...draft.remove.map((k) => `${k} removed`)].join(" · ")}
              {missing || !info?.current_version ? " · creates v1" : ` · becomes v${(info.current_version ?? 0) + 1}`}
              {info?.keys && draft.remove.length === info.keys.length && !Object.keys(draft.set).length && " · every key goes, so the latest version is deleted instead"}
            </span>
          </div>
          <div className="row">
            <button type="button" className="btn ghost small" onClick={() => { setDraft({ set: {}, remove: [], isNew: missing }); setEditing({}); }}>Discard</button>
            <button type="button" className="btn primary small" disabled={busy || Object.keys(editing).length > 0}
                    title={Object.keys(editing).length ? "Finish or cancel the open editors first" : undefined}
                    onClick={() => run({ path, action: "write", expected_version: expected, set: draft.set, remove: draft.remove },
                                       `${path}: ${pending} change${pending === 1 ? "" : "s"}`)}>
              {busy && <span className="spinner" />} {stage ? "Stage" : "Save"}
            </button>
          </div>
        </div>
      )}

      {confirm && (
        <div className="inline-confirm danger" role="alertdialog" aria-label="Confirm">
          <div><strong>{confirm.label}?</strong>
            {confirm.typed !== undefined && <> Type <code className="phrase">{confirm.typed}</code> to confirm:
              <input type="text" className="mono" aria-label="Confirmation phrase" autoFocus value={confirm.entered ?? ""}
                     onChange={(e) => setConfirm({ ...confirm, entered: e.target.value })} /></>}
          </div>
          <div className="row">
            <button type="button" className="btn ghost small" onClick={() => setConfirm(null)}>Cancel</button>
            <button type="button" className="btn small danger-solid" disabled={busy || (confirm.typed !== undefined && confirm.entered !== confirm.typed)}
                    onClick={() => run(confirm.edit, confirm.label)}>{busy && <span className="spinner" />} Confirm</button>
          </div>
        </div>
      )}

      {info && info.versions.length > 0 && (
        <section className="versions">
          <h3>Versions</h3>
          <div className="chips-wrap" role="group" aria-label="Versions">
            {info.versions.map((v) => (
              <button key={v.version} type="button" className={`chip${v.deleted ? " deleted" : ""}${v.destroyed ? " destroyed" : ""}`}
                      aria-pressed={(version ?? info.current_version) === v.version}
                      title={`${absoluteTime(v.created)}${v.by ? ` · written by ${v.by}` : ""}${v.deleted_by ? ` · deleted by ${v.deleted_by}` : ""}`}
                      onClick={() => setVersion(v.version === info.current_version ? null : v.version)}>
                v{v.version}{v.version === info.current_version ? " (current)" : ""}{v.destroyed ? " destroyed" : v.deleted ? " deleted" : ""}
                <span className="n">{relativeTime(v.created)}</span>
              </button>
            ))}
          </div>
          {viewingOld && (
            <div className="row version-actions">
              {vInfo && !vInfo.deleted && !vInfo.destroyed && <button type="button" className="btn ghost small" onClick={showDiff}>Compare with v{info.current_version}</button>}
              {writable && vInfo && !vInfo.deleted && !vInfo.destroyed && info.caps.write !== false && (
                <button type="button" className="btn small" onClick={() => setConfirm({ label: `Roll back to v${version} (writes it as v${(info.current_version ?? 0) + 1})`,
                  edit: { path, action: "rollback", expected_version: expected, rollback_to: version! } })}>Roll back to v{version}</button>
              )}
              {writable && vInfo?.deleted && !vInfo.destroyed && info.caps.undelete !== false && (
                <button type="button" className="btn small" onClick={() => setConfirm({ label: `Undelete v${version}`, edit: { path, action: "undelete", versions: [version!] } })}>Undelete v{version}</button>
              )}
              {writable && vInfo && !vInfo.destroyed && config.allow_destroy !== false && target.destroy !== false && info.caps.destroy_versions !== false && (
                <button type="button" className="btn ghost small danger" onClick={() => setConfirm({ label: `Destroy the data of v${version} (can’t be undone)`, typed: `destroy v${version}`,
                  edit: { path, action: "destroy", versions: [version!] } })}>Destroy v{version}…</button>
              )}
            </div>
          )}
          {diff && (
            <table className="plan-keys version-diff">
              <thead><tr><th>Key</th><th>v{diff.a} → v{diff.b}</th>{reveal && <><th>v{diff.a}</th><th>v{diff.b}</th></>}</tr></thead>
              <tbody>
                {diff.keys.map((k) => (
                  <tr key={k.key} className={k.change}>
                    <td className="mono">{k.key}</td><td><span className={`action ${k.change === "added" ? "add" : k.change === "removed" ? "remove" : k.change === "changed" ? "update" : "unchanged"}`}>{k.change}</span></td>
                    {reveal && <><td className="mono">{k.a === undefined ? "—" : formatValue(k.a)}</td><td className="mono">{k.b === undefined ? "—" : formatValue(k.b)}</td></>}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      )}

      {info?.metadata && editingMeta && (
        <MetadataEditor info={info} conn_id={target.conn_id} onCancel={() => setEditingMeta(false)}
                        onSaved={(m) => { setEditingMeta(false); setNotice(m); loadInfo(version); }} />
      )}
      {info?.metadata && !editingMeta && (
        <details className="metadata">
          <summary>Metadata</summary>
          <dl>
            <dt>Created</dt><dd title={absoluteTime(info.metadata.created_time)}>{relativeTime(info.metadata.created_time)}</dd>
            <dt>Updated</dt><dd title={absoluteTime(info.metadata.updated_time)}>{relativeTime(info.metadata.updated_time)}</dd>
            <dt>Max versions</dt><dd>{info.metadata.max_versions || "mount default"}</dd>
            <dt>Check-and-set required</dt><dd>{info.metadata.cas_required ? "yes" : "no"}</dd>
            {info.metadata.updated_by && <><dt>Last changed by</dt><dd>{info.metadata.updated_by}</dd></>}
            <dt>Delete versions after</dt><dd>{info.metadata.delete_version_after && info.metadata.delete_version_after !== "0s" ? info.metadata.delete_version_after : "never"}</dd>
            {Object.entries(info.metadata.custom_metadata ?? {}).map(([k, v]) => <Fragment key={k}><dt className="mono">{k}</dt><dd className="mono">{v}</dd></Fragment>)}
          </dl>
          {writable && <button type="button" className="btn ghost small" onClick={() => setEditingMeta(true)}>Edit metadata</button>}
        </details>
      )}
      {info?.metadata_error && <div className="subtle">Metadata: {info.metadata_error}</div>}

      {info && (
        <footer className="panel-foot">
          <div className="row">
            <button type="button" className="btn ghost small" onClick={() => onGo("compare", folder)}>Compare this folder…</button>
            <button type="button" className="btn ghost small" onClick={() => onGo("expiry", folder)}>Scan for certificates</button>
            <button type="button" className="btn ghost small" onClick={() => onGo("policies", folder)}>Why can I…?</button>
            <button type="button" className="btn ghost small" onClick={() => onGo("policy-build", folder)}
                    title="Start a policy draft that lets someone read this folder; adjust it in Policies › Build">Policy for this folder…</button>
            {(target.export ?? config.export_mode) !== "off" && <button type="button" className="btn ghost small" onClick={() => onGo("transfer", folder)}>Export this folder…</button>}
            {info.state === "present" && info.caps.read !== false && (
              <button type="button" className="btn ghost small" aria-expanded={sharing} onClick={() => setSharing(!sharing)}>Share once…</button>
            )}
            <button type="button" className="btn ghost small" aria-expanded={snippets} onClick={() => setSnippets(!snippets)}>Snippets</button>
          </div>
          {writable && !viewingOld && (
            <div className="row">
              {info.state === "present" && info.caps.delete !== false && (
                <button type="button" className="btn ghost small danger" onClick={() => setConfirm({ label: `Delete the latest version (v${info.current_version}); vault kv undelete brings it back`,
                  edit: { path, action: "delete", expected_version: expected } })}>Delete latest</button>
              )}
              {info.state === "deleted" && info.caps.undelete !== false && (
                <button type="button" className="btn small" onClick={() => setConfirm({ label: `Undelete v${info.current_version}`, edit: { path, action: "undelete", versions: [info.current_version!] } })}>Undelete v{info.current_version}</button>
              )}
              {writable && config.allow_destroy !== false && target.destroy !== false && info.caps.destroy !== false && (
                <button type="button" className="btn ghost small danger" onClick={() => setDestroying(true)}>Destroy secret…</button>
              )}
            </div>
          )}
        </footer>
      )}

      {sharing && info && (
        <SharePanel conn_id={target.conn_id} mount={target.mount} path={path} keys={info.keys ?? []} version={viewingOld ? version : null}
                    onClose={() => setSharing(false)} />
      )}
      {snippets && (
        <Snippets mount={target.mount} path={path} keys={keys} url={target.url}
                  pending={pending ? { set: Object.keys(draft.set), remove: draft.remove } : undefined} />
      )}

      {destroying && info && (
        <DestroyDialog sideLabel={target.label} vault={{ conn_id: target.conn_id, mount: target.mount, prefix: "" }}
                       secrets={[{ path, version: info.current_version }]}
                       onClose={(done) => { setDestroying(false); if (done) { onChanged(); onGone(); } }} />
      )}
    </div>
  );
}

/** The staged edits, previewed and applied together. */
function BrowseReview({ target, staged, reveal, onClose }: { target: BrowseTarget; staged: Staged[]; reveal: boolean; onClose: (done: boolean) => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const [preview, setPreview] = useState<BrowseEditResult[] | null>(null);
  const [applied, setApplied] = useState<BrowseEditResult[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [undoFile, setUndoFile] = useState<string | null>(null);
  const edits = staged.map((s) => s.edit);
  const undoWrites = applied ? browseUndoWrites(target.conn_id, target.mount, applied) : [];

  useEffect(() => { ref.current?.showModal(); }, []);
  useEffect(() => {
    api.browsePreview(target.conn_id, target.mount, edits, reveal).then(setPreview).catch((e) => setError(e.message));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  async function apply() {
    setBusy(true);
    try { setApplied(await api.browseApply(target.conn_id, target.mount, edits)); } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }
  const rows = applied ?? preview ?? [];
  const ready = (preview ?? []).filter((r) => r.status === "ready").length;
  return (
    <dialog ref={ref} className="review" onClose={() => onClose(Boolean(applied?.some((r) => r.status === "applied")))}>
      <header className="review-head">
        <h2>{applied ? "Changes saved" : "Review changes"}</h2>
        <button type="button" className="btn ghost icon small" aria-label="Close" onClick={() => ref.current?.close()} disabled={busy}>✕</button>
      </header>
      <div className="review-body">
        {error && <div className="notice error">{error}</div>}
        {!preview && !error && <div className="empty"><span className="spinner" /> Checking…</div>}
        <ul className="plan-list">
          {rows.map((r, i) => (
            <li key={i} className={`plan ${["conflict", "denied", "invalid", "error"].includes(r.status) ? r.status : ""}`}>
              <div className="plan-head">
                <span className="mono">{target.mount}/{r.path}</span>
                <span className={`badge ${r.status === "ready" || r.status === "applied" ? "equal" : r.status === "noop" ? "unknown" : "error"}`}>{r.status}</span>
              </div>
              <div className="subtle">{r.action}{r.versions.length ? ` v${r.versions.join(", v")}` : ""}
                {r.new_version ? ` · v${r.old_version ?? "—"} → v${r.new_version}` : ""}{r.message ? ` · ${r.message}` : ""}</div>
              {r.keys.filter((k) => k.action !== "unchanged").length > 0 && (
                <table className="plan-keys"><tbody>
                  {r.keys.filter((k) => k.action !== "unchanged").map((k) => (
                    <tr key={k.key}><td className="mono">{k.key}</td><td><span className={`action ${k.action}`}>{k.action}</span></td>
                      {reveal && !applied && <td className="mono vals">{k.action === "remove" ? <s>{formatValue(k.old)}</s> : <>{k.action === "update" && <><s>{formatValue(k.old)}</s> → </>}{formatValue(k.new)}</>}</td>}</tr>
                  ))}
                </tbody></table>
              )}
            </li>
          ))}
        </ul>
      </div>
      <footer className="review-foot">
        <span className="spacer" />
        {applied && undoWrites.length > 0 && (
          <button type="button" className="btn ghost" disabled={Boolean(undoFile)}
                  title="A signed file that puts back what was saved, for you or someone else to apply in Sync plans"
                  onClick={async () => { try { setUndoFile(await downloadUndo(undoWrites)); } catch (e) { setError((e as Error).message); } }}>
            {undoFile ? `Undo plan saved as ${undoFile}` : "Make an undo plan"}</button>
        )}
        {applied ? <button type="button" className="btn primary" onClick={() => ref.current?.close()}>Close</button> : (
          <>
            <button type="button" className="btn ghost" onClick={() => ref.current?.close()} disabled={busy}>Cancel</button>
            <button type="button" className="btn primary" onClick={apply} disabled={busy || !ready}>
              {busy && <span className="spinner" />} Apply {ready} change{ready === 1 ? "" : "s"}
            </button>
          </>
        )}
      </footer>
    </dialog>
  );
}
