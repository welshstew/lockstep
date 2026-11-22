import { useState } from "react";
import { api, ApiError } from "../api";
import type { AppConfig, Connection, LoadedFile, SideSelection } from "../types";
import { ConnectForm } from "./ConnectForm";
import { FileLoader, FileSummary } from "./FileLoader";
import { MountSelect } from "./MountSelect";

interface Props {
  side: "left" | "right";
  config: AppConfig;
  connections: Connection[];
  selection: SideSelection;
  onChange: (s: SideSelection) => void;
  onConnected: (c: Connection) => void;
  onDisconnect: (id: string) => void;
  /** Export files opened in this page, and a callback for a newly opened one */
  files: LoadedFile[];
  onFile: (f: LoadedFile) => void;
}

const NEW = "__new__";

function expiry(c: Connection): string {
  if (!c.expires_at) return "no expiry";
  const mins = Math.round((c.expires_at * 1000 - Date.now()) / 60000);
  if (mins <= 0) return "expired";
  if (mins < 90) return `expires in ${mins} min`;
  const hours = Math.round(mins / 60);
  return hours < 48 ? `expires in ${hours} h` : `expires in ${Math.round(hours / 24)} days`;
}

const COLLAPSE_KEY = (side: string) => `lockstep.collapsed.${side}`;

function loadCollapsed(side: string): boolean {
  try { return localStorage.getItem(COLLAPSE_KEY(side)) === "1"; } catch { return false; }
}

/** One line about what this side is: the account signed in and where it points. */
function Summary({ conn, file, selection }: { conn: Connection | null; file: LoadedFile | null; selection: SideSelection }) {
  const where = selection.mount ? `${selection.mount}${selection.prefix ? `/${selection.prefix.replace(/^\/+|\/+$/g, "")}` : ""}` : null;
  if (file) {
    return (
      <div className="side-summary">
        <span className="dot ok" />
        <span className="who"><strong>{file.name}</strong> <span className="subtle">export file, read-only</span></span>
        {selection.prefix && <span className="mono">{selection.prefix}</span>}
      </div>
    );
  }
  if (!conn) return <div className="side-summary"><span className="dot unknown" /><span className="subtle">Not connected. Expand to sign in.</span></div>;
  const policies = conn.policies.filter((p) => p !== "default");
  return (
    <div className="side-summary">
      <span className={`dot ${conn.status}`} title={conn.status} />
      <span className="who">
        <strong>{conn.display_name || conn.auth_method}</strong>{" "}
        <span className="subtle">via {conn.auth_method} on</span> <strong>{conn.name}</strong>
        {conn.namespace && <span className="subtle"> · namespace {conn.namespace}</span>}
      </span>
      <span className="subtle" title={conn.policies.join(", ")}>
        {policies.length ? `policies: ${policies.join(", ")}` : "default policy only"} · {expiry(conn)}
      </span>
      {where ? <span className="mono where">{where}</span> : <span className="subtle">no mount chosen</span>}
    </div>
  );
}

export function SideCard(props: Props) {
  const { side, files, selection, onChange, onFile, connections } = props;
  const [collapsed, setCollapsedState] = useState(() => loadCollapsed(side));
  const setCollapsed = (c: boolean) => {
    setCollapsedState(c);
    try { localStorage.setItem(COLLAPSE_KEY(side), c ? "1" : "0"); } catch { /* ignore */ }
  };
  // The selection decides when it can (it follows ⇄ swaps); the switch only matters for an empty side.
  const [wantFile, setWantFile] = useState(false);
  const mode: "vault" | "file" = selection.fileId ? "file" : selection.connId ? "vault" : wantFile ? "file" : "vault";
  const setMode = (m: "vault" | "file") => setWantFile(m === "file");
  const file = files.find((f) => f.id === selection.fileId) ?? null;

  return (
    <section className={`card side-card ${side}${collapsed ? " collapsed" : ""}`} aria-label={`${side} side`}>
      <div className="side-head">
        <button type="button" className="collapse-btn" aria-expanded={!collapsed} onClick={() => setCollapsed(!collapsed)}
                aria-label={`${collapsed ? "Expand" : "Collapse"} the ${side} side`} title={collapsed ? "Show the connection details" : "Collapse to a summary"}>
          <span className="caret">▸</span>
          <h2 className="side-title">{side === "left" ? "Left: source" : "Right: target"}</h2>
        </button>
        {!collapsed && <div className="segmented small" role="group" aria-label={`${side} side source`}>
          <button type="button" aria-pressed={mode === "vault"} onClick={() => {
            setMode("vault");
            if (selection.fileId) onChange({ connId: null, mount: null, prefix: "" });
          }}>Vault</button>
          <button type="button" aria-pressed={mode === "file"} onClick={() => {
            setMode("file");
            if (selection.connId) onChange({ connId: null, mount: null, prefix: "" });
          }}>Export file</button>
        </div>}
      </div>
      {collapsed ? (
        <div className="summary-row">
          <button type="button" className="summary-btn" onClick={() => setCollapsed(false)} aria-label={`${side} side summary: expand`}>
            <Summary conn={connections.find((c) => c.id === selection.connId) ?? null} file={file} selection={selection} />
          </button>
          {selection.prefix && (
            <button type="button" className="btn ghost small" onClick={() => onChange({ ...selection, prefix: "" })}
                    aria-label={`Clear the path prefix on the ${side} side`} title="Remove the path prefix: use the whole mount">
              ✕ Prefix
            </button>
          )}
        </div>
      ) : mode === "vault" ? <VaultSide {...props} /> : file ? (
        <>
          <div className="conn-chip file-chip">
            <span className="dot ok" />
            <div className="who"><FileSummary f={file} /></div>
            <button type="button" className="btn ghost small" onClick={() => onChange({ connId: null, mount: null, prefix: "", fileId: null })}>
              Close
            </button>
          </div>
          <div className="subtle">Read-only: values can be copied from the file, never into it.</div>
          <label className="field">
            <span>Path prefix <span className="subtle">(optional)</span></span>
            <span className="input-with-clear">
              <input type="text" value={selection.prefix} placeholder="e.g. payments/"
                     onChange={(e) => onChange({ ...selection, prefix: e.target.value })} />
              {selection.prefix && (
                <button type="button" className="btn ghost icon small" aria-label="Clear the path prefix" title="Clear: use the whole file"
                        onClick={() => onChange({ ...selection, prefix: "" })}>✕</button>
              )}
            </span>
          </label>
        </>
      ) : (
        <>
          {files.length > 0 && (
            <label className="field">
              <span>Opened files</span>
              <select value="" onChange={(e) => e.target.value && onChange({ connId: null, mount: null, prefix: "", fileId: e.target.value })}>
                <option value="">Choose…</option>
                {files.map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
              </select>
            </label>
          )}
          <FileLoader onLoaded={(f) => { onFile(f); onChange({ connId: null, mount: null, prefix: "", fileId: f.id }); }} />
          <p className="subtle">A secret-engine export from <strong>Export &amp; import</strong> or <code>lockstep export</code>. It stays in this page only.</p>
        </>
      )}
    </section>
  );
}

function VaultSide({ side, config, connections, selection, onChange, onConnected, onDisconnect }: Props) {
  const conn = connections.find((c) => c.id === selection.connId) ?? null;
  const [adding, setAdding] = useState(false);
  const [renewing, setRenewing] = useState(false);
  const [renewNote, setRenewNote] = useState<{ id: string; text: string; error?: boolean } | null>(null);
  const renew = async (c: Connection) => {
    setRenewing(true);
    try {
      const r = await api.renew(c.id);
      setRenewNote({ id: c.id, text: r.capped ? `Renewed up to the token's max TTL: ${expiry(r)}. Sign in again for more time.`
                                              : `Renewed: ${expiry(r)}.` });
      onConnected(r);
    } catch (e) {
      setRenewNote({ id: c.id, text: e instanceof ApiError ? e.message : String(e), error: true });
    } finally {
      setRenewing(false);
    }
  };
  // With no connection chosen, show the sign-in form straight away; the dropdown above it
  // lets the user reuse an existing connection instead (e.g. same Vault, another mount).
  const showForm = adding || !conn;

  return (
    <>
      {connections.length > 0 && (
        <label className="field">
          <span>Connection</span>
          <select
            value={showForm ? NEW : conn!.id}
            onChange={(e) => {
              if (e.target.value === NEW) { setAdding(true); return; }
              setAdding(false);
              onChange({ connId: e.target.value || null, mount: null, prefix: "" });
            }}
          >
            {connections.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name} · {c.display_name || c.auth_method}{c.status !== "ok" ? ` (${c.status})` : ""}
              </option>
            ))}
            <option value={NEW}>＋ New connection…</option>
          </select>
        </label>
      )}

      {showForm ? (
        <ConnectForm
          config={config}
          side={side}
          initialPresetId={conn?.preset_id ?? (side === "right" ? config.presets[1]?.id : config.presets[0]?.id)}
          onCancel={adding && conn ? () => setAdding(false) : undefined}
          onConnected={(c) => {
            setAdding(false);
            onConnected(c);
            onChange({ connId: c.id, mount: null, prefix: "" });
          }}
        />
      ) : conn && (
        <>
          <div className="conn-chip">
            <span className={`dot ${conn.status}`} title={conn.status} />
            <div className="who">
              <div className="name">{conn.display_name || conn.auth_method}</div>
              <div className="meta" title={conn.policies.join(", ")}>
                {conn.policies.filter((p) => p !== "default").join(", ") || "default"} · {expiry(conn)}
              </div>
            </div>
            {conn.renewable && conn.status === "ok" && (
              <button type="button" className="btn ghost small" disabled={renewing} onClick={() => renew(conn)}
                      title="Extend this token's lifetime (up to its max TTL)">
                {renewing ? "Renewing…" : "Renew"}
              </button>
            )}
            <button type="button" className="btn ghost small" onClick={() => onDisconnect(conn.id)}
                    title={conn.auth_method === "token" ? "Forget this connection" : "Sign out and revoke the token"}>
              Sign out
            </button>
          </div>

          {renewNote?.id === conn.id && (
            <div className={`notice ${renewNote.error ? "error" : "info"}`} role="status">{renewNote.text}</div>
          )}

          {conn.status === "expired" ? (
            <div className="notice error">
              This token is no longer valid.{" "}
              <button type="button" className="btn small" onClick={() => setAdding(true)}>Sign in again</button>
            </div>
          ) : (
            <>
              <MountSelect connId={conn.id} mount={selection.mount}
                           onChange={(mount) => onChange({ ...selection, mount, prefix: "" })} />
              <label className="field">
                <span>Path prefix <span className="subtle">(optional)</span></span>
                <span className="input-with-clear">
                  <input type="text" value={selection.prefix} placeholder="e.g. payments/"
                         disabled={!selection.mount}
                         onChange={(e) => onChange({ ...selection, prefix: e.target.value })} />
                  {selection.prefix && (
                    <button type="button" className="btn ghost icon small" aria-label="Clear the path prefix" title="Clear: use the whole mount"
                            onClick={() => onChange({ ...selection, prefix: "" })}>✕</button>
                  )}
                </span>
              </label>
            </>
          )}
        </>
      )}
    </>
  );
}
