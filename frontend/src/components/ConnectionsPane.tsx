import { useState } from "react";
import { api, ApiError } from "../api";
import type { AppConfig, Connection, SideSelection } from "../types";
import { ConnectForm } from "./ConnectForm";
import { MountSelect } from "./MountSelect";
import { NamespacePicker } from "./NamespacePicker";
import { expiry } from "./SideCard";

interface Props {
  config: AppConfig;
  connections: Connection[];
  onConnected: (c: Connection) => void;
  onDisconnect: (id: string) => void;
  /** Browse: the one connection and mount being explored. Without it the list only manages sign-ins (Matrix). */
  selection?: SideSelection;
  onSelect?: (s: SideSelection) => void;
  /** One line under the title: what the list is for on this tab */
  hint: string;
}

/** Every signed-in connection in one list across the page, with sign-in to another. */
export function ConnectionsPane({ config, connections, onConnected, onDisconnect, selection, onSelect, hint }: Props) {
  const selectable = !!selection && !!onSelect;
  // The sign-in form: a preset id, "new" for the default form, or closed
  const [signingIn, setSigningIn] = useState<number | "new" | null>(() => (connections.length ? null : "new"));
  const [renewing, setRenewing] = useState<string | null>(null);
  const [note, setNote] = useState<{ id: string; text: string; error?: boolean } | null>(null);
  const showForm = signingIn !== null || connections.length === 0;

  const renew = async (c: Connection) => {
    setRenewing(c.id);
    try {
      const r = await api.renew(c.id);
      setNote({ id: c.id, text: r.capped ? `Renewed up to the token's max TTL: ${expiry(r)}. Sign in again for more time.` : `Renewed: ${expiry(r)}.` });
      onConnected(r);
    } catch (e) {
      setNote({ id: c.id, text: e instanceof ApiError ? e.message : String(e), error: true });
    } finally {
      setRenewing(null);
    }
  };
  const pick = (id: string) => {
    if (!selectable || selection!.connId === id) return;
    onSelect!({ connId: id, mount: null, prefix: "" });
  };

  return (
    <section className="card conn-pane" aria-label="Connections">
      <div className="conn-pane-head">
        <h2>Connections</h2>
        <span className="subtle">{hint}</span>
      </div>

      {connections.length > 0 && (
        <ul className="conn-list" role={selectable ? "radiogroup" : undefined} aria-label={selectable ? "Connection to browse" : "Signed-in connections"}>
          {connections.map((c) => {
            const chosen = selectable && selection!.connId === c.id;
            const policies = c.policies.filter((p) => p !== "default");
            const who = (
              <>
                <span className={`dot ${c.status}`} title={c.status} />
                <span className="conn-name"><strong>{c.name}</strong>{c.namespace && <span className="subtle"> · namespace {c.namespace}</span>}</span>
                <span className="conn-user">{c.display_name || c.auth_method} <span className="subtle">via {c.auth_method}</span></span>
                <span className="subtle conn-meta" title={c.policies.join(", ")}>
                  {policies.length ? `policies: ${policies.join(", ")}` : "default policy only"} · {expiry(c)}
                </span>
              </>
            );
            return (
              <li key={c.id} className={`conn-row${chosen ? " chosen" : ""}`}>
                <div className="conn-line">
                  {selectable ? (
                    <button type="button" role="radio" aria-checked={chosen} className="conn-pick"
                            aria-label={`Browse ${c.name} as ${c.display_name || c.auth_method}`} onClick={() => pick(c.id)}>
                      <span className="radio" aria-hidden="true" />{who}
                    </button>
                  ) : <div className="conn-pick static">{who}</div>}
                  <span className="conn-actions">
                    {c.renewable && c.status === "ok" && (
                      <button type="button" className="btn ghost small" disabled={renewing === c.id} onClick={() => renew(c)}
                              title="Extend this token's lifetime (up to its max TTL)">{renewing === c.id ? "Renewing…" : "Renew"}</button>
                    )}
                    {c.status === "expired" && (
                      <button type="button" className="btn small" onClick={() => setSigningIn(c.preset_id ?? "new")}>Sign in again</button>
                    )}
                    <button type="button" className="btn ghost small" onClick={() => onDisconnect(c.id)}
                            aria-label={`${c.parent ? "Close" : "Sign out of"} ${c.name}`}
                            title={c.parent ? "Close this namespace (the sign-in it came from stays)"
                              : c.auth_method === "token" ? "Forget this connection" : "Sign out and revoke the token"}>
                      {c.parent ? "Close" : "Sign out"}
                    </button>
                  </span>
                </div>
                {note?.id === c.id && <div className={`notice ${note.error ? "error" : "info"}`} role="status">{note.text}</div>}
                {chosen && c.status !== "expired" && (
                  <div className="conn-where">
                    <NamespacePicker conn={c} connections={connections} onPick={(n, opened) => {
                      if (opened) onConnected(n);
                      onSelect!({ connId: n.id, mount: null, prefix: "" });
                    }} />
                    <MountSelect connId={c.id} mount={selection!.mount}
                                 onChange={(mount, version) => onSelect!({ ...selection!, mount, prefix: "", kvVersion: version })} />
                    <label className="field">
                      <span>Path prefix <span className="subtle">(optional)</span></span>
                      <span className="input-with-clear">
                        <input type="text" value={selection!.prefix} placeholder="e.g. payments/" disabled={!selection!.mount}
                               onChange={(e) => onSelect!({ ...selection!, prefix: e.target.value })} />
                        {selection!.prefix && (
                          <button type="button" className="btn ghost icon small" aria-label="Clear the path prefix" title="Clear: use the whole mount"
                                  onClick={() => onSelect!({ ...selection!, prefix: "" })}>✕</button>
                        )}
                      </span>
                    </label>
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}

      {showForm ? (
        <div className="conn-signin">
          <ConnectForm
            key={String(signingIn)}  // a new choice starts the form on that Vault
            config={config}
            initialPresetId={typeof signingIn === "number" ? signingIn : config.presets[0]?.id}
            onCancel={connections.length ? () => setSigningIn(null) : undefined}
            onConnected={(c) => {
              setSigningIn(null);
              onConnected(c);
              if (selectable) onSelect!({ connId: c.id, mount: null, prefix: "" });
            }}
          />
        </div>
      ) : (
        <div className="conn-add" role="group" aria-label="Sign in to another">
          <span className="subtle">Sign in to:</span>
          {config.presets.map((p) => (
            <button key={p.id} type="button" className="btn small" onClick={() => setSigningIn(p.id)}>{p.name}</button>
          ))}
          <button type="button" className="btn ghost small" onClick={() => setSigningIn("new")}>＋ New connection</button>
        </div>
      )}
    </section>
  );
}
