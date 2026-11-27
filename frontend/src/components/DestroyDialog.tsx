import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import type { DestroyOut, DestroyStatus } from "../types";

export interface DestroyTarget {
  path: string; // relative to the side's prefix
  version: number | null; // the current version seen in the comparison
}

interface Props {
  /** Compare's side; Browse has no sides */
  side?: "left" | "right";
  sideLabel: string;
  vault: { conn_id: string; mount: string; prefix: string };
  secrets: DestroyTarget[];
  onClose: (destroyed: boolean) => void;
}

const RESULT_LABEL: Record<DestroyStatus, string> = {
  destroyed: "Destroyed", absent: "Already gone", conflict: "Changed: not destroyed",
  denied: "Denied: not destroyed", error: "Failed",
};
const tone = (s: DestroyStatus) => (s === "destroyed" ? "equal" : s === "absent" ? "unknown" : s === "conflict" ? "different" : "error");
const LISTED = 200;

/** The phrase to type before destroying: the secret's path, or "destroy N secrets". */
export const destroyPhrase = (secrets: DestroyTarget[]) =>
  secrets.length === 1 ? secrets[0].path : `destroy ${secrets.length} secrets`;

/** Permanently delete secrets on one side, after typing a confirmation phrase. */
export function DestroyDialog({ side, sideLabel, vault, secrets, onClose }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const [typed, setTyped] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<DestroyOut | null>(null);
  const phrase = destroyPhrase(secrets);
  const n = secrets.length;
  const what = n === 1 ? "this secret" : `these ${n} secrets`;
  const prefix = vault.prefix.replace(/^\/+|\/+$/g, "");
  const base = `${vault.mount}/${prefix ? `${prefix}/` : ""}`;

  useEffect(() => { ref.current?.showModal(); }, []);

  async function run() {
    setRunning(true);
    setError(null);
    try {
      setDone(await api.destroy(vault, secrets.map((s) => ({ path: s.path, expected_version: s.version }))));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunning(false);
    }
  }

  return (
    <dialog ref={ref} className="review destroy-dialog" aria-label="Destroy secrets"
            onClose={() => onClose(Boolean(done?.summary.destroyed))} onCancel={(e) => { if (running) e.preventDefault(); }}>
      <header className="review-head">
        <h2>{done ? "Destroy finished" : `Destroy ${n === 1 ? "secret" : `${n} secrets`}${side ? ` on the ${side}` : ""}`}</h2>
        <button type="button" className="btn ghost icon small" aria-label="Close" onClick={() => ref.current?.close()} disabled={running}>✕</button>
      </header>

      <div className="review-body">
        {error && <div className="notice error" role="alert">{error}</div>}
        {done ? (
          <>
            <div className="notice info" role="status">
              {done.summary.destroyed} destroyed
              {(["absent", "conflict", "denied", "error"] as DestroyStatus[]).filter((s) => done.summary[s]).map((s) => ` · ${done.summary[s]} ${RESULT_LABEL[s].toLowerCase()}`)}
              . The comparison runs again when you close this.
            </div>
            <ul className="plan-list">
              {done.results.filter((r) => r.status !== "destroyed").concat(done.results.filter((r) => r.status === "destroyed")).slice(0, LISTED).map((r) => (
                <li key={r.path} className={`plan ${r.status === "destroyed" || r.status === "absent" ? "" : r.status}`}>
                  <div className="plan-head">
                    <span className="mono">{r.target}</span>
                    <span className={`badge ${tone(r.status)}`}>{RESULT_LABEL[r.status]}</span>
                  </div>
                  <div className="subtle">
                    {r.status === "destroyed" ? `${r.versions ?? "?"} version${r.versions === 1 ? "" : "s"} and the metadata` : r.message}
                  </div>
                </li>
              ))}
            </ul>
          </>
        ) : (
          <>
            <div className="notice error destroy-warning" role="alert">
              <strong>This can’t be undone.</strong> Destroying deletes every version of {what} and {n === 1 ? "its" : "their"} metadata
              on <strong>{sideLabel}</strong>. Unlike <strong>Delete</strong>, nothing is left for <code>vault kv undelete</code>,
              and Lockstep can’t bring {n === 1 ? "it" : "them"} back.{side && " The other side isn’t touched."}
            </div>
            <p className="subtle">
              Want a copy first? <strong>Export &amp; import</strong> can export these paths to an encrypted file.
              A secret written since you compared is skipped.
            </p>
            <ul className="destroy-list mono" aria-label="Secrets to destroy">
              {secrets.slice(0, LISTED).map((s) => (
                <li key={s.path}>{base}{s.path}
                  <span className="subtle"> v{s.version ?? "—"}</span></li>
              ))}
              {n > LISTED && <li className="subtle">…and {n - LISTED} more</li>}
            </ul>
            <label className="destroy-confirm">
              <span>Type <code className="phrase">{phrase}</code> to confirm</span>
              <input type="text" className="mono" value={typed} autoComplete="off" spellCheck={false}
                     aria-label="Confirmation phrase" onChange={(e) => setTyped(e.target.value)}
                     onKeyDown={(e) => { if (e.key === "Enter" && typed === phrase && !running) { e.preventDefault(); run(); } }} />
            </label>
          </>
        )}
      </div>

      <footer className="review-foot">
        <span className="spacer" />
        {done ? (
          <button type="button" className="btn primary" onClick={() => ref.current?.close()}>Close</button>
        ) : (
          <>
            <button type="button" className="btn ghost" onClick={() => ref.current?.close()} disabled={running}>Cancel</button>
            <button type="button" className="btn danger-solid" disabled={typed !== phrase || running} onClick={run}>
              {running ? <><span className="spinner" /> Destroying…</> : `Destroy ${n === 1 ? "permanently" : `${n} secrets permanently`}`}
            </button>
          </>
        )}
      </footer>
    </dialog>
  );
}
