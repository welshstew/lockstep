import { useState } from "react";
import { api } from "../api";
import type { Connection, MfaConstraint } from "../types";

const KIND: Record<string, string> = { totp: "authenticator app code", duo: "Duo", okta: "Okta", pingid: "PingID" };

/** The second factor Vault asked for at sign-in (login MFA): a passcode, or approving a push. */
export function MfaPrompt({ constraints, onDone, onCancel }: { constraints: MfaConstraint[]; onDone: (c: Connection) => void; onCancel: () => void }) {
  const [chosen, setChosen] = useState<Record<string, string>>(() => Object.fromEntries(constraints.map((c) => [c.name, c.methods[0]?.id ?? ""])));
  const [codes, setCodes] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const push = constraints.some((c) => c.methods.find((m) => m.id === chosen[c.name])?.uses_passcode === false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onDone(await api.answerMfa(Object.fromEntries(constraints.map((c) => [chosen[c.name], codes[chosen[c.name]] ?? ""]))));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <form className="mfa-prompt" onSubmit={submit} aria-label="Second factor">
      <div><strong>Vault asks for a second factor.</strong></div>
      {constraints.map((c) => {
        const m = c.methods.find((x) => x.id === chosen[c.name]) ?? c.methods[0];
        return (
          <div key={c.name} className="field">
            {c.methods.length > 1 && (
              <select aria-label={`Method for ${c.name}`} value={chosen[c.name]} onChange={(e) => setChosen({ ...chosen, [c.name]: e.target.value })}>
                {c.methods.map((x) => <option key={x.id} value={x.id}>{KIND[x.type] ?? x.type}</option>)}
              </select>
            )}
            {m.uses_passcode ? (
              <label className="field"><span>{KIND[m.type] ?? m.type}</span>
                <input type="text" inputMode="numeric" autoComplete="one-time-code" autoFocus className="mono" aria-label="Passcode"
                       value={codes[m.id] ?? ""} onChange={(e) => setCodes({ ...codes, [m.id]: e.target.value })} /></label>
            ) : (
              <div className="subtle">Approve the sign-in request in {KIND[m.type] ?? m.type} on your device, then press Continue.</div>
            )}
          </div>
        );
      })}
      {error && <div className="notice error" role="alert">{error}</div>}
      <div className="row">
        <button type="button" className="btn ghost small" onClick={onCancel} disabled={busy}>Cancel</button>
        <button type="submit" className="btn primary small" disabled={busy}>{busy && <span className="spinner" />} {push ? "Continue" : "Verify"}</button>
      </div>
    </form>
  );
}
