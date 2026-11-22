import { useEffect, useState } from "react";
import { api } from "../api";
import type { CompareSides } from "./PolicyCompare";
import { LeasesTool } from "./LeasesTool";
import { DatabaseTool } from "./DatabaseTool";

type Op = "encrypt" | "decrypt" | "rewrap" | "sign" | "verify" | "hmac";
const OPS: { id: Op; label: string; needs: "encryption" | "signing" | "any"; input: string }[] = [
  { id: "encrypt", label: "Encrypt", needs: "encryption", input: "Plaintext" },
  { id: "decrypt", label: "Decrypt", needs: "encryption", input: "Ciphertext (vault:v1:…)" },
  { id: "rewrap", label: "Rewrap", needs: "encryption", input: "Ciphertext to rewrap with the latest key version" },
  { id: "sign", label: "Sign", needs: "signing", input: "Text to sign" },
  { id: "verify", label: "Verify", needs: "signing", input: "Signed text" },
  { id: "hmac", label: "HMAC", needs: "any", input: "Text" },
];

/** Developer tools against a Vault: a Transit playground (encrypt, decrypt, sign, verify, HMAC). */
export function ToolsView({ sides, readOnly = false, allowClipboard = true }: { sides: CompareSides; readOnly?: boolean; allowClipboard?: boolean }) {
  const [tool, setTool] = useState<"transit" | "database" | "leases">("transit");
  const conns = (["left", "right"] as const).filter((s) => sides[s]).map((s) => ({ side: s, ...sides[s]! }));
  const [sideId, setSideId] = useState(conns[0]?.side ?? "left");
  const conn = conns.find((c) => c.side === sideId) ?? conns[0];
  const [mounts, setMounts] = useState<{ path: string }[] | null>(null);
  const [mount, setMount] = useState("");
  const [keys, setKeys] = useState<Awaited<ReturnType<typeof api.transitKeys>>["keys"]>([]);
  const [key, setKey] = useState("");
  const [op, setOp] = useState<Op>("encrypt");
  const [text, setText] = useState("");
  const [signature, setSignature] = useState("");
  const [context, setContext] = useState("");
  const [out, setOut] = useState<{ result: string; key_version?: number; valid?: boolean; note?: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!conn) return;
    setMounts(null);
    api.transitMounts(conn.conn_id).then((m) => { setMounts(m); setMount(m[0]?.path ?? ""); }).catch((e) => setError(e.message));
  }, [conn?.conn_id]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (!conn || !mount) { setKeys([]); return; }
    api.transitKeys(conn.conn_id, mount).then((k) => { setKeys(k.keys); setKey(k.keys[0]?.name ?? ""); }).catch((e) => setError(e.message));
  }, [conn?.conn_id, mount]); // eslint-disable-line react-hooks/exhaustive-deps

  // A key that can't do the chosen operation (e.g. a signing key and Decrypt): switch to one it can
  useEffect(() => {
    const sel = keys.find((x) => x.name === key);
    const ok = (o: (typeof OPS)[number]) => !sel || o.needs === "any" || (o.needs === "encryption" ? sel.supports_encryption : sel.supports_signing);
    const current = OPS.find((o) => o.id === op)!;
    if (sel && !ok(current)) setOp(OPS.find(ok)?.id ?? op);
  }, [key, keys]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!conns.length) return <section className="tools"><div className="notice info">Connect a Vault on a side to use the tools.</div></section>;
  const k = keys.find((x) => x.name === key);
  const can = (o: (typeof OPS)[number]) => !k || o.needs === "any" || (o.needs === "encryption" ? k.supports_encryption : k.supports_signing);
  const spec = OPS.find((o) => o.id === op)!;
  const toolTabs = (
    <div className="segmented" role="tablist" aria-label="Tool">
      <button type="button" role="tab" aria-selected={tool === "transit"} aria-pressed={tool === "transit"} onClick={() => setTool("transit")}>Transit playground</button>
      <button type="button" role="tab" aria-selected={tool === "database"} aria-pressed={tool === "database"} onClick={() => setTool("database")}>Database credentials</button>
      <button type="button" role="tab" aria-selected={tool === "leases"} aria-pressed={tool === "leases"} onClick={() => setTool("leases")}>Leases</button>
    </div>
  );
  if (tool !== "transit") {
    return (
      <section className="tools">
        <div className="field-row">{toolTabs}
          {conns.length > 1 && (
            <div className="segmented small" role="group" aria-label="Which side">
              {conns.map((c) => <button key={c.side} type="button" aria-pressed={c.side === conn.side} onClick={() => setSideId(c.side)}><span className={`side-dot ${c.side}`} /> {c.label}</button>)}
            </div>
          )}
        </div>
        {tool === "leases"
          ? <LeasesTool key={conn.conn_id} connId={conn.conn_id} readOnly={readOnly} />
          : <DatabaseTool key={conn.conn_id} connId={conn.conn_id} readOnly={readOnly} allowClipboard={allowClipboard} />}
      </section>
    );
  }

  async function run() {
    setBusy(true);
    setError(null);
    setOut(null);
    try {
      setOut(await api.transitRun({ conn_id: conn.conn_id, mount, key, op, text, ...(op === "verify" ? { signature } : {}), ...(context ? { context } : {}) }));
    } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }

  return (
    <section className="tools">
      {toolTabs}
      <div className="card policies-head">
        <div className="subtle">
          <strong>Transit playground:</strong> try encryption, signing and HMACs with a Transit key while you build an integration, using your own
          sign-in. Nothing is stored by Lockstep; Vault’s audit log records the operations.
        </div>
        <div className="field-row">
          {conns.length > 1 && (
            <div className="segmented small" role="group" aria-label="Which side">
              {conns.map((c) => <button key={c.side} type="button" aria-pressed={c.side === conn.side} onClick={() => setSideId(c.side)}><span className={`side-dot ${c.side}`} /> {c.label}</button>)}
            </div>
          )}
          {mounts && mounts.length > 0 && (
            <label className="field inline"><span>Transit engine</span>
              <select aria-label="Transit engine" value={mount} onChange={(e) => setMount(e.target.value)}>{mounts.map((m) => <option key={m.path} value={m.path}>{m.path}/</option>)}</select></label>
          )}
        </div>
        {mounts && mounts.length === 0 && <div className="notice info">This Vault has no Transit engine you can see.</div>}
      </div>
      {error && <div className="notice error" role="alert">{error}</div>}
      {keys.length > 0 && (
        <div className="build-layout">
          <nav className="card build-drafts" aria-label="Keys">
            <div className="tree-head">{mount}/keys <span className="subtle">({keys.length})</span></div>
            {keys.map((x) => (
              <button key={x.name} type="button" className="tree-row secret" aria-current={x.name === key} onClick={() => { setKey(x.name); setOut(null); }}>
                <span className="mono">{x.name}</span> <span className="subtle">{x.type}</span>
              </button>
            ))}
          </nav>
          <div className="card build-editor" aria-label="Transit operation">
            {k && <div className="subtle">{k.type} · version {k.latest_version}{k.min_decryption_version && k.min_decryption_version > 1 ? ` (decrypts from v${k.min_decryption_version})` : ""}
              {k.derived ? " · derived (needs a context)" : ""}{k.exportable ? " · exportable" : ""}{k.deletion_allowed ? " · deletion allowed" : ""}</div>}
            <div className="segmented small" role="tablist" aria-label="Operation">
              {OPS.filter(can).map((o) => <button key={o.id} type="button" role="tab" aria-selected={op === o.id} aria-pressed={op === o.id} onClick={() => { setOp(o.id); setOut(null); }}>{o.label}</button>)}
            </div>
            <label className="field"><span>{spec.input}</span>
              <textarea className="mono" rows={4} aria-label="Input" value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} /></label>
            {op === "verify" && <label className="field"><span>Signature</span>
              <input type="text" className="mono" aria-label="Signature" value={signature} onChange={(e) => setSignature(e.target.value)} placeholder="vault:v1:…" /></label>}
            {k?.derived && <label className="field"><span>Context</span>
              <input type="text" className="mono" aria-label="Context" value={context} onChange={(e) => setContext(e.target.value)} /></label>}
            <div className="field-row"><span className="spacer" />
              <button type="button" className="btn primary" disabled={busy || !key || (!text && op !== "hmac")} onClick={run}>{busy && <span className="spinner" />} {spec.label}</button>
            </div>
            {out && (
              <div className={`share-panel${out.valid === false ? " bad" : ""}`} role="region" aria-label="Result">
                <div className="field-row"><strong>Result</strong>{out.key_version ? <span className="subtle">key version {out.key_version}</span> : null}<span className="spacer" />
                  {allowClipboard && <button type="button" className="btn ghost small" onClick={() => navigator.clipboard?.writeText(out.result)}>Copy</button>}
                  {(op === "encrypt" || op === "sign") && <button type="button" className="btn ghost small" onClick={() => {
                    if (op === "encrypt") { setOp("decrypt"); setText(out.result); } else { setOp("verify"); setSignature(out.result); }
                    setOut(null);
                  }}>{op === "encrypt" ? "Decrypt it" : "Verify it"}</button>}
                </div>
                <pre className="mono share-token" aria-label="Output">{out.result}</pre>
                {out.note && <div className="subtle">{out.note}</div>}
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
