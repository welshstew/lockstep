import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import type {
  AnalysisNode, AnalyzeOptions, AnalyzeResult, CertInfo, Locator, PasswordCandidate, PasswordRef, PasswordSearch,
} from "../types";
import { CertCard, CertDiff } from "./CertCard";

export interface InspectTarget {
  side: "left" | "right";
  loc: Locator;
  title: string;
}

export interface TrustCandidate {
  loc: Locator;
  label: string;
}

interface Props {
  targets: InspectTarget[];
  reveal: boolean;
  trustCandidates: TrustCandidate[];
  onClose: () => void;
}

const locKey = (l: Locator) => `${l.conn_id}|${l.mount}|${l.path}|${l.key}`;

function firstCert(n: AnalysisNode | undefined): CertInfo | undefined {
  if (!n) return undefined;
  if (n.details.certificate) return n.details.certificate;
  for (const c of n.children) {
    const hit = firstCert(c);
    if (hit) return hit;
  }
  return undefined;
}

function anyNeedsPassword(n: AnalysisNode): boolean {
  return n.needs_password || n.children.some(anyNeedsPassword);
}

function fmtSize(n: number) {
  return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
}

export function Inspector({ targets, reveal, trustCandidates, onClose }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const [systemRoots, setSystemRoots] = useState(true);
  const [trust, setTrust] = useState<string[]>([]);
  const [trustFp, setTrustFp] = useState<string[]>([]);
  const [certs, setCerts] = useState<Record<string, CertInfo | undefined>>({});

  useEffect(() => { ref.current?.showModal(); }, []);

  const shared: AnalyzeOptions = {
    system_roots: systemRoots,
    trust: trustCandidates.filter((c) => trust.includes(locKey(c.loc))).map((c) => c.loc),
    trust_sha256: trustFp,
  };
  const both = targets.length === 2 && certs.left && certs.right;

  return (
    <dialog ref={ref} className="inspector" onClose={onClose}>
      <header className="review-head">
        <h2>Inspect value{targets.length > 1 ? "s" : ""}</h2>
        <button type="button" className="btn ghost icon small" aria-label="Close" onClick={() => ref.current?.close()}>✕</button>
      </header>

      <div className="inspector-trust">
        <span className="muted">Trust anchors:</span>
        <label className="inline-check">
          <input type="checkbox" checked={systemRoots} onChange={(e) => setSystemRoots(e.target.checked)} /> System roots
        </label>
        {trustCandidates.length > 0 && (
          <details className="trust-picker">
            <summary>Certificates from this comparison ({trust.length} selected)</summary>
            <div className="trust-list">
              {trustCandidates.map((c) => {
                const k = locKey(c.loc);
                return (
                  <label key={k} className="inline-check">
                    <input type="checkbox" checked={trust.includes(k)}
                           onChange={(e) => setTrust((t) => (e.target.checked ? [...t, k] : t.filter((x) => x !== k)))} />
                    <span className="mono">{c.label}</span>
                  </label>
                );
              })}
            </div>
          </details>
        )}
        {trustFp.length > 0 && (
          <button type="button" className="btn ghost small" onClick={() => setTrustFp([])}>
            Forget {trustFp.length} trusted root{trustFp.length === 1 ? "" : "s"}
          </button>
        )}
      </div>

      <div className="review-body">
        {!reveal && (
          <div className="notice info">
            Showing structure and certificate details only. Turn on <strong>Show values</strong> to preview content and download files.
          </div>
        )}
        {both && (
          <section className="cert-diff-wrap">
            <h3>Certificates side by side</h3>
            <CertDiff left={certs.left!} right={certs.right!} />
          </section>
        )}
        <div className={`inspect-cols n${targets.length}`}>
          {targets.map((t) => (
            <InspectColumn key={t.side + locKey(t.loc)} target={t} shared={shared} reveal={reveal}
                           onCert={(c) => setCerts((s) => (s[t.side] === c ? s : { ...s, [t.side]: c }))}
                           onTrustRoot={(fp) => setTrustFp((f) => (f.includes(fp) ? f : [...f, fp]))} />
          ))}
        </div>
      </div>
    </dialog>
  );
}

function InspectColumn({ target, shared, reveal, onCert, onTrustRoot }: {
  target: InspectTarget; shared: AnalyzeOptions; reveal: boolean;
  onCert: (c: CertInfo | undefined) => void; onTrustRoot: (fp: string) => void;
}) {
  const [password, setPassword] = useState("");
  const [passwordKey, setPasswordKey] = useState<string | null>(null);
  type Applied = { password: string | null; password_key: string | null; password_ref: PasswordRef | null; from: string | null };
  const NONE: Applied = { password: null, password_key: null, password_ref: null, from: null };
  const [applied, setApplied] = useState<Applied>(NONE);
  const [search, setSearch] = useState<PasswordSearch | "searching" | { error: string } | null>(null);
  const [out, setOut] = useState<AnalyzeResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const opts: AnalyzeOptions = { ...shared, password: applied.password, password_key: applied.password_key,
                                 password_ref: applied.password_ref };
  const optsKey = JSON.stringify(opts);

  useEffect(() => {
    let live = true;
    setLoading(true);
    setError(null);
    api.analyze(target.loc, JSON.parse(optsKey))
      .then((r) => { if (live) { setOut(r); onCert(firstCert(r.root)); } })
      .catch((e) => { if (live) setError(e.message); })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [optsKey, target.loc]);

  const showPassword = out && (anyNeedsPassword(out.root) || out.password_suggestions.length > 0 || applied.password
    || applied.password_key || applied.password_ref);
  const locked = !!out && anyNeedsPassword(out.root);

  // A locked keystore: look for its password in nearby secrets straight away (read-only; the
  // server tries each candidate and returns where they are, never their values).
  useEffect(() => {
    if (!locked || search !== null || applied.password_ref || applied.password_key || applied.password) return;
    setSearch("searching");
    api.findPasswords(target.loc).then(setSearch).catch((e) => setSearch({ error: e.message }));
  }, [locked, search, applied, target.loc]);

  return (
    <section className={`inspect-col ${target.side}`}>
      <h3 className={`side-title`}>{target.side === "left" ? "◧ " : ""}{target.title}{target.side === "right" ? " ◨" : ""}</h3>
      {showPassword && (
        <form className="pw-row" onSubmit={(e) => { e.preventDefault(); setApplied({ ...NONE, password: passwordKey ? null : password, password_key: passwordKey, from: passwordKey }); }}>
          <span className="muted">Keystore password:</span>
          {out!.password_suggestions.length > 0 && (
            <select value={passwordKey ?? ""} onChange={(e) => setPasswordKey(e.target.value || null)} aria-label="Password source">
              <option value="">type it…</option>
              {out!.password_suggestions.map((k) => <option key={k} value={k}>use key “{k}”</option>)}
            </select>
          )}
          {!passwordKey && (
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                   autoComplete="off" placeholder="password" aria-label="Keystore password" />
          )}
          <button type="submit" className="btn small">Open</button>
          {out!.password_used && <span className="check ok">✓ password accepted{applied.from ? ` (from ${applied.from})` : ""}</span>}
        </form>
      )}
      {showPassword && search && (
        <PasswordFinder search={search} usedRef={applied.password_ref}
                        onUse={(ref, label) => setApplied({ ...NONE, password_ref: ref, from: label })}
                        onUseDefault={(pw, label) => setApplied({ ...NONE, password: pw, from: label })} />
      )}
      {error && <div className="notice error">{error}</div>}
      {loading && !out && <div className="empty"><span className="spinner" /> Analysing…</div>}
      {out && (
        <div className={loading ? "dim" : ""}>
          {out.siblings.length > 0 && (
            <div className="subtle">Also used certificates from: {out.siblings.map((s) => s.key).join(", ")}</div>
          )}
          <NodeView node={out.root} loc={target.loc} opts={opts} reveal={reveal} onTrustRoot={onTrustRoot} depth={0} />
        </div>
      )}
    </section>
  );
}

function PasswordFinder({ search, usedRef, onUse, onUseDefault }: {
  search: PasswordSearch | "searching" | { error: string };
  usedRef: PasswordRef | null;
  onUse: (ref: PasswordRef, label: string) => void;
  onUseDefault: (password: string, label: string) => void;
}) {
  if (search === "searching") return <div className="subtle pw-finder"><span className="spinner" /> Looking for the password in nearby secrets…</div>;
  if ("error" in search) return <div className="notice error">Couldn’t search for the password: {search.error}</div>;
  if (!search.needs_password) return null;
  const where = search.searched ? `${search.searched}` : "the whole mount";
  const openers = search.candidates.filter((c) => c.opens);
  const others = search.candidates.filter((c) => !c.opens);
  const label = (c: PasswordCandidate) => `${c.path} · ${c.key}`;
  const isUsed = (c: PasswordCandidate) => usedRef?.path === c.path && usedRef?.key === c.key;
  return (
    <div className="pw-finder" role="region" aria-label="Password finder">
      {openers.map((c) => (
        <div key={label(c)} className="pw-candidate opens">
          <span className="check ok">✓ opens it</span>
          <span className="mono">{label(c)}</span>
          <span className="subtle">{c.reasons.join(" · ")}</span>
          <button type="button" className="btn small" disabled={isUsed(c)} onClick={() => onUse({ path: c.path, key: c.key }, label(c))}>
            {isUsed(c) ? "In use" : "Use"}
          </button>
        </div>
      ))}
      {search.default && (
        <div className="pw-candidate opens">
          <span className="check ok">✓ opens it</span>
          <span>{search.default_label}</span>
          <button type="button" className="btn small" onClick={() => onUseDefault(search.default!, search.default_label ?? "a default password")}>Use</button>
        </div>
      )}
      {!openers.length && !search.default && (
        <div className="subtle">
          No password found: {search.candidates.length ? `none of the ${search.candidates.length} likely keys` : "no password-like keys"} in
          <span className="mono"> {where}</span> ({search.secrets} secret{search.secrets === 1 ? "" : "s"} searched{search.truncated ? ", search cut short" : ""}) opened it.
        </div>
      )}
      {others.length > 0 && (
        <details className="pw-others">
          <summary className="subtle">{others.length} other candidate{others.length === 1 ? "" : "s"} tried in <span className="mono">{where}</span></summary>
          <ul>{others.map((c) => <li key={label(c)}><span className="mono">{label(c)}</span> <span className="subtle">{c.reasons.join(" · ")}</span></li>)}</ul>
        </details>
      )}
    </div>
  );
}

function NodeView({ node, loc, opts, reveal, onTrustRoot, depth }: {
  node: AnalysisNode; loc: Locator; opts: AnalyzeOptions; reveal: boolean; onTrustRoot: (fp: string) => void; depth: number;
}) {
  const [busy, setBusy] = useState(false);
  const download = async () => {
    setBusy(true);
    try {
      const { blob, filename } = await api.content(loc, opts, node.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } finally {
      setBusy(false);
    }
  };
  const d = node.details;
  return (
    <div className={`node depth${Math.min(depth, 3)}`}>
      <div className="node-head">
        <span className="node-label">{node.label}</span>
        {node.encoding.length > 0 && <span className="subtle">via {node.encoding.join(" → ")}</span>}
        {node.size > 0 && <span className="subtle">{fmtSize(node.size)}</span>}
        <span className="spacer" />
        {node.downloadable && (
          <button type="button" className="btn small" disabled={!reveal || busy} onClick={download}
                  title={reveal ? `Download as .${node.ext}` : "Turn on Show values to download"}>
            {busy ? <span className="spinner" /> : "⤓"} .{node.ext}
          </button>
        )}
      </div>
      {node.problems.map((p) => <div key={p} className="notice error">{p}</div>)}
      {node.notes.map((n) => <div key={n} className="subtle note">{n}</div>)}

      {d.certificate && <CertCard cert={d.certificate} chain={d.chain} onTrust={onTrustRoot} />}
      {node.kind === "private_key" && (
        <div className="kv">
          <span>{d.key}</span>
          {d.matches && (d.matches.length
            ? <span className="check ok">✓ matches {d.matches.join(", ")}</span>
            : <span className="check bad">✗ matches no certificate here</span>)}
        </div>
      )}
      {node.kind === "csr" && (
        <div className="kv"><span className="mono">{d.subject}</span><span>{d.public_key}</span>
          <span className={`check ${d.signature_valid ? "ok" : "bad"}`}>{d.signature_valid ? "✓" : "✗"} signature</span></div>
      )}
      {d.integrity && (
        <div className="kv"><span className={`check ${d.integrity === "ok" ? "ok" : d.integrity === "bad_password" ? "bad" : ""}`}>
          Integrity: {{ ok: "✓ verified", bad_password: "✗ wrong password", unchecked: "not checked (no password)", incomplete: "not checked" }[d.integrity]}
        </span></div>
      )}
      {d.entries && (
        <table className="zip-list"><tbody>
          {d.entries.map((e) => <tr key={e.name}><td className="mono">{e.name}</td><td className="subtle">{fmtSize(e.size)}</td></tr>)}
        </tbody></table>
      )}
      {reveal && ["image", "text", "json", "binary"].includes(node.kind) && (
        <Preview node={node} loc={loc} opts={opts} />
      )}
      {node.children.map((c) => (
        <NodeView key={c.id} node={c} loc={loc} opts={opts} reveal={reveal} onTrustRoot={onTrustRoot} depth={depth + 1} />
      ))}
    </div>
  );
}

function hexdump(bytes: Uint8Array): string {
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const row = bytes.slice(i, i + 16);
    const hex = [...row].map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const asc = [...row].map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${i.toString(16).padStart(6, "0")}  ${hex.padEnd(47)}  ${asc}`);
  }
  return lines.join("\n");
}

function Preview({ node, loc, opts }: { node: AnalysisNode; loc: Locator; opts: AnalyzeOptions }) {
  const [url, setUrl] = useState<string | null>(null);
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const optsKey = JSON.stringify(opts);

  useEffect(() => {
    let live = true;
    let objectUrl: string | null = null;
    api.content(loc, JSON.parse(optsKey), node.id).then(async ({ blob, mime }) => {
      if (!live) return;
      if (node.kind === "image") {
        // Rendered with <img>, so SVG scripts never run.
        objectUrl = URL.createObjectURL(new Blob([blob], { type: mime }));
        setUrl(objectUrl);
      } else if (node.kind === "binary") {
        setText(hexdump(new Uint8Array(await blob.slice(0, 512).arrayBuffer())) + (blob.size > 512 ? "\n…" : ""));
      } else {
        const t = await blob.slice(0, 65536).text();
        setText(node.kind === "json" ? (() => { try { return JSON.stringify(JSON.parse(t), null, 2); } catch { return t; } })() : t);
      }
    }).catch((e) => { if (live) setError(e.message); });
    return () => { live = false; if (objectUrl) URL.revokeObjectURL(objectUrl); };
  }, [loc, optsKey, node.id, node.kind]);

  if (error) return <div className="notice error">{error}</div>;
  if (url) return <div className="img-preview"><img src={url} alt={node.label} /></div>;
  if (text !== null) return <pre className="val expanded preview">{text}</pre>;
  return <div className="subtle"><span className="spinner" /></div>;
}
