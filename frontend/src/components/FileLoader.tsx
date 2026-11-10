import { useRef, useState } from "react";
import { api, ApiError } from "../api";
import { relativeTime } from "../time";
import type { LoadedFile } from "../types";

/** Open an export file: read it, ask for its key if it's encrypted, and let the server check
 * (and decrypt) it. The opened export lives only in this page's memory. */
export function FileLoader({ onLoaded, label = "Open an export file…" }: {
  onLoaded: (f: LoadedFile) => void;
  label?: string;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [pending, setPending] = useState<{ name: string; file: unknown } | null>(null);
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function open(name: string, file: unknown, k?: string) {
    setBusy(true);
    setError(null);
    try {
      const r = await api.exportOpen(file, k);
      setPending(null);
      setKey("");
      onLoaded({ id: `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`, name, encrypted: r.encrypted, doc: r.export });
    } catch (e) {
      const needsKey = e instanceof ApiError && Boolean(e.detail.needs_key);
      if (needsKey) setPending({ name, file });
      // Asking for the key the first time isn't an error worth shouting about
      if (!(needsKey && !k)) setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="file-loader">
      {!pending ? (
        <>
          <button type="button" className="btn" disabled={busy} onClick={() => input.current?.click()}>
            {busy && <span className="spinner" />} {label}
          </button>
          <input ref={input} type="file" accept="application/json,.json" hidden aria-label="Export file" onChange={async (e) => {
            const f = e.target.files?.[0];
            e.target.value = "";
            if (!f) return;
            let parsed: unknown;
            try { parsed = JSON.parse(await f.text()); } catch { setError("That file isn't JSON."); return; }
            open(f.name, parsed);
          }} />
        </>
      ) : (
        <form className="row" onSubmit={(e) => { e.preventDefault(); open(pending.name, pending.file, key); }}>
          <label className="field grow">
            <span><span className="mono">{pending.name}</span> is encrypted: enter its key</span>
            <input type="password" value={key} onChange={(e) => setKey(e.target.value)} placeholder="lsk1.…"
                   autoComplete="off" spellCheck={false} aria-label="Export key" required />
          </label>
          <button type="submit" className="btn primary" disabled={busy || !key.trim()}>{busy && <span className="spinner" />} Open</button>
          <button type="button" className="btn ghost" onClick={() => { setPending(null); setKey(""); setError(null); }}>Cancel</button>
        </form>
      )}
      {error && <div className="notice error" role="alert">{error}</div>}
    </div>
  );
}

/** One line describing an opened export. */
export function FileSummary({ f }: { f: LoadedFile }) {
  const s = f.doc.source;
  return (
    <span className="file-summary">
      <span className="mono">{f.name}</span>
      <span className="subtle">
        {s.vault} · {s.mount}{s.prefix ? `/${s.prefix}` : ""} · {f.doc.secrets.length} secret{f.doc.secrets.length === 1 ? "" : "s"}
        {" "}· exported {relativeTime(f.doc.created_at)}{f.encrypted ? " · was encrypted" : ""}
      </span>
    </span>
  );
}
