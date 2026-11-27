import { useRef, useState } from "react";
import { api, ApiError } from "../api";
import { relativeTime } from "../time";
import type { LoadedFile } from "../types";

type Scheme = "key" | "passphrase" | "age";
const PROMPT: Record<Scheme, { text: string; label: string; placeholder: string }> = {
  key: { text: "is encrypted: enter its key", label: "Export key", placeholder: "lsk1.…" },
  passphrase: { text: "is encrypted with a passphrase: enter it", label: "Export passphrase", placeholder: "" },
  age: { text: "is encrypted to age keys: paste your age identity (used for this request only, never stored)",
         label: "age identity", placeholder: "AGE-SECRET-KEY-1…" },
};
const scheme = (file: unknown): Scheme => {
  const s = (file as { scheme?: string } | null)?.scheme;
  return s === "passphrase" || s === "age" ? s : "key";
};

/** Open an export file: read it, ask for its key if it's encrypted, and let the server check
 * (and decrypt) it. The opened export lives only in this page's memory. */
export function FileLoader({ onLoaded, label = "Open an export file…" }: {
  onLoaded: (f: LoadedFile) => void;
  label?: string;
}) {
  const input = useRef<HTMLInputElement>(null);
  const folder = useRef<HTMLInputElement>(null);
  const [pending, setPending] = useState<{ name: string; file: unknown } | null>(null);
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const newId = () => `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;

  /** `vault kv get -format=json` output (one file, an object of path: output, or a folder's
   * files): the server reads it as an export. */
  async function fromKvGet(name: string, files: { name: string; content: unknown }[]) {
    setBusy(true);
    setError(null);
    try {
      const r = await api.exportFromKvGet(files, name);
      onLoaded({ id: newId(), name, encrypted: false, doc: r.export });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function open(name: string, file: unknown, k?: string) {
    setBusy(true);
    setError(null);
    try {
      const r = await api.exportOpen(file, k);
      setPending(null);
      setKey("");
      onLoaded({ id: newId(), name, encrypted: r.encrypted, doc: r.export });
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
            const format = (parsed as { format?: unknown } | null)?.format;
            if (typeof format === "string" && format.startsWith("lockstep.")) open(f.name, parsed);
            else fromKvGet(f.name, [{ name: f.name, content: parsed }]);
          }} />
          <button type="button" className="btn ghost small" disabled={busy} onClick={() => folder.current?.click()}
                  title="A folder of vault kv get -format=json files: each secret's path is the file's path in the folder">
            Open a folder of vault kv get files…
          </button>
          <input ref={folder} type="file" hidden aria-label="Folder of vault kv get files" multiple
                 {...{ webkitdirectory: "", directory: "" }} onChange={async (e) => {
            const all = Array.from(e.target.files ?? []);
            e.target.value = "";
            const picked = all.filter((f) => f.name.toLowerCase().endsWith(".json"));
            if (!picked.length) { setError("That folder has no .json files."); return; }
            const top = (picked[0].webkitRelativePath || picked[0].name).split("/")[0];
            const files: { name: string; content: unknown }[] = [];
            for (const f of picked) {
              const rel = f.webkitRelativePath ? f.webkitRelativePath.split("/").slice(1).join("/") : f.name;
              try { files.push({ name: rel, content: JSON.parse(await f.text()) }); }
              catch { setError(`${rel} isn't JSON.`); return; }
            }
            fromKvGet(top, files);
          }} />
        </>
      ) : (
        <form className="row" onSubmit={(e) => { e.preventDefault(); open(pending.name, pending.file, key); }}>
          <label className="field grow">
            <span><span className="mono">{pending.name}</span> {PROMPT[scheme(pending.file)].text}</span>
            <input type="password" value={key} onChange={(e) => setKey(e.target.value)} placeholder={PROMPT[scheme(pending.file)].placeholder}
                   autoComplete="off" spellCheck={false} aria-label={PROMPT[scheme(pending.file)].label} required />
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
  const kept = f.doc.secrets.filter((x) => x.keep).length;
  const n = f.doc.secrets.length - kept;
  return (
    <span className="file-summary">
      <span className="mono">{f.name}</span>
      <span className="subtle">
        {s.vault} · {s.mount}{s.prefix ? `/${s.prefix}` : ""} · {n} secret{n === 1 ? "" : "s"}{kept ? ` (+${kept} kept)` : ""}
        {" "}· exported {relativeTime(f.doc.created_at)}{f.encrypted ? " · was encrypted" : ""}
      </span>
    </span>
  );
}
