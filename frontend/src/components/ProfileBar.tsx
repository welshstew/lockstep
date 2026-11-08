import { useRef, useState } from "react";
import { describe, importProfiles, type ProfileRef } from "../profiles";
import type { Profile } from "../types";

interface Props {
  shared: Profile[];
  personal: Profile[];
  active: ProfileRef | null;
  onSelect: (ref: ProfileRef | null) => void;
  onNew: () => void;
  onEdit: (p: Profile, source: "shared" | "personal") => void;
  onDelete: (name: string) => void;
  onImport: (list: Profile[]) => void;
  onExport: (list: Profile[]) => void;
}

const refKey = (r: ProfileRef | null) => (r ? `${r.source}:${r.name}` : "");

export function ProfileBar({ shared, personal, active, onSelect, onNew, onEdit, onDelete, onImport, onExport }: Props) {
  const file = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);
  const current = active ? (active.source === "shared" ? shared : personal).find((p) => p.name === active.name) ?? null : null;

  return (
    <section className="profile-bar card" aria-label="Comparison profile">
      <label className="field profile-select">
        <span>Comparison profile</span>
        <select value={refKey(current ? active : null)} onChange={(e) => {
          const v = e.target.value;
          if (!v) return onSelect(null);
          const [source, ...rest] = v.split(":");
          onSelect({ source: source as ProfileRef["source"], name: rest.join(":") });
        }}>
          <option value="">None: compare paths as they are</option>
          {shared.length > 0 && (
            <optgroup label="Shared (from the server)">
              {shared.map((p) => <option key={`s${p.name}`} value={`shared:${p.name}`}>{p.name}</option>)}
            </optgroup>
          )}
          {personal.length > 0 && (
            <optgroup label="Yours (this browser)">
              {personal.map((p) => <option key={`p${p.name}`} value={`personal:${p.name}`}>{p.name}</option>)}
            </optgroup>
          )}
        </select>
      </label>
      <div className="profile-info">
        {current ? (
          <>
            <span className="profile-sum">{describe(current)}</span>
            {current.description && <span className="subtle">{current.description}</span>}
          </>
        ) : <span className="subtle">Profiles map paths between the sides and ignore differences you expect.</span>}
      </div>
      <div className="profile-actions">
        {current && active?.source === "personal" && (
          <>
            <button type="button" className="btn small" onClick={() => onEdit(current, "personal")}>Edit</button>
            <button type="button" className="btn ghost small" onClick={() => onDelete(current.name)}>Delete</button>
          </>
        )}
        {current && active?.source === "shared" && (
          <button type="button" className="btn small" onClick={() => onEdit(current, "shared")} title="Shared profiles are read-only: this makes your own copy">Duplicate</button>
        )}
        <button type="button" className="btn small" onClick={onNew}>＋ New</button>
        <button type="button" className="btn ghost small" onClick={() => onExport(current ? [current] : personal)}
                disabled={!current && personal.length === 0}>Export</button>
        <button type="button" className="btn ghost small" onClick={() => file.current?.click()}>Import</button>
        <input ref={file} type="file" accept="application/json,.json" hidden onChange={async (e) => {
          const f = e.target.files?.[0];
          e.target.value = "";
          if (!f) return;
          try { setError(null); onImport(await importProfiles(f)); } catch (err) { setError((err as Error).message); }
        }} />
      </div>
      {error && <div className="notice error profile-error" role="alert">{error}</div>}
    </section>
  );
}
