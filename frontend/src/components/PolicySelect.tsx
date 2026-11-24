import { useEffect, useMemo, useState } from "react";
import { api } from "../api";

// One listing per connection for the page's lifetime; a denied listing is remembered too
const cache = new Map<string, Promise<string[]>>();
function policyNames(connId: string): Promise<string[]> {
  let p = cache.get(connId);
  if (!p) {
    p = api.policyNames(connId).then((r) => r.names);
    p.catch(() => cache.delete(connId));
    cache.set(connId, p);
  }
  return p;
}

/** Choose policies for a role, group or user: the Vault's existing policies as toggles, plus names typed in
 *  (for a policy that doesn't exist yet). `root` is never offered. */
export function PolicySelect({ connId, value, onChange, label = "Policies", id }: {
  connId: string; value: string[]; onChange: (v: string[]) => void; label?: string; id?: string;
}) {
  const [names, setNames] = useState<string[] | null>(null);
  const [denied, setDenied] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [typed, setTyped] = useState("");
  useEffect(() => {
    let live = true;
    setNames(null);
    setDenied(null);
    policyNames(connId).then((n) => live && setNames(n.filter((x) => x !== "root")))
      .catch((e) => { if (live) { setNames([]); setDenied((e as Error).message); } });
    return () => { live = false; };
  }, [connId]);

  const known = useMemo(() => new Set(names ?? []), [names]);
  const options = useMemo(() => [...new Set([...(names ?? []), ...value])].sort(), [names, value]);
  const q = query.trim().toLowerCase();
  const shown = q ? options.filter((n) => n.toLowerCase().includes(q) || value.includes(n)) : options;
  const toggle = (n: string) => onChange(value.includes(n) ? value.filter((x) => x !== n) : [...value, n]);
  const add = () => {
    const more = typed.split(/[\s,]+/).map((x) => x.trim()).filter((x) => x && !value.includes(x));
    if (more.length) onChange([...value, ...more]);
    setTyped("");
  };

  return (
    <div className="policy-select" id={id}>
      <div className="subtle" aria-live="polite">
        {value.length ? `${value.length} chosen: ` : "None chosen. "}
        {value.length > 0 && <span className="mono">{value.join(", ")}</span>}
      </div>
      {names === null ? <div className="subtle"><span className="spinner" /> Listing policies…</div> : (
        <>
          {options.length > 12 && <input type="search" className="search" placeholder="Find a policy…" value={query}
                                         onChange={(e) => setQuery(e.target.value)} aria-label={`Find a policy for ${label}`} />}
          {options.length > 0 && (
            <div className="chips-wrap" role="group" aria-label={label}>
              {shown.map((n) => (
                <button key={n} type="button" className={`chip mono${known.has(n) ? "" : " missing"}`} aria-pressed={value.includes(n)}
                        title={known.has(n) ? undefined : "Not on this Vault (yet)"} onClick={() => toggle(n)}>
                  {n}{!known.has(n) && <span className="subtle"> · not on this Vault</span>}
                </button>
              ))}
            </div>
          )}
          {denied && <div className="subtle">This sign-in can’t list policies, so type their names.</div>}
        </>
      )}
      <div className="field-row">
        <input type="text" className="mono" value={typed} placeholder="another policy name" aria-label={`Add a policy name to ${label}`}
               onChange={(e) => setTyped(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); add(); } }} />
        <button type="button" className="btn ghost small" disabled={!typed.trim()} onClick={add}>Add</button>
      </div>
    </div>
  );
}
