import { useEffect, useId, useState } from "react";
import { api } from "../api";
import type { AppConfig } from "../types";

let servers: Promise<AppConfig["plan_servers"]> | null = null;
const known = () => (servers ??= api.config().then((c) => c.plan_servers).catch(() => undefined));

/** "a, b" → ["a", "b"]: the Lockstep servers a plan is limited to (its audience). */
export const parseAudience = (s: string) => [...new Set(s.split(",").map((x) => x.trim()).filter(Boolean))];

/** Which Lockstep servers may apply a plan: empty for any that trusts this one. Names are offered from
 *  this server's own and its trusted servers', and an unknown name is pointed out (a typo makes the plan unusable). */
export function AudienceField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const id = useId();
  const [names, setNames] = useState<string[]>([]);
  useEffect(() => {
    known().then((s) => setNames(s ? [...new Set([s.self, ...s.trusted])] : []));
  }, []);
  const unknown = names.length ? parseAudience(value).filter((n) => !names.includes(n)) : [];
  return (
    <span className="audience-field">
      <label htmlFor={`${id}-input`} className="subtle">Only for</label>
      <input id={`${id}-input`} type="text" className="plan-note-input" list={`${id}-servers`} value={value} maxLength={1000}
             placeholder="any server (optional)" aria-label="Only for these Lockstep servers"
             title="Only these Lockstep servers may apply the plan, comma-separated. Empty: any server that trusts this one."
             onChange={(e) => onChange(e.target.value)} />
      <datalist id={`${id}-servers`}>{names.map((n) => <option key={n} value={n} />)}</datalist>
      {unknown.length > 0 && (
        <span className="subtle audience-unknown" role="status">
          Not a server this one knows: {unknown.join(", ")}. Check the spelling: only a server with that name can apply it.
        </span>
      )}
    </span>
  );
}
