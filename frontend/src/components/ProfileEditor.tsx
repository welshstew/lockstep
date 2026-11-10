import { useEffect, useRef, useState } from "react";
import { emptyRules, validateRules } from "../profiles";
import type { Profile } from "../types";

interface Props {
  initial: Profile | null;
  takenNames: string[];
  current: { left_mount: string | null; left_prefix: string; right_mount: string | null; right_prefix: string };
  onSave: (p: Profile) => void;
  onClose: () => void;
}

export function ProfileEditor({ initial, takenNames, current, onSave, onClose }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [mappings, setMappings] = useState(initial?.rules.mappings ?? []);
  const [ignoreKeys, setIgnoreKeys] = useState(initial?.rules.ignore_keys ?? []);
  const [ignorePaths, setIgnorePaths] = useState((initial?.rules.ignore_paths ?? []).join("\n"));
  const hasMounts = !!(initial?.left_mount || initial?.right_mount);
  const [keepMounts, setKeepMounts] = useState(hasMounts);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { ref.current?.showModal(); }, []);

  function save(e: React.FormEvent) {
    e.preventDefault();
    const rules = {
      ...emptyRules(),
      mappings: mappings.map((m) => ({ left: m.left.trim(), right: m.right.trim() })).filter((m) => m.left || m.right),
      ignore_keys: ignoreKeys.map((k) => ({ key: k.key.trim(), path: k.path.trim() || "**" })).filter((k) => k.key),
      ignore_paths: ignorePaths.split("\n").map((l) => l.trim()).filter(Boolean),
    };
    if (!name.trim()) return setError("Give the profile a name.");
    if (takenNames.includes(name.trim()) && name.trim() !== initial?.name) return setError("You already have a profile with that name.");
    const err = validateRules(rules);
    if (err) return setError(err);
    const mounts = keepMounts
      ? (initial && hasMounts && !current.left_mount
        ? { left_mount: initial.left_mount, left_prefix: initial.left_prefix, right_mount: initial.right_mount, right_prefix: initial.right_prefix }
        : { left_mount: current.left_mount, left_prefix: current.left_prefix, right_mount: current.right_mount, right_prefix: current.right_prefix })
      : {};
    onSave({ name: name.trim(), description: description.trim(), ...mounts, rules });
    ref.current?.close();
  }

  return (
    <dialog ref={ref} className="review profile-editor" onClose={onClose}>
      <form onSubmit={save}>
        <header className="review-head">
          <h2>{initial?.name ? "Edit profile" : "New comparison profile"}</h2>
          <button type="button" className="btn ghost icon small" aria-label="Close" onClick={() => ref.current?.close()}>✕</button>
        </header>
        <div className="review-body">
          <div className="row">
            <label className="field grow"><span>Name</span>
              <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="Prod ↔ staging" required /></label>
            <label className="field grow"><span>Description <span className="subtle">(optional)</span></span>
              <input type="text" value={description} onChange={(e) => setDescription(e.target.value)} /></label>
          </div>

          <h3 className="editor-h">Path mappings</h3>
          <p className="subtle">
            Pair paths that differ between the sides. <code>*</code> matches within one path segment, <code>**</code> any depth;
            both sides need the same wildcards, in order. Example: <code>services/*/prod/**</code> ⇄ <code>services/*/staging/**</code>.
            The first matching rule wins; other paths are compared as they are. Copies follow the mapping.
          </p>
          {mappings.map((m, i) => (
            <div className="row rule-row" key={i}>
              <input className="grow mono" type="text" aria-label={`Mapping ${i + 1} left pattern`} value={m.left} placeholder="left pattern"
                     onChange={(e) => setMappings(mappings.map((x, j) => (j === i ? { ...x, left: e.target.value } : x)))} />
              <span className="map-arrow">⇄</span>
              <input className="grow mono" type="text" aria-label={`Mapping ${i + 1} right pattern`} value={m.right} placeholder="right pattern"
                     onChange={(e) => setMappings(mappings.map((x, j) => (j === i ? { ...x, right: e.target.value } : x)))} />
              <button type="button" className="btn ghost icon small" aria-label={`Remove mapping ${i + 1}`}
                      onClick={() => setMappings(mappings.filter((_, j) => j !== i))}>✕</button>
            </div>
          ))}
          <button type="button" className="btn small" onClick={() => setMappings([...mappings, { left: "", right: "" }])}>＋ Add mapping</button>

          <h3 className="editor-h">Ignored keys</h3>
          <p className="subtle">Keys meant to differ, such as hostnames or URLs. They're still shown, marked <em>ignored</em>, but don't make a secret count as different.</p>
          {ignoreKeys.map((k, i) => (
            <div className="row rule-row" key={i}>
              <input className="grow mono" type="text" aria-label={`Ignored key ${i + 1}`} value={k.key} placeholder="key pattern, e.g. host or *_url"
                     onChange={(e) => setIgnoreKeys(ignoreKeys.map((x, j) => (j === i ? { ...x, key: e.target.value } : x)))} />
              <span className="subtle">under</span>
              <input className="grow mono" type="text" aria-label={`Ignored key ${i + 1} path`} value={k.path} placeholder="** (everywhere)"
                     onChange={(e) => setIgnoreKeys(ignoreKeys.map((x, j) => (j === i ? { ...x, path: e.target.value } : x)))} />
              <button type="button" className="btn ghost icon small" aria-label={`Remove ignored key ${i + 1}`}
                      onClick={() => setIgnoreKeys(ignoreKeys.filter((_, j) => j !== i))}>✕</button>
            </div>
          ))}
          <button type="button" className="btn small" onClick={() => setIgnoreKeys([...ignoreKeys, { key: "", path: "" }])}>＋ Add ignored key</button>

          <h3 className="editor-h">Ignored paths</h3>
          <label className="field"><span className="subtle">One pattern per line. Matching secrets are left out of the comparison.</span>
            <textarea className="mono" rows={3} value={ignorePaths} onChange={(e) => setIgnorePaths(e.target.value)} placeholder={"legacy/**\ntmp/*"} /></label>

          <label className="inline-check">
            <input type="checkbox" checked={keepMounts} onChange={(e) => setKeepMounts(e.target.checked)} />
            Remember the mounts and prefixes{current.left_mount || current.right_mount
              ? <> (now <code>{current.left_mount ?? "—"}{current.left_prefix ? `/${current.left_prefix}` : ""}</code> ⇄ <code>{current.right_mount ?? "—"}{current.right_prefix ? `/${current.right_prefix}` : ""}</code>)</>
              : null}
          </label>
          {error && <div className="notice error" role="alert">{error}</div>}
        </div>
        <footer className="review-foot">
          <span className="subtle">Saved in this browser. Use Export to share it.</span>
          <span className="spacer" />
          <button type="button" className="btn ghost" onClick={() => ref.current?.close()}>Cancel</button>
          <button type="submit" className="btn primary">Save profile</button>
        </footer>
      </form>
    </dialog>
  );
}
