import { useEffect, useMemo, useRef, useState } from "react";
import { api, type SideRef } from "../api";
import { emptyRules, ruleEffect, validateRules } from "../profiles";
import type { Profile, ProfileRules, ProfileSuggestions, Rewrite } from "../types";

interface Props {
  initial: Profile | null;
  takenNames: string[];
  current: { left_mount: string | null; left_prefix: string; right_mount: string | null; right_prefix: string };
  /** Both sides as chosen above, when each has a mount: lets the builder read them */
  sides?: { left: SideRef; right: SideRef; leftLabel: string; rightLabel: string } | null;
  onSave: (p: Profile) => void;
  onClose: () => void;
}

type Counts = Record<string, number>;

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

function countLine(c: Counts): string {
  const parts = [
    `${c.equal ?? 0} equal`, `${c.different ?? 0} different`,
    `${c.left_only ?? 0} only on the left`, `${c.right_only ?? 0} only on the right`,
  ];
  if (c.rewritten_keys) parts.push(`${plural(c.rewritten_keys, "key")} equal after rewrites`);
  if (c.ignored_keys) parts.push(`${plural(c.ignored_keys, "key difference")} ignored`);
  return parts.join(" · ");
}

const short = (list: string[], n = 4) => list.slice(0, n).join(", ") + (list.length > n ? `, and ${list.length - n} more` : "");

export function ProfileEditor({ initial, takenNames, current, sides, onSave, onClose }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [mappings, setMappings] = useState(initial?.rules.mappings ?? []);
  const [rewrites, setRewrites] = useState<Rewrite[]>(initial?.rules.rewrites ?? []);
  const [ignoreKeys, setIgnoreKeys] = useState(initial?.rules.ignore_keys ?? []);
  const [ignorePaths, setIgnorePaths] = useState((initial?.rules.ignore_paths ?? []).join("\n"));
  const hasMounts = !!(initial?.left_mount || initial?.right_mount);
  const [keepMounts, setKeepMounts] = useState(hasMounts);
  const [error, setError] = useState<string | null>(null);
  const [reading, setReading] = useState(false);
  const [found, setFound] = useState<ProfileSuggestions | null>(null);
  const [readError, setReadError] = useState<string | null>(null);
  const [preview, setPreview] = useState<Counts | null>(null);
  const [previewing, setPreviewing] = useState(false);

  useEffect(() => { ref.current?.showModal(); }, []);

  const rules: ProfileRules = useMemo(() => ({
    ...emptyRules(),
    mappings: mappings.map((m) => ({ left: m.left.trim(), right: m.right.trim() })).filter((m) => m.left || m.right),
    rewrites: rewrites.map((w) => ({ left: w.left.trim(), right: w.right.trim() })).filter((w) => w.left || w.right),
    ignore_keys: ignoreKeys.map((k) => ({ key: k.key.trim(), path: k.path.trim() || "**" })).filter((k) => k.key),
    ignore_paths: ignorePaths.split("\n").map((l) => l.trim()).filter(Boolean),
  }), [mappings, rewrites, ignoreKeys, ignorePaths]);
  const valid = validateRules(rules) === null;
  const effect = useMemo(() => (found && valid ? ruleEffect(rules, found.left_paths, found.right_paths) : null), [found, rules, valid]);
  useEffect(() => { setPreview(null); }, [rules]);

  const leftName = sides?.leftLabel ?? "the left side";
  const rightName = sides?.rightLabel ?? "the right side";

  async function readSides() {
    if (!sides) return;
    setReading(true);
    setReadError(null);
    try {
      setFound(await api.suggestRules(sides.left, sides.right, valid ? rules : null));
      if (!initial) setKeepMounts(true);
    } catch (e) {
      setReadError((e as Error).message);
    } finally {
      setReading(false);
    }
  }

  async function runPreview() {
    if (!sides || !valid) return;
    setPreviewing(true);
    try {
      setPreview((await api.compare(sides.left, sides.right, rules)).summary);
    } catch (e) {
      setReadError((e as Error).message);
    } finally {
      setPreviewing(false);
    }
  }

  const hasMapping = (m: { left: string; right: string }) => mappings.some((x) => x.left.trim() === m.left && x.right.trim() === m.right);
  const hasRewrite = (w: Rewrite) => rewrites.some((x) => x.left.trim() === w.left && x.right.trim() === w.right);
  const addMapping = (m: { left: string; right: string }) => { if (!hasMapping(m)) setMappings((ms) => [...ms.filter((x) => x.left || x.right), { left: m.left, right: m.right }]); };
  const addRewrite = (w: Rewrite) => { if (!hasRewrite(w)) setRewrites((ws) => [...ws.filter((x) => x.left || x.right), { left: w.left, right: w.right }]); };

  function save(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return setError("Give the profile a name.");
    if (takenNames.includes(name.trim()) && name.trim() !== initial?.name) return setError("You already have a profile with that name.");
    const err = validateRules(rules);
    if (err) return setError(err);
    const mounts = keepMounts
      ? (initial && hasMounts && !current.left_mount
        ? { left_mount: initial.left_mount, left_prefix: initial.left_prefix, right_mount: initial.right_mount, right_prefix: initial.right_prefix }
        : { left_mount: current.left_mount, left_prefix: current.left_prefix, right_mount: current.right_mount, right_prefix: current.right_prefix })
      : {};
    onSave({ name: name.trim(), description: description.trim(), ...mounts, rules: { ...rules, rewrites: rules.rewrites?.length ? rules.rewrites : undefined } });
    ref.current?.close();
  }

  const suggestionCount = (found?.mappings.length ?? 0) + (found?.rewrites.length ?? 0);
  const allAdded = !!found && found.mappings.every(hasMapping) && found.rewrites.every(hasRewrite);

  return (
    <dialog ref={ref} className="review profile-editor" onClose={onClose}>
      <form onSubmit={save}>
        <header className="review-head">
          <h2>{initial?.name ? "Edit profile" : "New comparison profile"}</h2>
          <button type="button" className="btn ghost icon small" aria-label="Close" onClick={() => ref.current?.close()}>✕</button>
        </header>
        <div className="review-body editor-grid">
          <div className="editor-main">
            <div className="row">
              <label className="field grow"><span>Name</span>
                <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="Test ↔ dev" required /></label>
              <label className="field grow"><span>Description <span className="subtle">(optional)</span></span>
                <input type="text" value={description} onChange={(e) => setDescription(e.target.value)} /></label>
            </div>

            <section className="builder" aria-label="Build from both sides">
              <div className="builder-head">
                <div>
                  <h3 className="editor-h">Start from what's in the two Vaults</h3>
                  <p className="subtle">
                    {sides
                      ? <>Lockstep lists every secret in {leftName} and {rightName} and compares them on the server. It suggests
                        rules from folders that look renamed, and from words that differ between environments inside values,
                        such as <code>test</code> and <code>dev</code>. You see paths and counts; values stay hidden.</>
                      : <>Choose a mount on both sides first, and Lockstep can read them and suggest the rules.</>}
                  </p>
                </div>
                <button type="button" className="btn small" disabled={!sides || reading} onClick={readSides}>
                  {reading && <span className="spinner" />} {found ? "Read again" : "Read both sides"}
                </button>
              </div>
              {readError && <div className="notice error" role="alert">{readError}</div>}
              {found && (
                <div className="builder-found" role="status">
                  <p className="subtle">
                    {plural(found.left_paths.length, "secret")} on the left, {plural(found.right_paths.length, "secret")} on the right.
                    With the rules below as they are: {countLine(found.before)}.
                    {found.truncated && " Some folders hold more secrets than the limit, so not everything was read."}
                  </p>
                  {suggestionCount === 0 ? (
                    <p className="subtle">Nothing more to suggest: no folders look renamed, and no environment or folder words explain the values that differ.</p>
                  ) : (
                    <>
                      <ul className="suggestions">
                        {found.mappings.map((m) => (
                          <li key={`m${m.left}`}>
                            <div className="suggestion-rule"><span className="kind">Map</span>
                              <code className="map-l">{m.left}</code><span className="map-arrow">⇄</span><code className="map-r">{m.right}</code></div>
                            <p>{m.reason}</p>
                            <button type="button" className="btn small" disabled={hasMapping(m)} onClick={() => addMapping(m)}>
                              {hasMapping(m) ? "Added" : "Add mapping"}</button>
                          </li>
                        ))}
                        {found.rewrites.map((w) => (
                          <li key={`r${w.left}`}>
                            <div className="suggestion-rule"><span className="kind">Rewrite</span>
                              <code className="map-l">{w.left}</code><span className="map-arrow">⇄</span><code className="map-r">{w.right}</code></div>
                            <p>{w.reason}</p>
                            <button type="button" className="btn small" disabled={hasRewrite(w)} onClick={() => addRewrite(w)}>
                              {hasRewrite(w) ? "Added" : "Add rewrite"}</button>
                          </li>
                        ))}
                      </ul>
                      <div className="row builder-foot">
                        <span className="subtle">With every suggestion: {countLine(found.after)}.</span>
                        <span className="spacer" />
                        <button type="button" className="btn small" disabled={allAdded}
                                onClick={() => { found.mappings.forEach(addMapping); found.rewrites.forEach(addRewrite); }}>Add all</button>
                      </div>
                    </>
                  )}
                </div>
              )}
            </section>

            <h3 className="editor-h">Path mappings</h3>
            <p className="subtle">
              Pair paths that differ between the sides, such as a renamed application: <code>enterprise-logging-app/**</code> ⇄ <code>ELP/**</code>.
              {" "}<code>*</code> matches within one path segment, <code>**</code> any depth; both sides need the same wildcards, in order.
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

            <h3 className="editor-h">Value rewrites</h3>
            <p className="subtle">
              Words that name the environment or the application inside values. Each left word is read as its right word before
              comparing, so <code>logs.test.internal</code> matches <code>logs.dev.internal</code>, while a wrong host still shows as
              different. Whole words, case-sensitive: <code>test</code> never touches <code>latest</code>. Copies write the target
              side's word. Certificates, keys and base64 data are never rewritten.
            </p>
            {rewrites.map((w, i) => (
              <div className="row rule-row" key={i}>
                <input className="grow mono" type="text" aria-label={`Rewrite ${i + 1} left word`} value={w.left} placeholder="word on the left, e.g. test"
                       onChange={(e) => setRewrites(rewrites.map((x, j) => (j === i ? { ...x, left: e.target.value } : x)))} />
                <span className="map-arrow">⇄</span>
                <input className="grow mono" type="text" aria-label={`Rewrite ${i + 1} right word`} value={w.right} placeholder="word on the right, e.g. dev"
                       onChange={(e) => setRewrites(rewrites.map((x, j) => (j === i ? { ...x, right: e.target.value } : x)))} />
                <button type="button" className="btn ghost icon small" aria-label={`Remove rewrite ${i + 1}`}
                        onClick={() => setRewrites(rewrites.filter((_, j) => j !== i))}>✕</button>
              </div>
            ))}
            <button type="button" className="btn small" onClick={() => setRewrites([...rewrites, { left: "", right: "" }])}>＋ Add rewrite</button>

            <h3 className="editor-h">Ignored keys</h3>
            <p className="subtle">Keys meant to differ, such as credentials or a log level. They're still shown, marked <em>ignored</em>, but don't make a secret count as different.</p>
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

          <aside className="explain" aria-label="What this profile does">
            <h3 className="editor-h">What this profile does</h3>
            {!valid && <div className="notice warn">{validateRules(rules)}</div>}
            {valid && rules.mappings.length + (rules.rewrites?.length ?? 0) + rules.ignore_keys.length + rules.ignore_paths.length === 0 && (
              <p>No rules yet. Paths are compared as they are, and every difference counts.
                {sides && !found && <> Press <strong>Read both sides</strong> to see what Lockstep suggests.</>}</p>
            )}
            {valid && (
              <ol className="explain-list">
                {rules.mappings.map((m, i) => {
                  const fx = effect?.mappings[i];
                  return (
                    <li key={`m${i}`}>
                      <strong>Pairs</strong> secrets under <code className="map-l">{m.left}</code> on the left with the same names under <code className="map-r">{m.right}</code> on the right.
                      {fx && (fx.pairs.length
                        ? <> Here it pairs {plural(fx.pairs.length, "secret")}: {short(fx.pairs.map(([l, r]) => `${l} ⇄ ${r}`), 3)}.</>
                        : <> <span className="warn-text">It matches nothing that has a partner yet: check the names.</span></>)}
                      {fx && fx.unmatched.length > 0 && <> {short(fx.unmatched, 3)} {fx.unmatched.length === 1 ? "has" : "have"} no partner on the right, so {fx.unmatched.length === 1 ? "it shows" : "they show"} as only on the left.</>}
                      {" "}A copy to the right lands under <code>{m.right}</code>.
                    </li>
                  );
                })}
                {(rules.rewrites ?? []).map((w, i) => {
                  const s = found?.rewrites.find((x) => x.left === w.left && x.right === w.right);
                  return (
                    <li key={`r${i}`}>
                      <strong>Reads</strong> <code className="map-l">{w.left}</code> in values on the left as <code className="map-r">{w.right}</code>, before comparing.
                      {s && <> That makes {plural(s.keys, "differing key")} equal.</>}
                      {" "}Anything else that differs in the same value still counts. Copying to the right writes <code>{w.right}</code>; copying to the left writes <code>{w.left}</code>.
                    </li>
                  );
                })}
                {rules.ignore_keys.map((k, i) => (
                  <li key={`k${i}`}>
                    <strong>Ignores</strong> differences in <code>{k.key}</code>{k.path && k.path !== "**" ? <> under <code>{k.path}</code></> : " everywhere"}
                    {effect && <> ({plural(effect.ignoredKeys[i], "secret")} in scope)</>}. The key is still shown, marked ignored. Use this for values that must differ, such as credentials.
                  </li>
                ))}
                {rules.ignore_paths.map((p, i) => (
                  <li key={`p${i}`}>
                    <strong>Leaves out</strong> <code>{p}</code>{effect && <> ({effect.ignoredPaths[i].left} on the left, {effect.ignoredPaths[i].right} on the right)</>}.
                  </li>
                ))}
              </ol>
            )}
            {effect && (
              <div className="explain-rest">
                <p><strong>With these rules</strong> {plural(effect.paired, "pair")} {effect.paired === 1 ? "is" : "are"} compared key by key.</p>
                {effect.leftOnly.length > 0 && <p>Only on the left: {short(effect.leftOnly)}.</p>}
                {effect.rightOnly.length > 0 && <p>Only on the right: {short(effect.rightOnly)}.</p>}
                {(effect.leftOnly.length > 0 || effect.rightOnly.length > 0) && (
                  <p className="subtle">These are secrets added or removed on one side: the differences you're looking for, unless a mapping is missing.</p>
                )}
              </div>
            )}
            {sides && (
              <div className="explain-preview">
                <button type="button" className="btn small" disabled={!valid || previewing} onClick={runPreview}>
                  {previewing && <span className="spinner" />} Preview the comparison
                </button>
                {preview && <p role="status">{countLine(preview)}.</p>}
              </div>
            )}
          </aside>
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
