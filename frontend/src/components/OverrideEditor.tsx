import { useState } from "react";
import type { Side } from "../staging";

interface Row {
  key: string;
  on: boolean; // include this key in the override
  text: string;
  json: boolean; // parse the text as JSON (numbers, booleans, objects…) instead of a string
  added: boolean; // a new key, not in the secret yet
}

interface Props {
  targets: Side[];
  sideNames: Record<Side, string>;
  keys: string[]; // the secret's keys (both sides)
  initial: Record<string, unknown>; // values already staged for the first target
  current: Record<string, unknown> | null; // the first target's current values, when Show values is on
  reveal: boolean;
  onSave: (values: Record<string, unknown> | null) => void;
  onCancel: () => void;
}

const asText = (v: unknown) => (typeof v === "string" ? v : JSON.stringify(v, null, 2));

/** Type the values to write to one or both sides. Values stay in this page until applied. */
export function OverrideEditor({ targets, sideNames, keys, initial, current, reveal, onSave, onCancel }: Props) {
  const [rows, setRows] = useState<Row[]>(() => {
    const names = [...new Set([...keys, ...Object.keys(initial)])].sort();
    return names.map((key) => {
      const staged = key in initial;
      const v = staged ? initial[key] : current?.[key];
      return { key, on: staged, text: v === undefined ? "" : asText(v),
               json: v !== undefined && typeof v !== "string", added: !keys.includes(key) };
    });
  });
  const [newKey, setNewKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const where = targets.map((t) => sideNames[t]).join(" and ");

  const update = (i: number, patch: Partial<Row>) => setRows((rs) => rs.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  function addKey() {
    const k = newKey.trim();
    if (!k) return;
    if (rows.some((r) => r.key === k)) { setError(`“${k}” is already in the list.`); return; }
    setRows([...rows, { key: k, on: true, text: "", json: false, added: true }]);
    setNewKey("");
    setError(null);
  }

  function save() {
    const values: Record<string, unknown> = {};
    for (const r of rows.filter((x) => x.on)) {
      if (!r.json) { values[r.key] = r.text; continue; }
      try { values[r.key] = JSON.parse(r.text); } catch {
        setError(`“${r.key}” isn't valid JSON. Untick JSON to store it as text.`);
        return;
      }
    }
    onSave(Object.keys(values).length ? values : null);
  }

  return (
    <div className="override-editor" role="group" aria-label={`Override values on ${where}`}>
      <div className="override-head">
        <strong>Set values on {where}</strong>
        <span className="subtle">
          Ticked keys are written as typed when you apply; other keys stay as they are.
          {!reveal && " Values are masked while Show values is off."}
        </span>
      </div>
      {rows.map((r, i) => (
        <div className="override-row" key={r.key}>
          <label className="inline-check override-key">
            <input type="checkbox" checked={r.on} onChange={(e) => update(i, { on: e.target.checked })}
                   aria-label={`Set ${r.key}`} />
            <span className="mono">{r.key}</span>
            {r.added && <span className="badge kind equal">new</span>}
          </label>
          <textarea className={`mono override-value${reveal ? "" : " masked-input"}`} rows={Math.min(6, Math.max(1, r.text.split("\n").length))}
                    value={r.text} spellCheck={false} autoComplete="off" aria-label={`New value for ${r.key}`}
                    onChange={(e) => update(i, { text: e.target.value, on: true })} />
          <label className="inline-check subtle" title="Store as a JSON value (number, boolean, object…) instead of text">
            <input type="checkbox" checked={r.json} onChange={(e) => update(i, { json: e.target.checked })} /> JSON
          </label>
        </div>
      ))}
      <div className="override-row">
        <input type="text" className="mono override-key" placeholder="new key name" value={newKey} aria-label="New key name"
               onChange={(e) => setNewKey(e.target.value)}
               onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addKey(); } }} />
        <button type="button" className="btn small" onClick={addKey} disabled={!newKey.trim()}>＋ Add key</button>
      </div>
      {error && <div className="notice error" role="alert">{error}</div>}
      <div className="override-foot">
        {Object.keys(initial).length > 0 && (
          <button type="button" className="btn ghost small" onClick={() => onSave(null)}>Remove override</button>
        )}
        <span className="spacer" />
        <button type="button" className="btn ghost small" onClick={onCancel}>Cancel</button>
        <button type="button" className="btn primary small" onClick={save}>Stage override</button>
      </div>
    </div>
  );
}
