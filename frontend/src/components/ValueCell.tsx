import { type ReactNode, useState } from "react";

interface Props {
  side: "left" | "right";
  /** Why there is nothing to show, if that's the case. */
  unavailable?: "absent" | "no_access" | "deleted" | "error";
  reveal: boolean;
  loading: boolean;
  value: unknown;
  highlight: boolean;
  /** Types differ between the sides: show the JSON form (strings quoted) and the type. */
  typed?: boolean;
  /** Metadata line under the value (e.g. when the key last changed). Never part of the comparison. */
  meta?: ReactNode;
}

const LONG = 300;

export function formatValue(v: unknown, typed = false): string {
  return typeof v === "string" && !typed ? v : JSON.stringify(v, null, 2);
}

export function typeName(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v === "object" ? "object" : typeof v;
}

// Every state renders the same root (.val-cell > .val [+ tools] [+ meta]), so layout and
// the "incoming value" outline selectors don't depend on which state a cell is in.
export function ValueCell(props: Props) {
  return (
    <div className="val-cell">
      <ValueBody {...props} />
      {props.meta && <div className="val-meta">{props.meta}</div>}
    </div>
  );
}

function ValueBody({ side, unavailable, reveal, loading, value, highlight, typed }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  if (unavailable) {
    const text = { absent: "not present", no_access: "no access", deleted: "deleted", error: "read failed" }[unavailable];
    return <div className="val absent">{text}</div>;
  }
  if (!reveal) return <div className={`val masked ${highlight ? `diff-${side[0]}` : ""}`}>••••••••</div>;
  if (loading || value === undefined) return <div className="val"><span className="spinner" /></div>;

  const text = formatValue(value, typed);
  const long = text.length > LONG || text.split("\n").length > 6;

  return (
    <div className="val-wrap">
      <div className={`val ${expanded ? "expanded" : ""} ${highlight ? `diff-${side[0]}` : ""}`}>
        {typed && <span className="type-tag">{typeName(value)}</span>}{text}
      </div>
      <button type="button" className="btn small copy" onClick={async () => {
        await navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      }}>{copied ? "Copied" : "Copy"}</button>
      {long && (
        <div className="val-tools">
          <button type="button" className="btn ghost small" onClick={() => setExpanded(!expanded)}>
            {expanded ? "Collapse" : `Expand (${text.length.toLocaleString()} chars)`}
          </button>
        </div>
      )}
    </div>
  );
}
