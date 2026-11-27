import { useEffect, useState } from "react";
import { api } from "../api";
import type { Connection, NamespacesResponse } from "../types";

interface Props {
  conn: Connection;
  connections: Connection[];
  /** A connection opened in a child namespace (same token), or one already signed in */
  onPick: (c: Connection, opened: boolean) => void;
}

const UP = "up:";
const CHILD = "ns:";

/** Vault Enterprise and OpenBao namespaces: move this side to a child namespace (or back up)
 *  without signing in again. Hidden on a Vault without namespaces. */
export function NamespacePicker({ conn, connections, onPick }: Props) {
  const [data, setData] = useState<NamespacesResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setData(null);
    setError(null);
    if (conn.status !== "ok") return;
    api.namespaces(conn.id).then((d) => { if (live) setData(d); }).catch(() => { if (live) setData(null); });
    return () => { live = false; };
  }, [conn.id, conn.status]);

  const parent = conn.parent ? connections.find((c) => c.id === conn.parent) ?? null : null;
  if (!data?.supported || (!data.namespaces.length && !parent && !data.error)) return null;

  async function choose(v: string) {
    setError(null);
    if (v.startsWith(UP) && parent) { onPick(parent, false); return; }
    if (!v.startsWith(CHILD)) return;
    setBusy(true);
    try {
      onPick(await api.openNamespace(conn.id, v.slice(CHILD.length)), true);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <label className="field">
        <span>Namespace</span>
        <select value="" disabled={busy} onChange={(e) => choose(e.target.value)}>
          <option value="">{conn.namespace ? `${conn.namespace}/` : "root namespace"}{busy ? " (opening…)" : ""}</option>
          {parent && <option value={`${UP}${parent.id}`}>↑ {parent.namespace ? `${parent.namespace}/` : "root namespace"}</option>}
          {data.namespaces.map((n) => <option key={n.path} value={`${CHILD}${n.name}`}>↳ {n.path}/</option>)}
        </select>
      </label>
      {data.error && <div className="notice info">{data.error}</div>}
      {error && <div className="notice error">{error}</div>}
    </>
  );
}
