import { useEffect, useState } from "react";
import { api } from "../api";
import type { MountsResponse } from "../types";

interface Props {
  connId: string;
  mount: string | null;
  onChange: (mount: string | null) => void;
}

const MANUAL = "__manual__";

export function MountSelect({ connId, mount, onChange }: Props) {
  const [data, setData] = useState<MountsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [manual, setManual] = useState(false);
  const [manualPath, setManualPath] = useState("");
  const [checking, setChecking] = useState(false);
  const [manualError, setManualError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setData(null);
    setError(null);
    api.mounts(connId)
      .then((d) => { if (live) setData(d); })
      .catch((e) => { if (live) { setError(e.message); setManual(true); } });
    return () => { live = false; };
  }, [connId]);

  const listed = data?.mounts.some((m) => m.path === mount) ?? false;
  const selectValue = manual || (mount && !listed) ? MANUAL : mount ?? "";

  async function useManual() {
    const path = manualPath.trim().replace(/^\/+|\/+$/g, "");
    if (!path) return;
    setChecking(true);
    setManualError(null);
    try {
      const m = await api.describeMount(connId, path);
      onChange(m.path);
    } catch (e) {
      setManualError((e as Error).message);
    } finally {
      setChecking(false);
    }
  }

  return (
    <>
      <label className="field">
        <span>KV v2 secret engine</span>
        <select
          value={selectValue}
          disabled={!data && !error}
          onChange={(e) => {
            if (e.target.value === MANUAL) {
              setManual(true);
              setManualPath(mount ?? "");
            } else {
              setManual(false);
              onChange(e.target.value || null);
            }
          }}
        >
          <option value="">{data || error ? "Choose a mount…" : "Loading mounts…"}</option>
          {data?.mounts.map((m) => (
            <option key={m.path} value={m.path}>{m.path}/{m.description ? ` · ${m.description}` : ""}</option>
          ))}
          <option value={MANUAL}>{mount && !listed && !manual ? `${mount}/ (entered manually)` : "Enter a path manually…"}</option>
        </select>
      </label>

      {data && !data.complete && (
        <div className="notice info">
          This token can’t list every mount, so only mounts it can access are shown. If yours is missing, enter its path.
        </div>
      )}
      {error && <div className="notice error">Couldn’t list mounts: {error}</div>}

      {manual && (
        <div className="field">
          <span>Mount path</span>
          <div className="row">
            <input className="grow" type="text" value={manualPath} placeholder="e.g. app-config"
                   onChange={(e) => setManualPath(e.target.value)}
                   onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); useManual(); } }} />
            <button type="button" className="btn" onClick={useManual} disabled={checking || !manualPath.trim()}>
              {checking && <span className="spinner" />} Use
            </button>
          </div>
          {manualError && <div className="notice error">{manualError}</div>}
        </div>
      )}
    </>
  );
}
