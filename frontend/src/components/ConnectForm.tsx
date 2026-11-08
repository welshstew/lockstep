import { useEffect, useRef, useState } from "react";
import { api, type AuthInput } from "../api";
import type { AppConfig, Connection } from "../types";

type Method = "token" | "userpass" | "ldap" | "oidc" | "kubernetes";

interface Props {
  config: AppConfig;
  onConnected: (c: Connection) => void;
  onCancel?: () => void;
  /** Pre-select a target, for example when reconnecting an expired connection. */
  initialPresetId?: number | null;
  /** Which side of the comparison this form belongs to (returned after an OIDC redirect). */
  side?: "left" | "right";
}

type LoginMethod = { path: string; type: string; description: string };
const OIDC_TYPES = ["oidc", "jwt"];

export function ConnectForm({ config, onConnected, onCancel, initialPresetId, side }: Props) {
  const firstPreset = config.presets[0]?.id ?? null;
  const [target, setTarget] = useState<string>(
    initialPresetId != null ? String(initialPresetId)
      : firstPreset != null ? String(firstPreset) : "custom");
  const [url, setUrl] = useState("");
  const [namespace, setNamespace] = useState("");
  const [method, setMethod] = useState<Method>("userpass");
  const [token, setToken] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [authMount, setAuthMount] = useState("");
  const [role, setRole] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [methods, setMethods] = useState<LoginMethod[] | null>(null);
  // Set once the user picks a login method, so a slow discovery reply never overrides it.
  const picked = useRef(false);

  const k8s = config.k8s_auth ?? { available: false, mount: "kubernetes", roles: [], service_account: null };
  const custom = target === "custom";
  const preset = custom ? null : config.presets.find((p) => String(p.id) === target) ?? null;
  const targetBody = custom ? { url } : { preset_id: preset?.id };

  // Ask the Vault which login methods it advertises (like the Vault UI's login screen),
  // and pre-select OIDC when it's offered, unless the user has already chosen a method.
  useEffect(() => {
    if (custom && !/^https?:\/\/[^/]+/.test(url)) { setMethods(null); return; }
    let live = true;
    const t = setTimeout(() => {
      api.loginMethods({ ...targetBody, ...(namespace ? { namespace } : {}) })
        .then(({ methods: m }) => {
          if (!live) return;
          setMethods(m);
          const oidc = m.find((x) => OIDC_TYPES.includes(x.type));
          if (oidc && !picked.current) { setMethod("oidc"); setAuthMount(oidc.path === "oidc" ? "" : oidc.path); }
        })
        .catch(() => { if (live) setMethods(null); });
    }, custom ? 400 : 0);
    return () => { live = false; clearTimeout(t); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target, url, namespace]);

  async function startOidc() {
    setBusy(true);
    setError(null);
    try {
      const { auth_url } = await api.oidcStart({
        ...targetBody, ...(namespace ? { namespace } : {}),
        mount: authMount || "oidc", ...(role ? { role } : {}), ...(side ? { side } : {}),
      });
      window.location.assign(auth_url); // full-page redirect to the identity provider
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (method === "oidc") { startOidc(); return; }
    setBusy(true);
    setError(null);
    const auth: AuthInput = method === "token"
      ? { method, token }
      : method === "kubernetes"
        ? { method, role, ...(authMount ? { mount: authMount } : {}) }
        : { method, username, password, ...(authMount ? { mount: authMount } : {}) };
    try {
      const conn = await api.connect({
        ...(custom ? { url } : { preset_id: preset!.id }),
        ...(namespace ? { namespace } : {}),
        auth,
      });
      setPassword("");
      setToken("");
      onConnected(conn);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} autoComplete="off">
      <label className="field">
        <span>Vault</span>
        <select value={target} onChange={(e) => setTarget(e.target.value)}>
          {config.presets.map((p) => (
            <option key={p.id} value={p.id}>{p.name}{p.browser_url ? ` (${p.browser_url})` : ""}</option>
          ))}
          {config.allow_custom_connections && <option value="custom">Other Vault URL…</option>}
        </select>
      </label>

      {custom && (
        <label className="field">
          <span>Vault address</span>
          <input type="text" placeholder="https://vault.example.com:8200" value={url}
                 onChange={(e) => setUrl(e.target.value)} required />
        </label>
      )}
      {(custom || !preset?.namespace) && (
        <label className="field">
          <span>Namespace <span className="subtle">(optional, Enterprise)</span></span>
          <input type="text" placeholder="admin/team-a" value={namespace} onChange={(e) => setNamespace(e.target.value)} />
        </label>
      )}

      <div className="field">
        <span>Sign in with</span>
        <div className="segmented" role="group" aria-label="Authentication method">
          {(["userpass", "ldap", "token", "oidc", ...(k8s.available ? ["kubernetes"] : [])] as Method[]).map((m) => (
            <button key={m} type="button" aria-pressed={method === m}
                    onClick={() => { picked.current = true; setMethod(m); setAuthMount(""); setRole(m === "kubernetes" && k8s.roles.length ? k8s.roles[0] : ""); }}>
              {{ userpass: "Username", ldap: "LDAP", token: "Token", oidc: "OIDC", kubernetes: "Kubernetes" }[m]}
            </button>
          ))}
        </div>
      </div>

      {methods && methods.length > 0 && (
        <div className="subtle" style={{ marginTop: -4, marginBottom: 8 }}>
          This Vault offers: {methods.map((m) => `${m.type} (${m.path}/)`).join(", ")}
        </div>
      )}

      {method === "kubernetes" ? (
        <>
          <div className="row">
            <label className="field grow">
              <span>Auth mount path <span className="subtle">(default: {k8s.mount})</span></span>
              <input type="text" value={authMount} onChange={(e) => setAuthMount(e.target.value)}
                     placeholder={methods?.find((x) => x.type === "kubernetes")?.path ?? k8s.mount} />
            </label>
            <label className="field grow">
              <span>Role name</span>
              {k8s.roles.length > 0 ? (
                <select value={role} onChange={(e) => setRole(e.target.value)}>
                  {k8s.roles.map((r) => <option key={r} value={r}>{r}</option>)}
                </select>
              ) : (
                <input type="text" value={role} onChange={(e) => setRole(e.target.value)} placeholder="e.g. lockstep-reader" required />
              )}
            </label>
          </div>
          <div className="notice warn" style={{ marginTop: 0 }}>
            Signs in as this tool’s Kubernetes service account
            {k8s.service_account ? <> <strong className="mono">{k8s.service_account}</strong></> : ""}, not as you.
            You get that account’s Vault access, and changes are logged under it.
          </div>
        </>
      ) : method === "oidc" ? (
        <>
          <div className="row">
            <label className="field grow">
              <span>Auth mount path <span className="subtle">(default: oidc)</span></span>
              <input type="text" value={authMount} onChange={(e) => setAuthMount(e.target.value)} placeholder="oidc" />
            </label>
            <label className="field grow">
              <span>Role <span className="subtle">(optional)</span></span>
              <input type="text" value={role} onChange={(e) => setRole(e.target.value)} placeholder="the mount's default role" />
            </label>
          </div>
          <div className="subtle" style={{ marginBottom: 8 }}>
            You'll be sent to your identity provider to sign in, then brought back here.
          </div>
        </>
      ) : method === "token" ? (
        <label className="field">
          <span>Token</span>
          <input type="password" value={token} onChange={(e) => setToken(e.target.value)} placeholder="hvs.…" required />
        </label>
      ) : (
        <>
          <div className="row">
            <label className="field grow">
              <span>Username</span>
              <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} required />
            </label>
            <label className="field grow">
              <span>Password</span>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            </label>
          </div>
          <label className="field">
            <span>Auth mount path <span className="subtle">(default: {method})</span></span>
            <input type="text" value={authMount} onChange={(e) => setAuthMount(e.target.value)} placeholder={method} />
          </label>
        </>
      )}

      {error && <div className="notice error" role="alert">{error}</div>}

      <div className="row" style={{ justifyContent: "flex-end", marginTop: 4 }}>
        {onCancel && <button type="button" className="btn ghost" onClick={onCancel}>Cancel</button>}
        <button type="submit" className="btn primary" disabled={busy}>
          {busy && <span className="spinner" />} {method === "oidc" ? "Continue with OIDC →" : "Connect"}
        </button>
      </div>
    </form>
  );
}
