import type {
  AnalyzeOptions, AnalyzeResult, ApiChange, PasswordSearch, ExportDoc, ExportResult, ImportPreview, ImportRules, AppConfig, ApplyResult, ChangePlan, CompareResult, Connection, DestroyOut, ExpiryResult, KeyHistory, Locator, Mount, MountsResponse, PlanApplyResult, PlanCheck, Profile, ProfileRules, SecretValues, SyncPlan,
} from "./types";

/** A comparison side: a Vault location, or an opened export file (read-only). */
export type SideRef = { conn_id: string; mount: string; prefix: string } | { export: ExportDoc; name: string; prefix: string };
type VaultSide = { conn_id: string; mount: string; prefix: string };

export class ApiError extends Error {
  constructor(public status: number, message: string, public detail: Record<string, unknown> = {}) {
    super(message);
  }
  get reconnect(): boolean {
    return Boolean(this.detail.reconnect);
  }
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: {
      "X-Requested-With": "lockstep",
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return undefined as T;
  const json = await parseJson(res);
  if (!res.ok) {
    const d = json.detail;
    const msg = typeof d === "string" ? d
      : d?.message ?? (Array.isArray(d) ? d.map((e: { msg: string }) => e.msg).join("; ") : res.statusText);
    throw new ApiError(res.status, msg, typeof d === "object" && !Array.isArray(d) ? d : {});
  }
  return json as T;
}

/** A response that isn't JSON came from something in between (a proxy's error page, usually). */
function notJson(res: Response): ApiError {
  const why = res.status === 502 || res.status === 503 || res.status === 504
    ? "The server didn't answer in time, or couldn't be reached"
    : "The server sent an unexpected answer";
  return new ApiError(res.status, `${why} (HTTP ${res.status}${res.statusText ? ` ${res.statusText}` : ""}, `
    + "not from Lockstep itself: probably a proxy in front of it). Try again, or narrow the request, for example with a path prefix.");
}

async function parseJson(res: Response): Promise<any> {
  const text = await res.text();
  if (!text) return {};
  try { return JSON.parse(text); } catch { throw notJson(res); }
}

export interface ExpiryProgress { side: "left" | "right"; stage: "listing" | "reading" | "scanning" | "done";
                                  done: number; total: number; certificates: number }

/** The certificate scan, streamed: progress lines keep proxies from timing out a long scan. */
async function expiryStream(sides: { side: "left" | "right"; conn_id: string; mount: string; prefix: string }[],
                            onProgress: (p: ExpiryProgress) => void): Promise<ExpiryResult> {
  const res = await fetch("/api/expiry/stream", {
    method: "POST", credentials: "same-origin",
    headers: { "X-Requested-With": "lockstep", "Content-Type": "application/json" },
    body: JSON.stringify({ sides }),
  });
  if (!res.ok || !res.body) {
    const j = await parseJson(res);
    throw new ApiError(res.status, j?.detail?.message ?? res.statusText, j?.detail ?? {});
  }
  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    buf += value ?? "";
    const lines = buf.split("\n");
    buf = done ? "" : lines.pop()!;
    for (const line of lines.filter((l) => l.trim())) {
      let ev;
      try { ev = JSON.parse(line); } catch { throw notJson(res); }
      if (ev.progress) onProgress(ev.progress);
      if (ev.error) throw new ApiError(ev.error.status ?? 500, ev.error.message ?? "The scan failed.", ev.error);
      if (ev.result) return ev.result as ExpiryResult;
    }
    if (done) throw new ApiError(502, "The scan stopped before it finished (the connection was cut). Try again, or scan a narrower path.");
  }
}

const q = (params: Record<string, string>) => new URLSearchParams(params).toString();

export type AuthInput =
  | { method: "token"; token: string }
  | { method: "userpass" | "ldap"; username: string; password: string; mount?: string }
  | { method: "kubernetes"; role: string; mount?: string }
  | { method: "jwt"; jwt: string; role?: string; mount?: string };

export interface ConnectInput {
  preset_id?: number;
  url?: string;
  namespace?: string;
  name?: string;
  auth: AuthInput;
}

/** Raw bytes of one part of an analysed value (download / image preview). */
async function content(loc: Locator, opts: AnalyzeOptions, nodeId: string) {
  const res = await fetch("/api/analyze/content", {
    method: "POST",
    credentials: "same-origin",
    headers: { "X-Requested-With": "lockstep", "Content-Type": "application/json" },
    body: JSON.stringify({ ...loc, ...opts, node_id: nodeId }),
  });
  if (!res.ok) {
    const j = await parseJson(res);
    throw new ApiError(res.status, j?.detail?.message ?? res.statusText);
  }
  return {
    blob: await res.blob(),
    filename: res.headers.get("X-Filename") ?? "value.bin",
    mime: res.headers.get("X-Mime") ?? "application/octet-stream",
  };
}

export const api = {
  loginMethods: (target: { preset_id?: number; url?: string; namespace?: string }) =>
    call<{ methods: { path: string; type: string; description: string }[] }>("POST", "/api/auth/methods", target),
  oidcStart: (body: { preset_id?: number; url?: string; namespace?: string; mount: string; role?: string; side?: string }) =>
    call<{ auth_url: string }>("POST", "/api/auth/oidc/start", body),
  expiry: (sides: { side: "left" | "right"; conn_id: string; mount: string; prefix: string }[]) =>
    call<ExpiryResult>("POST", "/api/expiry", { sides }),
  expiryStream,
  analyze: (loc: Locator, opts: AnalyzeOptions) => call<AnalyzeResult>("POST", "/api/analyze", { ...loc, ...opts }),
  findPasswords: (loc: Locator) => call<PasswordSearch>("POST", "/api/analyze/passwords", loc),
  content,
  config: () => call<AppConfig>("GET", "/api/config"),
  connections: () => call<Connection[]>("GET", "/api/connections"),
  connect: (input: ConnectInput) => call<Connection>("POST", "/api/connections", input),
  disconnect: (id: string) => call<void>("DELETE", `/api/connections/${id}`),
  mounts: (id: string) => call<MountsResponse>("GET", `/api/connections/${id}/mounts`),
  describeMount: (id: string, path: string) =>
    call<Mount>("GET", `/api/connections/${id}/mounts/${encodeURIComponent(path).replace(/%2F/g, "/")}`),
  compare: (left: SideRef, right: SideRef, rules?: ProfileRules | null) =>
    call<CompareResult>("POST", "/api/compare", { left, right, ...(rules ? { rules } : {}) }),
  profiles: () => call<Profile[]>("GET", "/api/profiles"),
  syncPreview: (left: SideRef, right: SideRef, changes: ApiChange[], reveal: boolean) =>
    call<ChangePlan[]>("POST", "/api/sync/preview", { left, right, changes, reveal }),
  syncApply: (left: SideRef, right: SideRef, changes: ApiChange[]) =>
    call<ApplyResult>("POST", "/api/sync/apply", { left, right, changes, confirm: true }),
  destroy: (side: VaultSide, secrets: { path: string; expected_version: number | null }[]) =>
    call<DestroyOut>("POST", "/api/destroy", { side, secrets, confirm: true }),
  planCreate: (left: VaultSide, right: VaultSide, changes: ApiChange[], note: string, profile: string | null) =>
    call<SyncPlan>("POST", "/api/plans", { left, right, changes, note, profile }),
  planVerify: (plan: unknown) => call<{ plan: SyncPlan }>("POST", "/api/plans/verify", { plan }),
  planReport: async (plan: SyncPlan) => {
    const res = await fetch("/api/plans/report", {
      method: "POST", credentials: "same-origin",
      headers: { "X-Requested-With": "lockstep", "Content-Type": "application/json" },
      body: JSON.stringify({ plan }),
    });
    if (!res.ok) throw new ApiError(res.status, (await parseJson(res))?.detail?.message ?? res.statusText);
    return res.text();
  },
  planCheck: (plan: SyncPlan, left_conn_id: string, right_conn_id: string) =>
    call<PlanCheck>("POST", "/api/plans/check", { plan, left_conn_id, right_conn_id }),
  planApply: (plan: SyncPlan, left_conn_id: string, right_conn_id: string) =>
    call<PlanApplyResult>("POST", "/api/plans/apply", { plan, left_conn_id, right_conn_id, confirm: true }),
  exportCreate: (side: VaultSide, rules: { ignore_paths: string[]; ignore_keys: { key: string; path: string }[] }, encrypt: boolean) =>
    call<ExportResult>("POST", "/api/exports", { side, rules, encrypt }),
  exportOpen: (file: unknown, key?: string) =>
    call<{ export: ExportDoc; encrypted: boolean }>("POST", "/api/exports/open", { file, ...(key ? { key } : {}) }),
  importPreview: (exp: ExportDoc, name: string, rules: ImportRules, target: VaultSide, reveal: boolean, deleteMissing: boolean) =>
    call<ImportPreview>("POST", "/api/import/preview", { export: exp, name, rules, target, reveal, delete_missing: deleteMissing }),
  importApply: (exp: ExportDoc, name: string, rules: ImportRules, target: VaultSide, expected: Record<string, number | null>, deleteMissing: boolean) =>
    call<ApplyResult>("POST", "/api/import/apply", { export: exp, name, rules, target, expected, delete_missing: deleteMissing, confirm: true }),
  history: (id: string, mount: string, path: string) =>
    call<KeyHistory>("GET", `/api/connections/${id}/history?${q({ mount, path })}`),
  secret: (id: string, mount: string, path: string) =>
    call<SecretValues>("GET", `/api/connections/${id}/secret?${q({ mount, path })}`),
};
