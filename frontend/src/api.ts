import type {
  AnalyzeOptions, AnalyzeResult, ApiChange, PasswordSearch, ExportDoc, ExportResult, ImportPreview, ImportRules, AppConfig, ApplyResult, ChangePlan, CompareResult, Connection, AccessChanges, AccessCompareResult, ConfigCompare, MfaChallenge, MfaConstraint, AccessItem, AccessPlanInfo, AuthMount, BrowseDiff, BrowseEdit, BrowseEditResult, BrowseList, BrowseSecret, DestroyOut, ExpiryResult, ExplainResult, PolicyBuildRule, PolicyCompareResult, PolicyProfile, RoleDraft, RoleFinding, RoleKind, RolePair, RolesList, RoleTemplate, SuggestResult, TerraformOptions, KeyHistory, Locator, Mount, MountsResponse, PlanApplyResult, PlanCheck, Profile, ProfileRules, SecretValues, SyncPlan,
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

export interface ExpiryProgress { side: "left" | "right"; stage: "listing" | "reading" | "scanning" | "pki" | "done";
                                  done: number; total: number; certificates: number }

/** The certificate scan, streamed: progress lines keep proxies from timing out a long scan. */
async function expiryStream(sides: { side: "left" | "right"; conn_id: string; mount: string; prefix: string }[],
                            onProgress: (p: ExpiryProgress) => void, includePki = false): Promise<ExpiryResult> {
  const res = await fetch("/api/expiry/stream", {
    method: "POST", credentials: "same-origin",
    headers: { "X-Requested-With": "lockstep", "Content-Type": "application/json" },
    body: JSON.stringify({ sides, include_pki: includePki }),
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
  connect: (input: ConnectInput) => call<Connection | MfaChallenge>("POST", "/api/connections", input),
  pendingMfa: () => call<{ constraints: MfaConstraint[]; name: string; side: string | null }>("GET", "/api/connections/mfa"),
  answerMfa: (payload: Record<string, string>) => call<Connection>("POST", "/api/connections/mfa", { payload }),
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
  policyNames: (connId: string) => call<{ names: string[] }>("GET", `/api/policies?conn_id=${encodeURIComponent(connId)}`),
  policyText: (connId: string, name: string) =>
    call<{ name: string; text: string }>("GET", `/api/policies/${encodeURIComponent(name)}?conn_id=${encodeURIComponent(connId)}`),
  explainPolicies: (body: { conn_id: string; mount: string; prefix: string; names?: string[];
                            pasted?: { name: string; text: string }[]; token?: "self";
                            identity?: { kind: "entity" | "group" | "token"; name: string } }) =>
    call<ExplainResult>("POST", "/api/policies/explain", body),
  browseList: (connId: string, mount: string, folder: string, offset = 0) =>
    call<BrowseList>("GET", `/api/browse/list?${q({ conn_id: connId, mount, folder, offset: String(offset) })}`),
  browseSecret: (connId: string, mount: string, path: string, version?: number | null) =>
    call<BrowseSecret>("GET", `/api/browse/secret?${q({ conn_id: connId, mount, path, ...(version ? { version: String(version) } : {}) })}`),
  browseValues: (connId: string, mount: string, path: string, version?: number | null) =>
    call<{ path: string; version: number; data: Record<string, unknown> }>(
      "GET", `/api/browse/values?${q({ conn_id: connId, mount, path, ...(version ? { version: String(version) } : {}) })}`),
  browseFind: (connId: string, mount: string, folder: string, query: string) =>
    call<{ matches: string[]; more: boolean; denied: string[]; truncated: boolean }>(
      "POST", "/api/browse/find", { conn_id: connId, mount, folder, query }),
  browseDiff: (connId: string, mount: string, path: string, a: number, b: number, reveal: boolean) =>
    call<BrowseDiff>("POST", "/api/browse/diff", { conn_id: connId, mount, path, a, b, reveal }),
  browseMetadata: (body: { conn_id: string; mount: string; path: string; expected_hash?: string; max_versions?: number;
                           cas_required?: boolean; delete_version_after?: string; custom_metadata?: Record<string, string> }) =>
    call<BrowseEditResult>("POST", "/api/browse/metadata", body),
  browseShare: (connId: string, mount: string, path: string, keys: string[] | null, ttl: string, version?: number | null) =>
    call<{ token: string; ttl: number; created: string; keys: string[] }>("POST", "/api/browse/share",
      { conn_id: connId, mount, path, keys, ttl, ...(version ? { version } : {}) }),
  browseUnwrap: (connId: string, token: string, open: boolean) =>
    call<{ info: { creation_time: string; creation_ttl: number; creation_path: string }; data?: Record<string, unknown> }>(
      "POST", "/api/browse/unwrap", { conn_id: connId, token, open }),
  browsePreview: (connId: string, mount: string, edits: BrowseEdit[], reveal: boolean) =>
    call<BrowseEditResult[]>("POST", "/api/browse/preview", { conn_id: connId, mount, edits, reveal }),
  browseApply: (connId: string, mount: string, edits: BrowseEdit[]) =>
    call<BrowseEditResult[]>("POST", "/api/browse/apply", { conn_id: connId, mount, edits, confirm: true }),
  buildPolicy: (mount: string, name: string, rules: PolicyBuildRule[]) =>
    call<{ hcl: string; findings: import("./types").PolicyFinding[] }>("POST", "/api/policies/build", { mount, name, rules }),
  suggestPolicies: (connId: string, mount: string, prefix: string, pattern: string | null) =>
    call<SuggestResult>("POST", "/api/policies/suggest", { conn_id: connId, mount, prefix, ...(pattern ? { pattern } : {}) }),
  policyBundle: async (policies: { name: string; text: string }[], terraform: TerraformOptions | null, connId: string | null,
                       roles: RoleDraft[] = []) => {
    const res = await fetch("/api/policies/bundle", {
      method: "POST", credentials: "same-origin",
      headers: { "X-Requested-With": "lockstep", "Content-Type": "application/json" },
      body: JSON.stringify({ policies, roles, ...(terraform ? { terraform } : {}), ...(connId ? { conn_id: connId } : {}) }),
    });
    if (!res.ok) {
      const body = await parseJson(res).catch(() => null);
      const d = body?.detail;
      throw new ApiError(res.status, typeof d?.message === "string" ? d.message : Array.isArray(d) ? d.map((x: { msg: string }) => x.msg).join("; ") : res.statusText);
    }
    const name = /filename="([^"]+)"/.exec(res.headers.get("Content-Disposition") ?? "")?.[1] ?? "lockstep-policies.zip";
    return { blob: await res.blob(), name };
  },
  policyPatterns: () => call<{ name: string; yaml: string }[]>("GET", "/api/policies/patterns"),
  accessPreview: (body: AccessChanges) => call<AccessItem[]>("POST", "/api/access/preview", body),
  accessApply: (body: AccessChanges, expected: Record<string, string | null>) =>
    call<AccessItem[]>("POST", "/api/access/apply", { ...body, expected, confirm: true }),
  accessPlanCreate: (body: AccessChanges) => call<Record<string, unknown> & { id: string }>("POST", "/api/access/plans", body),
  accessPlanCheck: (connIds: string[], plan: Record<string, unknown>) =>
    call<{ plan: AccessPlanInfo; conn_id: string; items: AccessItem[] }>("POST", "/api/access/plans/check", { conn_ids: connIds, plan }),
  accessPlanApply: (connIds: string[], plan: Record<string, unknown>) =>
    call<AccessItem[]>("POST", "/api/access/plans/apply", { conn_ids: connIds, plan, confirm: true }),
  configCompare: (left: string, right: string) => call<ConfigCompare>("POST", "/api/config/compare", { left, right }),
  identityGroups: (connId: string) => call<{ groups: { name: string; type?: string; policies?: string[]; members?: string[]; member_groups?: number; alias?: string }[]; missing: string[] }>(
    "GET", `/api/identity/groups?${q({ conn_id: connId })}`),
  compareGroups: (left: string, right: string, profile: PolicyProfile | null) =>
    call<{ pairs: { left: string | null; right: string | null; status: "equal" | "different" | "left_only" | "right_only"; fields: { field: string; left: unknown; right: unknown }[] }[];
           summary: Record<string, number>; missing: { left: string[]; right: string[] } }>("POST", "/api/identity/compare-groups", { left, right, ...(profile ? { profile } : {}) }),
  pkiMounts: (connId: string) => call<{ path: string; description: string }[]>("GET", `/api/pki/mounts?${q({ conn_id: connId })}`),
  pkiOverview: (connId: string, mount: string) =>
    call<{ issuers: { id: string; name?: string; subject?: string; not_after?: string; error?: string }[];
           roles: { name: string; allowed_domains?: string[]; allow_subdomains?: boolean; max_ttl?: number; key_type?: string; error?: string }[];
           missing: string[] }>("GET", `/api/pki/overview?${q({ conn_id: connId, mount })}`),
  pkiIssue: (body: { conn_id: string; mount: string; role: string; common_name: string; alt_names: string[]; ttl: string;
                     store?: { mount: string; path: string } }) =>
    call<{ certificate: string; private_key: string; ca_chain: string[]; serial: string;
           info: { subject: string; issuer: string; sans: string[]; not_before: string; not_after: string; serial: string; key: string };
           stored: { mount: string; path: string; version: number } | null }>("POST", "/api/pki/issue", body),
  transitMounts: (connId: string) => call<{ path: string; description: string }[]>("GET", `/api/transit/mounts?${q({ conn_id: connId })}`),
  transitKeys: (connId: string, mount: string) =>
    call<{ keys: { name: string; type?: string; latest_version?: number; min_decryption_version?: number; supports_encryption?: boolean;
                   supports_signing?: boolean; derived?: boolean; exportable?: boolean; deletion_allowed?: boolean; error?: string }[] }>(
      "GET", `/api/transit/keys?${q({ conn_id: connId, mount })}`),
  transitRun: (body: { conn_id: string; mount: string; key: string; op: string; text: string; signature?: string; context?: string }) =>
    call<{ result: string; key_version?: number; valid?: boolean; note?: string }>("POST", "/api/transit/run", body),
  leases: (connId: string, prefix: string) =>
    call<{ prefix: string; folders: string[]; leases: string[]; truncated: boolean; note?: string | null }>("GET", `/api/leases?${q({ conn_id: connId, prefix })}`),
  leaseLookup: (connId: string, ids: string[]) =>
    call<{ leases: { id: string; issue_time?: string; expire_time?: string | null; ttl?: number; renewable?: boolean; error?: string }[] }>(
      "POST", "/api/leases/lookup", { conn_id: connId, lease_ids: ids }),
  leaseRenew: (connId: string, id: string, increment?: number) =>
    call<{ lease_id: string; ttl: number; renewable: boolean }>("POST", "/api/leases/renew", { conn_id: connId, lease_id: id, increment }),
  leaseRevoke: (connId: string, ids: string[]) =>
    call<{ results: { id: string; revoked: boolean; error?: string }[]; revoked: number }>("POST", "/api/leases/revoke", { conn_id: connId, lease_ids: ids }),
  databaseMounts: (connId: string) => call<{ path: string; description: string }[]>("GET", `/api/database/mounts?${q({ conn_id: connId })}`),
  databaseOverview: (connId: string, mount: string) =>
    call<{ connections: { name: string; plugin_name?: string; connection_url?: string; username?: string; allowed_roles?: string[]; error?: string }[];
           roles: { name: string; db_name?: string; default_ttl?: number; max_ttl?: number; creation_statements?: string[]; error?: string }[];
           static_roles: { name: string; db_name?: string; username?: string; rotation_period?: number; last_vault_rotation?: string; error?: string }[];
           missing: string[] }>("GET", `/api/database/overview?${q({ conn_id: connId, mount })}`),
  databaseCreds: (connId: string, mount: string, role: string) =>
    call<{ data: Record<string, string>; lease_id: string; ttl: number; renewable: boolean }>("POST", "/api/database/creds", { conn_id: connId, mount, role }),
  roleMounts: (connId: string) => call<AuthMount[]>("GET", `/api/roles/mounts?${q({ conn_id: connId })}`),
  roles: (connId: string, mount: string) => call<RolesList>("GET", `/api/roles?${q({ conn_id: connId, mount })}`),
  roleTemplates: () => call<RoleTemplate[]>("GET", "/api/roles/templates"),
  roleCheck: (kind: RoleKind, body: Record<string, unknown>, connId: string | null) =>
    call<{ role: Record<string, unknown>; policies: string[]; findings: RoleFinding[] }>("POST", "/api/roles/check",
      { kind, body, ...(connId ? { conn_id: connId } : {}) }),
  roleExplain: (connId: string, mount: string, role: string, kvMount: string, prefix: string) =>
    call<ExplainResult>("POST", "/api/roles/explain", { conn_id: connId, mount, role, kv_mount: kvMount, prefix }),
  roleCompare: (left: { conn_id: string; mount: string }, right: { conn_id: string; mount: string }, profile: PolicyProfile | null) =>
    call<{ kind: RoleKind; pairs: RolePair[]; summary: Record<string, number> }>("POST", "/api/roles/compare",
      { left, right, ...(profile ? { profile } : {}) }),
  issueSecretId: (connId: string, mount: string, role: string, ttl: string) =>
    call<{ role_id: string; wrapping_token: string; ttl: number }>("POST", "/api/roles/secret-id", { conn_id: connId, mount, role, ttl }),
  roleGranting: (connId: string, policy: string) =>
    call<{ policy: string; roles: { mount: string; kind: RoleKind; role: string }[]; unreadable_mounts: string[]; groups: string[]; groups_missing: string[] }>(
      "GET", `/api/roles/granting?${q({ conn_id: connId, policy })}`),
  policyProfiles: () => call<PolicyProfile[]>("GET", "/api/policies/profiles"),
  comparePolicies: (left: string, right: string, profile: PolicyProfile | null) =>
    call<PolicyCompareResult>("POST", "/api/policies/compare", { left, right, ...(profile ? { profile } : {}) }),
  compareAccess: (left: { conn_id: string; mount: string; prefix: string; name: string },
                  right: { conn_id: string; mount: string; prefix: string; name: string }) =>
    call<AccessCompareResult>("POST", "/api/policies/compare-access", { left, right }),
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
