export interface Preset {
  id: number;
  name: string;
  browser_url: string | null;
  namespace: string | null;
}

export interface AppConfig {
  presets: Preset[];
  allow_custom_connections: boolean;
  demo_banner?: string;
  export_mode?: "any" | "encrypted" | "off";
  allow_destroy?: boolean;
  read_only?: boolean;
  allow_clipboard?: boolean;
  policy_apply?: boolean;
  k8s_auth: {
    available: boolean;
    mount: string;
    roles: string[];
    service_account: string | null;
  };
}

export type ConnStatus = "ok" | "expired" | "unreachable" | "unknown";

export interface Connection {
  id: string;
  name: string;
  url: string | null;
  namespace: string | null;
  preset_id: number | null;
  auth_method: string;
  display_name: string;
  policies: string[];
  expires_at: number | null;
  status: ConnStatus;
}

export interface Mount {
  path: string;
  description: string;
}

export interface MountsResponse {
  mounts: Mount[];
  source: string;
  complete: boolean;
}

export type KeyStatus = "equal" | "different" | "left_only" | "right_only" | "unknown";
export type SecretStatus = "equal" | "different" | "left_only" | "right_only" | "no_access" | "error";
export type SideState = "present" | "absent" | "deleted" | "no_access" | "error";

export interface KeyDiff {
  key: string;
  status: KeyStatus;
  type_differs: boolean;
  ignored: boolean;
}

export interface SideInfo {
  state: SideState;
  version: number | null;
  updated: string | null;
  error: string | null;
}

export interface Badge {
  kind: string;
  label: string;
  status: "ok" | "warn" | "bad" | null;
  detail: string;
}

export interface SecretDiff {
  path: string;
  status: SecretStatus;
  left: SideInfo;
  right: SideInfo;
  keys: KeyDiff[];
  badges: Record<string, { left: Badge | null; right: Badge | null }>;
  left_path: string;
  right_path: string;
  ignored_keys: number;
  note: string;
}

export interface SideSummary {
  kind?: "vault" | "file";
  conn_id: string;
  mount: string;
  prefix: string;
  denied: string[];
  truncated: boolean;
  secret_count: number;
}

export interface CompareResult {
  left: SideSummary;
  right: SideSummary;
  secrets: SecretDiff[];
  summary: Record<SecretStatus | "total" | "ignored_paths" | "ignored_keys" | "mapped", number>;
}

export interface SecretValues {
  path: string;
  state: string;
  version: number | null;
  updated: string | null;
  data: Record<string, unknown> | null;
}

/** What the user has picked for one side of the comparison. */
export interface SideSelection {
  connId: string | null;
  mount: string | null;
  prefix: string;
  fileId?: string | null; // an opened export file instead of a Vault connection
}

export type SyncDirection = "left_to_right" | "right_to_left";

export interface ApiChange {
  path: string;
  right_path: string;
  direction: SyncDirection;
  keys: string[] | null;
  set?: Record<string, unknown>;
  remove?: string[];
  expected_target_version: number | null;
  expected_source_version: number | null;
}

export interface SyncEndpoint {
  conn_id: string;
  name: string;
  mount: string;
  path: string;
  version: number | null;
  state: string;
}

export interface KeyPlan {
  key: string;
  action: "add" | "update" | "unchanged" | "remove";
  type_change: boolean;
  override: boolean;
  source_value: unknown;
  target_value: unknown;
}

export type PlanStatus = "ready" | "noop" | "conflict" | "denied" | "invalid" | "error";

export interface ChangePlan {
  path: string;
  right_path: string;
  direction: SyncDirection;
  action?: "write" | "delete";
  source: SyncEndpoint;
  target: SyncEndpoint;
  keys: KeyPlan[];
  can_write: boolean;
  problems: string[];
  warnings: string[];
  status: PlanStatus;
}

export type ResultStatus = "applied" | "noop" | "conflict" | "denied" | "invalid" | "error";

export interface ChangeResult {
  path: string;
  direction: SyncDirection;
  action?: "write" | "delete";
  target: string;
  status: ResultStatus;
  overridden: string[];
  old_version: number | null;
  new_version: number | null;
  keys: string[];
  message: string;
}

export type DestroyStatus = "destroyed" | "absent" | "conflict" | "denied" | "error";

export interface DestroyResult {
  path: string;
  target: string;
  status: DestroyStatus;
  version: number | null;
  versions: number | null;
  message: string;
}

export interface DestroyOut {
  results: DestroyResult[];
  summary: Record<DestroyStatus, number>;
}

export interface ApplyResult {
  results: ChangeResult[];
  summary: Record<ResultStatus, number>;
}

export interface KeyChange {
  version: number;
  time: string | null;
  exact: boolean;
}

export interface KeyHistory {
  path: string;
  current_version: number | null;
  updated: string | null;
  keys: Record<string, KeyChange>;
}

export interface ChainLink {
  subject: string;
  sha256: string;
  status: "valid" | "expiring" | "expired" | "not_yet_valid";
  anchor: boolean;
  self_signed: boolean;
  signature_ok: boolean | null;
  issuer_is_ca: boolean | null;
  problem: string;
}

export interface Chain {
  verdict: "trusted" | "untrusted_root" | "incomplete" | "invalid";
  reason: string;
  links: ChainLink[];
}

export interface CertInfo {
  subject: string;
  issuer: string;
  serial: string;
  not_before: string;
  not_after: string;
  status: "valid" | "expiring" | "expired" | "not_yet_valid";
  days_left: number;
  sans: string[];
  key_usage: string[];
  extended_key_usage: string[];
  is_ca: boolean;
  path_length: number | null;
  self_signed: boolean;
  public_key: string;
  signature_algorithm: string;
  sha256: string;
  sha1: string;
  subject_key_id: string | null;
  authority_key_id: string | null;
}

export interface AnalysisNode {
  id: string;
  kind: string;
  label: string;
  size: number;
  encoding: string[];
  mime: string;
  ext: string;
  downloadable: boolean;
  details: {
    certificate?: CertInfo;
    chain?: Chain;
    alias?: string;
    key?: string;
    matches?: string[];
    integrity?: string;
    entries?: { name: string; size: number }[];
    decoded_size?: number;
    subject?: string;
    public_key?: string;
    signature_valid?: boolean;
  };
  children: AnalysisNode[];
  problems: string[];
  notes: string[];
  needs_password: boolean;
}

export interface Locator {
  conn_id: string;
  mount: string;
  path: string;
  key: string;
}

export interface PasswordRef {
  path: string;
  key: string;
}

export interface AnalyzeOptions {
  password?: string | null;
  password_key?: string | null;
  password_ref?: PasswordRef | null;
  trust?: Locator[];
  trust_sha256?: string[];
  system_roots?: boolean;
}

export interface PasswordCandidate {
  path: string;
  key: string;
  opens: boolean;
  reasons: string[];
}

export interface PasswordSearch {
  needs_password: boolean;
  candidates: PasswordCandidate[];
  default: string | null;
  default_label: string | null;
  searched: string;
  secrets: number;
  truncated: boolean;
  denied: string[];
}

export interface AnalyzeResult {
  root: AnalysisNode;
  password_used: boolean;
  password_suggestions: string[];
  siblings: { key: string; certificates: number }[];
  trust_anchors: { system: number; selected: number };
}

export interface CertRow {
  side: "left" | "right";
  conn_id: string;
  mount: string;
  path: string;
  key: string;
  container: string;
  opened_with: string | null;
  alias: string | null;
  subject: string;
  subject_cn: string;
  issuer_cn: string;
  not_before: string;
  not_after: string;
  days_left: number;
  status: "valid" | "expiring" | "expired" | "not_yet_valid";
  is_ca: boolean;
  self_signed: boolean;
  serial: string;
  sha256: string;
}

export interface ExpiryResult {
  certificates: CertRow[];
  locked: { side: "left" | "right"; path: string; key: string; container: string; reason: string }[];
  sides: { side: "left" | "right"; mount: string; prefix: string; secrets: number; values: number;
           denied: string[]; truncated: boolean; unreadable: number }[];
}

export interface ProfileRules {
  mappings: { left: string; right: string }[];
  ignore_paths: string[];
  ignore_keys: { key: string; path: string }[];
}

export interface Profile {
  name: string;
  description: string;
  left_mount?: string | null;
  left_prefix?: string | null;
  right_mount?: string | null;
  right_prefix?: string | null;
  rules: ProfileRules;
}

// ---- Saved sync plans (signed files, no values)

export interface PlanVault {
  vault: string;
  preset: boolean;
  namespace: string | null;
  mount: string;
  prefix: string;
  identity: string;
}

export interface PlanChange {
  path: string;
  right_path: string;
  direction: SyncDirection;
  source_path: string;
  target_path: string;
  source_version: number;
  target_version: number | null;
  keys: { key: string; action: "add" | "update" | "remove"; override?: boolean }[];
  set?: Record<string, unknown> | null; // typed values, for keys marked override
}

export interface SyncPlan {
  format: "lockstep.sync-plan";
  version: 1;
  id: string;
  created_at: string;
  note: string;
  profile: string | null;
  left: PlanVault;
  right: PlanVault;
  changes: PlanChange[];
  holds_values?: boolean; // some changes carry typed values
  signature: string;
}

export type PlanCheckStatus = "ready" | "stale" | "denied" | "error";

export interface PlanCheck {
  status: PlanCheckStatus;
  message: string;
  changes: { path: string; right_path: string; direction: SyncDirection; source: string; target: string;
             status: PlanCheckStatus; problems: string[] }[];
}

export interface PlanApplyResult extends ApplyResult {
  plan_id: string;
}

// ---- Secret-engine exports (files with values) and imports

export interface ExportSecret {
  path: string;
  version: number | null;
  updated: string | null;
  data?: Record<string, unknown> | null;
  /** A keep entry (no data): the target's secret is left as it is, never written or deleted. */
  keep?: boolean;
}

export interface ExportSkipped {
  ignored_paths: number;
  ignored_keys: number;
  unreadable: string[];
  deleted: string[];
  denied_folders: string[];
  truncated: boolean;
}

export interface ExportDoc {
  $schema?: string | null;
  format: "lockstep.secret-export";
  version: 1;
  created_at: string;
  tool: string;
  source: { vault: string; url: string | null; namespace: string | null; mount: string; prefix: string; identity: string };
  rules: { ignore_paths: string[]; ignore_keys: { key: string; path: string }[] };
  secrets: ExportSecret[];
  skipped: ExportSkipped;
}

/** An export opened in this page (memory only, never stored). */
export interface LoadedFile {
  id: string;
  name: string;
  encrypted: boolean;
  doc: ExportDoc;
}

export interface ExportResult {
  filename: string;
  file: Record<string, unknown>;
  key: string | null;
  secrets: number;
  keys: number;
  skipped: ExportSkipped;
}

export type TransformOp = "replace" | "prefix" | "suffix" | "upper" | "lower";

export interface Transform {
  op: TransformOp;
  target: "values" | "keys" | "paths";
  find: string;
  with: string;
  path: string;
  key: string;
}

export interface ImportRules {
  $schema?: string;
  ignore_paths: string[];
  ignore_keys: { key: string; path: string }[];
  transforms: Transform[];
}

export interface ImportPreview {
  prepared: {
    secrets: number; ignored_paths: number; ignored_keys: number;
    paths_changed: number; keys_changed: number; values_changed: number; kept: number;
    problems: { path: string; message: string }[];
  };
  plans: ChangePlan[];
  warnings: string[];
}

// --------------------------------------------------------------------------- policies

export type PolicyColumn = "names" | "read" | "write" | "delete" | "destroy" | "history";

export interface PolicyCell {
  ok: boolean;
  rule: number | null; // index into ExplainResult.rules
  deny: boolean; // decided by a deny rule
  caps: string[];
}

export interface PolicyRuleSource { policy: string; path: string; line: number | null; capabilities: string[] }

export interface PolicyRule {
  key: string;
  kind: "exact" | "prefix" | "segment";
  capabilities: string[];
  sources: PolicyRuleSource[];
}

export interface PolicyFinding {
  level: "error" | "warn" | "info";
  message: string;
  policy: string | null;
  path: string | null;
  line: number | null;
}

export interface ExplainResult {
  mount: string;
  prefix: string;
  policies: { name: string; origin: "vault" | "pasted" | "token" | "identity"; rules: number; error: string | null }[];
  identity?: { label: string; sources: { from: string; policies: string[]; note?: string }[] } | null;
  missing: string[];
  complete: boolean;
  mode: "policies" | "vault";
  root: boolean;
  vault_version?: string | null;
  evaluation?: string;
  columns: { id: PolicyColumn; label: string }[];
  rules: PolicyRule[];
  rows: { path: string; cells: Record<PolicyColumn, PolicyCell> }[];
  findings: PolicyFinding[];
  denied: string[];
  truncated: boolean;
}

export interface PolicyProfile {
  name: string;
  description?: string;
  mappings: { left: string; right: string }[];
  rewrites: { find: string; replace: string }[];
  ignore: string[];
}

export type PolicyPairStatus = "equal" | "different" | "left_only" | "right_only" | "error";

export interface PolicyRuleDiff {
  path: string;
  left: string[] | null;
  right: string[] | null;
  left_extra: Record<string, unknown> | null;
  right_extra: Record<string, unknown> | null;
  change: "same" | "changed" | "left_only" | "right_only";
}

export interface PolicyPair {
  left: string | null;
  right: string | null;
  status: PolicyPairStatus;
  mapped: boolean;
  formatting: boolean;
  note: string;
  rules: PolicyRuleDiff[];
  left_text: string | null;
  right_text: string | null;
}

export interface PolicyCompareResult {
  left: { count: number; error: string | null };
  right: { count: number; error: string | null };
  pairs: PolicyPair[];
  summary: Record<PolicyPairStatus, number>;
  missing: string[];
}

export interface AccessCompareResult {
  columns: { id: PolicyColumn; label: string }[];
  rows: { path: string; left: Record<PolicyColumn, { ok: boolean; deny: boolean }> | null;
          right: Record<PolicyColumn, { ok: boolean; deny: boolean }> | null; differs: boolean }[];
  left: { mount: string; prefix: string; missing: string[]; denied: string[]; truncated: boolean };
  right: { mount: string; prefix: string; missing: string[]; denied: string[]; truncated: boolean };
}

// --------------------------------------------------------------------------- browse

export interface BrowseEntry {
  name: string;
  path: string; // inside the mount
  folder: boolean;
  caps: { list?: boolean | null; read?: boolean | null; write?: boolean | null; history?: boolean | null };
}

export interface BrowseList {
  mount: string;
  folder: string;
  total: number;
  offset: number;
  entries: BrowseEntry[];
  denied: boolean;
}

export interface BrowseVersion { version: number; created: string | null; deleted: boolean; destroyed: boolean; by?: string | null; deleted_by?: string | null }

export interface BrowseSecret {
  path: string;
  mount: string;
  state: "present" | "deleted" | "destroyed" | "absent";
  version: number | null;
  current_version: number | null;
  updated: string | null;
  keys: string[] | null;
  keys_only?: boolean; // names from subkeys/: the values can't be read
  read_error: string | null;
  metadata: { max_versions: number; cas_required: boolean; delete_version_after: string;
              custom_metadata: Record<string, string> | null; created_time: string; updated_time: string;
              oldest_version: number; updated_by?: string | null; hash: string } | null;
  metadata_error: string | null;
  versions: BrowseVersion[];
  caps: Record<"read" | "write" | "patch" | "delete" | "delete_versions" | "undelete" | "destroy_versions" | "destroy" | "history",
               boolean | null>;
}

export interface BrowseEdit {
  path: string;
  action: "write" | "delete" | "undelete" | "destroy" | "rollback";
  expected_version?: number | null;
  set?: Record<string, unknown>;
  remove?: string[];
  versions?: number[];
  rollback_to?: number;
}

export interface BrowseEditResult {
  path: string;
  action: string;
  status: "ready" | "noop" | "conflict" | "invalid" | "error" | "applied" | "denied";
  old_version: number | null;
  new_version: number | null;
  versions: number[];
  keys: { key: string; action: "add" | "update" | "remove" | "unchanged"; old: unknown; new: unknown }[];
  message: string;
  patch?: boolean;
}

export interface BrowseDiff {
  a: number;
  b: number;
  keys: { key: string; change: "added" | "removed" | "changed" | "same"; a?: unknown; b?: unknown }[];
}

export type PolicyCan = "names" | "read" | "write" | "delete" | "destroy" | "history";
export interface PolicyBuildRule { where: string; can: PolicyCan[] }

export interface PolicyDraft {
  name: string;
  mount: string;
  rules: PolicyBuildRule[];
  hcl?: string; // set in Advanced mode: the text is used as it is
  description?: string;
}

export interface SuggestResult {
  layout: string;
  why: string[];
  notes: string[];
  secrets: number;
  truncated: boolean;
  suggestions: { name: string; description: string; rules: PolicyBuildRule[]; hcl: string; template: string }[];
  profile: PolicyProfile | null;
  pattern_yaml: string;
}

export interface TerraformOptions { tool: "terraform" | "opentofu"; provider: "~> 5.0" | "~> 4.0"; layout: "single" | "files"; imports: boolean }

// --------------------------------------------------------------------------- auth roles

export type RoleKind = "kubernetes" | "jwt" | "approle";
export interface RoleFinding { level: "error" | "warn" | "info"; message: string; field: string | null }
export interface AuthMount { path: string; type: string; kind: RoleKind; description: string }
export interface RoleItem { name: string; role?: Record<string, unknown>; policies?: string[]; findings?: RoleFinding[]; error?: string }
export interface RolesList { mount: string; kind: RoleKind; labels: Record<string, string>; roles: RoleItem[]; policies_known: boolean }
export interface RoleTemplate { id: string; kind: RoleKind; label: string; body: Record<string, unknown> }
export interface RoleDraft { kind: RoleKind; mount: string; name: string; body: Record<string, unknown> }
export interface RolePair {
  left: string | null; right: string | null; mapped: boolean; status: "equal" | "different" | "left_only" | "right_only";
  fields: { field: string; label: string; left: unknown; right: unknown }[]; note: string;
}

export interface AccessItem {
  id: string;
  kind: "policy" | "role";
  name: string;
  action: "new" | "change" | "same" | "delete" | "absent";
  hash: string | null;
  diff: string;
  allowed: boolean | null;
  status: "ready" | "noop" | "denied" | "invalid" | "conflict" | "applied" | "error";
  problems: string[];
  warnings: string[];
}
export interface AccessChanges {
  conn_id: string;
  policies?: { name: string; text: string }[];
  roles?: RoleDraft[];
  delete_policies?: string[];
  delete_roles?: { mount: string; name: string }[];
}

export interface AccessPlanInfo {
  format: string; version: number; id: string; created: string; created_by: string;
  vault: string; preset: boolean; namespace: string | null; items: { id: string; action: string; status: string }[];
}

export interface VaultOverview {
  version: string | null; cluster_name: string | null; sealed: boolean | null; seal_type: string | null;
  storage_type: string | null; ha_enabled: boolean | null; performance_standby: boolean | null;
  replication: Record<string, string> | null;
}
export interface ConfigPair {
  path: string; type: string | null; system: boolean; status: "equal" | "different" | "left_only" | "right_only";
  fields: { field: string; left: unknown; right: unknown }[]; left: Record<string, unknown> | null; right: Record<string, unknown> | null;
}
export interface ConfigCompare {
  overview: { left: VaultOverview; right: VaultOverview };
  mounts: ConfigPair[]; auth: ConfigPair[]; engines: ConfigPair[]; summary: Record<string, number>;
  missing: { left: string[]; right: string[] };
}

export interface MfaConstraint { name: string; methods: { id: string; type: string; uses_passcode: boolean; name: string }[] }
export interface MfaChallenge { mfa_required: true; constraints: MfaConstraint[] }
