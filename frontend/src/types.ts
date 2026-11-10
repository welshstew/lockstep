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
  action: "add" | "update" | "unchanged";
  type_change: boolean;
  override: boolean;
  source_value: unknown;
  target_value: unknown;
}

export type PlanStatus = "ready" | "noop" | "conflict" | "denied" | "invalid" | "error";

export interface ChangePlan {
  path: string;
  direction: SyncDirection;
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
  target: string;
  status: ResultStatus;
  overridden: string[];
  old_version: number | null;
  new_version: number | null;
  keys: string[];
  message: string;
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
  keys: { key: string; action: "add" | "update" }[];
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
  data: Record<string, unknown>;
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
    paths_changed: number; keys_changed: number; values_changed: number;
    problems: { path: string; message: string }[];
  };
  plans: ChangePlan[];
}
