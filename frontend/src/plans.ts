import { api } from "./api";
import type { BrowseEditResult, ChangeResult, SyncPlan, UndoPlan } from "./types";

type UndoWrite = { conn_id: string; mount: string; path: string; action: "write" | "delete"; old_version: number | null; new_version: number | null };

export const planFileName = (p: SyncPlan, ext: "json" | "md") =>
  `lockstep-plan-${p.created_at.slice(0, 10)}-${p.id.slice(0, 8)}.${ext}`;

export function saveFile(text: string, name: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function downloadPlan(p: SyncPlan) {
  saveFile(JSON.stringify(p, null, 2) + "\n", planFileName(p, "json"), "application/json");
}

export async function downloadReport(p: SyncPlan) {
  saveFile(await api.planReport(p), planFileName(p, "md"), "text/markdown");
}

/** Make an undo plan for what these results (copies, a plan, an import) wrote, and download it.
 * Returns the file name. */
export async function downloadUndoPlan(results: ChangeResult[], undoes?: string): Promise<string> {
  return downloadUndo(results.filter((r) => r.status === "applied" && r.target_conn_id && r.target_mount && r.target_path)
    .map((r) => ({ conn_id: r.target_conn_id!, mount: r.target_mount!, path: r.target_path!, action: r.action ?? "write",
                   old_version: r.old_version, new_version: r.new_version })), undoes);
}

/** What an undo plan can put back from Browse edits: writes and rollbacks (the old version, or a
 * soft-delete if the edit created the secret), and a soft-delete of the latest version
 * (undeleted). Undeletes, destroys and deletes of older versions can't be undone this way. */
export function browseUndoWrites(connId: string, mount: string, results: BrowseEditResult[]): UndoWrite[] {
  return results.flatMap((r): UndoWrite[] => {
    if (r.status !== "applied") return [];
    if ((r.action === "write" || r.action === "rollback") && r.new_version)
      return [{ conn_id: connId, mount, path: r.path, action: "write", old_version: r.old_version, new_version: r.new_version }];
    if (r.action === "delete" && r.old_version && r.versions.length === 1 && r.versions[0] === r.old_version)
      return [{ conn_id: connId, mount, path: r.path, action: "delete", old_version: r.old_version, new_version: null }];
    return [];
  });
}

export async function downloadUndo(writes: UndoWrite[], undoes?: string): Promise<string> {
  const plan: UndoPlan = await api.undoCreate(writes, undoes);
  const name = `lockstep-undo-${plan.created_at.slice(0, 10)}-${plan.id.slice(0, 8)}.json`;
  saveFile(JSON.stringify(plan, null, 2) + "\n", name, "application/json");
  return name;
}

export const vaultLabel = (v: SyncPlan["left"]) => v.vault + (v.namespace ? ` (namespace ${v.namespace})` : "");

/** What a plan still needs before this server applies it, as a sentence (for the approvals notice). */
export function approvalsNeeded(ap: { required: number; approved_by: string[]; approver_policies?: string[] }): string {
  const left = ap.required - ap.approved_by.length;
  if (left <= 0) return "";
  const who = ap.required === 1 ? "someone other than its creator has" : `${ap.required} different people other than its creator have`;
  const pols = ap.approver_policies?.length ? ` Approvers need one of the Vault policies ${ap.approver_policies.join(", ")}.` : "";
  const more = ap.required > 1 && ap.approved_by.length ? ` ${left} more to go.` : "";
  return `This Lockstep server applies it only once ${who} checked it and chosen Approve.${more}${pols} `;
}
