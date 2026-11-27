import { api } from "./api";
import type { ChangeResult, SyncPlan, UndoPlan } from "./types";

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

/** Make an undo plan for what these results wrote, and download it. Returns the file name. */
export async function downloadUndoPlan(results: ChangeResult[], undoes?: string): Promise<string> {
  const writes = results.filter((r) => r.status === "applied" && r.target_conn_id && r.target_mount && r.target_path)
    .map((r) => ({ conn_id: r.target_conn_id!, mount: r.target_mount!, path: r.target_path!, action: r.action ?? "write",
                   old_version: r.old_version, new_version: r.new_version }));
  const plan: UndoPlan = await api.undoCreate(writes, undoes);
  const name = `lockstep-undo-${plan.created_at.slice(0, 10)}-${plan.id.slice(0, 8)}.json`;
  saveFile(JSON.stringify(plan, null, 2) + "\n", name, "application/json");
  return name;
}

export const vaultLabel = (v: SyncPlan["left"]) => v.vault + (v.namespace ? ` (namespace ${v.namespace})` : "");
