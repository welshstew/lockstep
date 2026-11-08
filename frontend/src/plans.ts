import { api } from "./api";
import type { SyncPlan } from "./types";

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

export const vaultLabel = (v: SyncPlan["left"]) => v.vault + (v.namespace ? ` (namespace ${v.namespace})` : "");
