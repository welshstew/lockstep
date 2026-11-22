import { api } from "./api";
import type { AccessChanges } from "./types";

/** Save changes as a signed access plan file, for someone with the rights to apply. */
export async function saveAccessPlan(changes: AccessChanges): Promise<string> {
  const plan = await api.accessPlanCreate(changes);
  const url = URL.createObjectURL(new Blob([JSON.stringify(plan, null, 2) + "\n"], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url; a.download = `lockstep-access-plan-${plan.id}.json`; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  return plan.id;
}
