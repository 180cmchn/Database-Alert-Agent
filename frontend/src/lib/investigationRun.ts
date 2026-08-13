import type { InvestigationRun } from "../types/api";

type CancellableRun = Pick<InvestigationRun, "status" | "cancel_requested_at">;
type TrackableRun = Pick<InvestigationRun, "status">;

export function isRunCancellationPending(run: CancellableRun | null | undefined): boolean {
  return run?.status === "RUNNING" && Boolean(run.cancel_requested_at);
}

export function canRequestRunCancellation(run: CancellableRun | null | undefined): boolean {
  return run?.status === "RUNNING" && !run.cancel_requested_at;
}

export function shouldPollAlertDetail(
  selectedRun: TrackableRun | null | undefined,
  latestRun: TrackableRun | null | undefined,
): boolean {
  return selectedRun?.status === "RUNNING" || latestRun?.status === "RUNNING";
}
