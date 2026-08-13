import assert from "node:assert/strict";
import test from "node:test";
import type { AgentTraceEntry, AgentTraceKind } from "../src/types/api.ts";
import {
  advanceTraceSequence,
  mergeAgentTraceItems,
  shouldShowReasoningFallback,
} from "../src/components/agentTraceModel.ts";
import {
  canRequestRunCancellation,
  isRunCancellationPending,
  shouldPollAlertDetail,
} from "../src/lib/investigationRun.ts";

function traceEntry(
  eventId: string,
  sequence: number,
  kind: AgentTraceKind,
  scope: AgentTraceEntry["scope"] = "main_agent",
): AgentTraceEntry {
  return {
    event_id: eventId,
    run_id: "run-1",
    sequence,
    kind,
    scope,
    actor: "main-agent",
    provider: "test-provider",
    content: `${kind}-${sequence}`,
    occurred_at: "2026-08-13T08:00:00Z",
  };
}

function reasoningDelta(
  eventId: string,
  sequence: number,
  content: string,
  deltaIndex: number,
  scope: AgentTraceEntry["scope"] = "main_agent",
): AgentTraceEntry {
  return {
    ...traceEntry(eventId, sequence, "REASONING", scope),
    content,
    stream_id: "decision:1",
    delta_index: deltaIndex,
  };
}

test("trace cursor only advances", () => {
  assert.equal(advanceTraceSequence(7, 11), 11);
  assert.equal(advanceTraceSequence(11, 7), 11);
});

test("incremental trace items are deduplicated and ordered", () => {
  const current = [traceEntry("event-2", 2, "ACTION")];
  const merged = mergeAgentTraceItems(current, [
    traceEntry("event-3", 3, "OBSERVATION"),
    traceEntry("event-1", 1, "REASONING"),
    traceEntry("event-2", 2, "ACTION"),
    traceEntry("event-3", 3, "OBSERVATION"),
  ]);

  assert.deepEqual(merged.map((item) => item.event_id), ["event-1", "event-2", "event-3"]);
  assert.deepEqual(merged.map((item) => item.kind), ["REASONING", "ACTION", "OBSERVATION"]);
});

test("streamed reasoning deltas are rendered as one continuous thought", () => {
  const firstPage = mergeAgentTraceItems([], [
    reasoningDelta("delta-1", 1, "正在检查", 0),
    reasoningDelta("delta-2", 2, "慢查询", 1),
  ]);
  const secondPage = mergeAgentTraceItems(firstPage, [
    reasoningDelta("delta-2", 2, "慢查询", 1),
    reasoningDelta("delta-3", 3, "证据。", 2),
    traceEntry("action-1", 4, "ACTION"),
  ]);

  assert.equal(secondPage.length, 2);
  assert.equal(secondPage[0]?.event_id, "delta-1");
  assert.equal(secondPage[0]?.content, "正在检查慢查询证据。");
  assert.equal(secondPage[0]?.delta_index, 2);
  assert.equal(secondPage[1]?.kind, "ACTION");
});

test("active traces without model reasoning show the required fallback", () => {
  const actionAndObservation = [
    traceEntry("event-1", 1, "ACTION"),
    traceEntry("event-2", 2, "OBSERVATION"),
  ];

  assert.equal(shouldShowReasoningFallback([], true), true);
  assert.equal(shouldShowReasoningFallback(actionAndObservation, true), true);
  assert.equal(
    shouldShowReasoningFallback(
      [...actionAndObservation, traceEntry("event-3", 3, "REASONING")],
      true,
    ),
    false,
  );
  assert.equal(shouldShowReasoningFallback([], false), false);
});

test("reasoning fallback is evaluated again after each observation", () => {
  const firstRound = [
    traceEntry("reasoning-1", 1, "REASONING"),
    traceEntry("action-1", 2, "ACTION"),
    traceEntry("observation-1", 3, "OBSERVATION"),
  ];

  assert.equal(shouldShowReasoningFallback(firstRound, true), true);
  assert.equal(
    shouldShowReasoningFallback(
      [...firstRound, traceEntry("action-2", 4, "ACTION")],
      true,
    ),
    true,
  );
  assert.equal(
    shouldShowReasoningFallback(
      [...firstRound, traceEntry("reasoning-2", 4, "REASONING")],
      true,
    ),
    false,
  );
});

test("MCP internal reasoning never suppresses the missing main-Agent reasoning fallback", () => {
  const internalTrace = [
    traceEntry("internal-reasoning", 1, "REASONING", "mcp_internal"),
    traceEntry("internal-action", 2, "ACTION", "mcp_internal"),
    traceEntry("internal-observation", 3, "OBSERVATION", "mcp_internal"),
  ];

  assert.equal(shouldShowReasoningFallback(internalTrace, true), true);
  assert.equal(
    shouldShowReasoningFallback(
      [...internalTrace, traceEntry("main-reasoning", 4, "REASONING")],
      true,
    ),
    false,
  );
});

test("reasoning streams with the same id remain isolated by scope", () => {
  const merged = mergeAgentTraceItems([], [
    reasoningDelta("main-delta", 1, "主 Agent", 0),
    reasoningDelta("mcp-delta", 2, "MCP Agent", 0, "mcp_internal"),
  ]);

  assert.deepEqual(merged.map((item) => item.content), ["主 Agent", "MCP Agent"]);
  assert.deepEqual(merged.map((item) => item.scope), ["main_agent", "mcp_internal"]);
});

test("a submitted cancellation cannot be requested twice", () => {
  const activeRun = { status: "RUNNING" as const, cancel_requested_at: null };
  const cancellingRun = {
    status: "RUNNING" as const,
    cancel_requested_at: "2026-08-13T08:00:00Z",
  };
  const completedRun = { status: "COMPLETED" as const, cancel_requested_at: null };

  assert.equal(canRequestRunCancellation(activeRun), true);
  assert.equal(isRunCancellationPending(activeRun), false);
  assert.equal(canRequestRunCancellation(cancellingRun), false);
  assert.equal(isRunCancellationPending(cancellingRun), true);
  assert.equal(canRequestRunCancellation(completedRun), false);
  assert.equal(isRunCancellationPending(completedRun), false);
});

test("a running latest run keeps historical alert detail views refreshing", () => {
  const completedRun = { status: "COMPLETED" as const };
  const runningRun = { status: "RUNNING" as const };
  const cancelledRun = { status: "CANCELLED" as const };

  assert.equal(shouldPollAlertDetail(completedRun, runningRun), true);
  assert.equal(shouldPollAlertDetail(completedRun, cancelledRun), false);
  assert.equal(shouldPollAlertDetail(runningRun, runningRun), true);
});
