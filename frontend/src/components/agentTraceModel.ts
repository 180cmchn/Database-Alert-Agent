import type { AgentTraceEntry } from "../types/api";

export function advanceTraceSequence(current: number, received: number): number {
  return Math.max(current, received);
}

export function mergeAgentTraceItems(
  current: AgentTraceEntry[],
  incoming: AgentTraceEntry[],
): AgentTraceEntry[] {
  const itemsById = new Map(current.map((item) => [item.event_id, item]));
  const reasoningByStream = new Map<string, AgentTraceEntry>();
  current.forEach((item) => {
    if (item.kind === "REASONING" && item.stream_id !== null && item.delta_index !== null) {
      reasoningByStream.set(`${item.scope}:${item.stream_id}`, item);
    }
  });

  [...incoming]
    .sort((left, right) => left.sequence - right.sequence)
    .forEach((item) => {
      if (itemsById.has(item.event_id)) return;
      if (item.kind !== "REASONING" || item.stream_id === null || item.delta_index === null) {
        itemsById.set(item.event_id, item);
        return;
      }

      const streamKey = `${item.scope}:${item.stream_id}`;
      const accumulated = reasoningByStream.get(streamKey);
      if (accumulated === undefined) {
        itemsById.set(item.event_id, item);
        reasoningByStream.set(streamKey, item);
        return;
      }
      if (accumulated.delta_index !== null && item.delta_index <= accumulated.delta_index) return;

      const merged = {
        ...accumulated,
        content: accumulated.content + item.content,
        delta_index: item.delta_index,
        occurred_at: item.occurred_at,
      };
      itemsById.set(accumulated.event_id, merged);
      reasoningByStream.set(streamKey, merged);
    });
  return [...itemsById.values()].sort((left, right) => left.sequence - right.sequence);
}

export function shouldShowReasoningFallback(
  items: AgentTraceEntry[],
  active: boolean,
): boolean {
  if (!active) return false;
  const latestObservationSequence = items.reduce(
    (latest, item) => item.scope === "main_agent" && item.kind === "OBSERVATION"
      ? Math.max(latest, item.sequence)
      : latest,
    0,
  );
  return !items.some(
    (item) => item.scope === "main_agent"
      && item.kind === "REASONING"
      && item.sequence > latestObservationSequence,
  );
}

export interface TraceVisibilityFlags {
  hideMainAgent: boolean;
  hideMcp: boolean;
}

export const INITIAL_TRACE_VISIBILITY: TraceVisibilityFlags = {
  hideMainAgent: true,
  hideMcp: true,
};

export function resolveTraceVisibility(
  flags: TraceVisibilityFlags,
): TraceVisibilityFlags {
  // Hiding the main Agent chain always forces the MCP chain to hide as well,
  // while the MCP chain may be hidden on its own.
  return flags.hideMainAgent
    ? { hideMainAgent: true, hideMcp: true }
    : { hideMainAgent: false, hideMcp: flags.hideMcp };
}

export function filterAgentTraceItems(
  items: AgentTraceEntry[],
  flags: TraceVisibilityFlags,
): AgentTraceEntry[] {
  const resolved = resolveTraceVisibility(flags);
  if (resolved.hideMainAgent) return [];
  if (resolved.hideMcp) {
    return items.filter((item) => item.scope !== "mcp_internal");
  }
  return items;
}

export function countMcpTraceItems(items: AgentTraceEntry[]): number {
  return items.reduce(
    (count, item) => (item.scope === "mcp_internal" ? count + 1 : count),
    0,
  );
}
