import { BrainCircuit, Eye, LoaderCircle, TerminalSquare } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import { formatDateTime } from "../lib/format";
import type { AgentTraceEntry, AgentTraceKind } from "../types/api";
import {
  advanceTraceSequence,
  mergeAgentTraceItems,
  shouldShowReasoningFallback,
} from "./agentTraceModel";

const kindLabel: Record<AgentTraceKind, string> = {
  REASONING: "REASONING",
  ACTION: "ACTION",
  OBSERVATION: "OBSERVATION",
};

const scopeLabel: Record<AgentTraceEntry["scope"], string> = {
  main_agent: "主 Agent ReAct",
  mcp_internal: "MCP 内部调查",
};

function TraceIcon({ kind }: { kind: AgentTraceKind }) {
  if (kind === "REASONING") return <BrainCircuit size={16} />;
  if (kind === "ACTION") return <TerminalSquare size={16} />;
  return <Eye size={16} />;
}

interface AgentTraceProps {
  alertId: string;
  runId: string;
  active: boolean;
}

export function AgentTrace({ alertId, runId, active }: AgentTraceProps) {
  const [items, setItems] = useState<AgentTraceEntry[]>([]);
  const [error, setError] = useState("");
  const nextSequence = useRef(0);

  useEffect(() => {
    nextSequence.current = 0;
    setItems([]);
    setError("");
  }, [alertId, runId]);

  useEffect(() => {
    let disposed = false;
    let timer: number | undefined;

    async function loadNext() {
      let hasMore = false;
      try {
        const response = await api.getAgentTrace(alertId, runId, nextSequence.current);
        if (disposed) return;
        hasMore = response.has_more;
        nextSequence.current = advanceTraceSequence(nextSequence.current, response.next_sequence);
        if (response.items.length) {
          setItems((current) => mergeAgentTraceItems(current, response.items));
        }
        setError("");
      } catch (requestError) {
        if (!disposed) {
          setError(requestError instanceof Error ? requestError.message : "实时轨迹加载失败");
        }
      } finally {
        if (!disposed && (active || hasMore)) {
          timer = window.setTimeout(() => void loadNext(), hasMore ? 0 : 1_000);
        }
      }
    }

    void loadNext();
    return () => {
      disposed = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [active, alertId, runId]);

  const showReasoningFallback = shouldShowReasoningFallback(items, active);

  return (
    <div className="agent-trace" aria-live="polite">
      {showReasoningFallback && (
        <div className="trace-reasoning-fallback">
          <LoaderCircle size={16} className="spin" />
          <span>当前暂时无法显示思维链，但仍在分析中</span>
        </div>
      )}
      {items.length ? (
        <ol className="agent-trace-list">
          {items.map((item) => (
            <li
              key={item.event_id}
              className={`trace-${item.kind.toLowerCase()} trace-scope-${item.scope}`}
            >
              <span className="trace-icon"><TraceIcon kind={item.kind} /></span>
              <div>
                <header>
                  <strong>{kindLabel[item.kind]}</strong>
                  <span className={`trace-scope-label scope-${item.scope}`}>
                    {scopeLabel[item.scope]}
                  </span>
                  <span>{item.actor} · {item.provider}</span>
                  <time>{formatDateTime(item.occurred_at)}</time>
                </header>
                <pre>{item.content}</pre>
              </div>
            </li>
          ))}
        </ol>
      ) : !active ? (
        <p className="muted-copy">本次运行没有可展示的 Agent 实时事件。</p>
      ) : null}
      {error && <p className="trace-load-error">轨迹更新失败：{error}</p>}
    </div>
  );
}
