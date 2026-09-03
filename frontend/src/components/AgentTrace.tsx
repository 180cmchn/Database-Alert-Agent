import { BrainCircuit, Eye, EyeOff, LoaderCircle, Radio, TerminalSquare } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../lib/api";
import { formatDateTime } from "../lib/format";
import type { AgentTraceEntry, AgentTraceKind } from "../types/api";
import {
  advanceTraceSequence,
  countMcpTraceItems,
  filterAgentTraceItems,
  INITIAL_TRACE_VISIBILITY,
  mergeAgentTraceItems,
  resolveTraceVisibility,
  shouldShowReasoningFallback,
  type TraceVisibilityFlags,
} from "./agentTraceModel";
import { SectionCard } from "./ui";

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
  const [visibility, setVisibility] = useState<TraceVisibilityFlags>(() => ({
    ...INITIAL_TRACE_VISIBILITY,
  }));
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

  const resolvedVisibility = resolveTraceVisibility(visibility);
  const visibleItems = useMemo(
    () => filterAgentTraceItems(items, visibility),
    [items, visibility],
  );
  const mcpItemCount = useMemo(() => countMcpTraceItems(items), [items]);
  const showReasoningFallback = !resolvedVisibility.hideMainAgent
    && shouldShowReasoningFallback(visibleItems, active);

  return (
    <SectionCard
      className="agent-trace-card"
      eyebrow="AGENT TRACE"
      title="实时思考与调用轨迹"
      description="按实际发生顺序追加展示模型返回、工具动作与观察结果"
      action={(
        <div className="trace-card-actions">
          {active && (
            <span className="live-trace-indicator">
              <Radio size={13} className="pulse" /> LIVE
            </span>
          )}
          <div className="trace-visibility-toolbar" role="group" aria-label="思考链折叠设置">
            <label
              className={`trace-visibility-toggle${resolvedVisibility.hideMcp ? " on" : ""}${resolvedVisibility.hideMainAgent ? " locked" : ""}`}
              title={resolvedVisibility.hideMainAgent
                ? "主 Agent 思考链折叠期间，MCP 思考链会一并折叠"
                : undefined}
            >
              <input
                type="checkbox"
                checked={resolvedVisibility.hideMcp}
                disabled={resolvedVisibility.hideMainAgent}
                onChange={() => setVisibility((current) => ({ ...current, hideMcp: !current.hideMcp }))}
              />
              {resolvedVisibility.hideMcp ? <EyeOff size={13} /> : <Eye size={13} />}
              <span>折叠 MCP 思考链</span>
            </label>
            <label className={`trace-visibility-toggle${resolvedVisibility.hideMainAgent ? " on" : ""}`}>
              <input
                type="checkbox"
                checked={visibility.hideMainAgent}
                onChange={() => setVisibility((current) => ({
                  ...current,
                  hideMainAgent: !current.hideMainAgent,
                }))}
              />
              {resolvedVisibility.hideMainAgent ? <EyeOff size={13} /> : <Eye size={13} />}
              <span>折叠主 Agent 思考链</span>
            </label>
          </div>
        </div>
      )}
    >
      <div className="agent-trace" aria-live="polite">
        {showReasoningFallback && (
          <div className="trace-reasoning-fallback">
            <LoaderCircle size={16} className="spin" />
            <span>当前暂时无法显示思维链，但仍在分析中</span>
          </div>
        )}
        {resolvedVisibility.hideMainAgent ? (
          <div className="trace-hidden-notice">
            <EyeOff size={16} />
            <span>主 Agent 与 MCP 思考链均已折叠，展开主 Agent 思考链后可查看完整轨迹。</span>
          </div>
        ) : (
          <>
            {resolvedVisibility.hideMcp && mcpItemCount > 0 && (
              <p className="trace-hidden-notice-inline">
                已折叠 {mcpItemCount} 条 MCP 内部思考轨迹，主 Agent 轨迹仍正常展示。
              </p>
            )}
            {visibleItems.length ? (
              <ol className="agent-trace-list">
                {visibleItems.map((item) => (
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
          </>
        )}
        {error && <p className="trace-load-error">轨迹更新失败：{error}</p>}
      </div>
    </SectionCard>
  );
}
