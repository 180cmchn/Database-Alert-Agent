import type {
  InvestigationRun,
  KnowledgeExcerpt,
  ProgressRecord,
  Recommendation,
} from "../types/api";

export type KnowledgeCardState =
  | "not_configured"
  | "matching"
  | "no_match"
  | "matched"
  | "unavailable_history";

export interface KnowledgeCardModel {
  state: KnowledgeCardState;
  sources: string[];
  matches: KnowledgeExcerpt[];
  summary: string;
  headline: string;
  description: string;
}

interface KnowledgeCardInput {
  run: InvestigationRun | null | undefined;
  recommendation: Recommendation | null | undefined;
  progress: ProgressRecord[];
  resultAvailable: boolean;
}

function progressKnowledgeSummary(progress: ProgressRecord[]): string {
  for (let index = progress.length - 1; index >= 0; index -= 1) {
    const summary = progress[index]?.details.knowledge_match_summary;
    if (typeof summary === "string" && summary.trim()) return summary.trim();
  }
  return "";
}

function progressKnowledgeCount(progress: ProgressRecord[]): number | null {
  for (let index = progress.length - 1; index >= 0; index -= 1) {
    const count = progress[index]?.details.knowledge_match_count;
    if (typeof count === "number" && Number.isFinite(count) && count >= 0) return count;
  }
  return null;
}

export function buildKnowledgeCardModel({
  run,
  recommendation,
  progress,
  resultAvailable,
}: KnowledgeCardInput): KnowledgeCardModel {
  const sources = run?.config_snapshot?.knowledge_sources ?? [];
  const matches = recommendation?.knowledge_matches ?? [];
  const summary = recommendation?.knowledge_match_summary?.trim()
    || progressKnowledgeSummary(progress);

  if (run && run.status !== "RUNNING" && !resultAvailable) {
    return {
      state: "unavailable_history",
      sources,
      matches: [],
      summary: "",
      headline: "历史知识匹配结果不可恢复",
      description: "该次运行发生在运行级结果开始保存之前，无法还原当时的知识匹配内容。",
    };
  }

  if (matches.length > 0) {
    return {
      state: "matched",
      sources,
      matches,
      summary,
      headline: `命中 ${matches.length} 条知识`,
      description: "知识结果提供机制和处置参考，但不能单独证明本次事故根因。",
    };
  }

  if (run?.config_snapshot && sources.length === 0) {
    return {
      state: "not_configured",
      sources,
      matches: [],
      summary,
      headline: "未配置知识来源",
      description: "本次运行未选择知识来源，不影响 Agent 继续依据告警与实时证据分析。",
    };
  }

  const completedMatchCount = progressKnowledgeCount(progress);
  if (run?.status === "RUNNING" && recommendation == null && completedMatchCount !== 0) {
    return {
      state: "matching",
      sources,
      matches: [],
      summary,
      headline: "正在匹配知识",
      description: "正在并行检索本次运行选择的知识来源；检索失败不会阻断 Agent 排查。",
    };
  }

  return {
    state: "no_match",
    sources,
    matches: [],
    summary,
    headline: "未匹配到符合条件的知识",
    description: "已配置的知识来源未返回达到匹配条件的结果，Agent 仍会继续分析实时证据。",
  };
}