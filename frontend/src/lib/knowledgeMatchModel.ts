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
  | "unavailable"
  | "unavailable_history";

export type KnowledgeSourceOutcomeState = "matched" | "no_match" | "unavailable";

export interface KnowledgeSourceOutcome {
  source: string;
  status: KnowledgeSourceOutcomeState;
  matchCount: number;
  error: string | null;
  durationMs: number | null;
}

export interface KnowledgeCardModel {
  state: KnowledgeCardState;
  sources: string[];
  sourceOutcomes: KnowledgeSourceOutcome[];
  matches: KnowledgeExcerpt[];
  matchCount: number;
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

function sourceOutcomesFromProgress(progress: ProgressRecord[]): KnowledgeSourceOutcome[] {
  for (let index = progress.length - 1; index >= 0; index -= 1) {
    const sources = progress[index]?.details.sources;
    if (!Array.isArray(sources)) continue;

    const outcomes = sources.flatMap((item): KnowledgeSourceOutcome[] => {
      if (typeof item !== "object" || item === null) return [];
      const value = item as Record<string, unknown>;
      const source = typeof value.source === "string" ? value.source.trim() : "";
      if (!source) return [];
      const matchCount = typeof value.match_count === "number"
        && Number.isFinite(value.match_count)
        && value.match_count >= 0
        ? value.match_count
        : 0;
      const error = typeof value.error === "string" && value.error.trim()
        ? value.error.trim()
        : null;
      const explicitStatus = value.status;
      const status: KnowledgeSourceOutcomeState = explicitStatus === "matched"
        || explicitStatus === "no_match"
        || explicitStatus === "unavailable"
        ? explicitStatus
        : error
          ? "unavailable"
          : matchCount > 0
            ? "matched"
            : "no_match";
      const durationMs = typeof value.duration_ms === "number"
        && Number.isFinite(value.duration_ms)
        && value.duration_ms >= 0
        ? value.duration_ms
        : null;
      return [{ source, status, matchCount, error, durationMs }];
    });
    if (outcomes.length > 0) return outcomes;
  }
  return [];
}

export function buildKnowledgeCardModel({
  run,
  recommendation,
  progress,
  resultAvailable,
}: KnowledgeCardInput): KnowledgeCardModel {
  const sources = run?.config_snapshot?.knowledge_sources ?? [];
  const matches = recommendation?.knowledge_matches ?? [];
  const sourceOutcomes = sourceOutcomesFromProgress(progress);
  const outcomeMatchCount = sourceOutcomes.reduce(
    (total, outcome) => total + outcome.matchCount,
    0,
  );
  const matchCount = Math.max(matches.length, outcomeMatchCount);
  const summary = recommendation?.knowledge_match_summary?.trim()
    || progressKnowledgeSummary(progress);
  const base = { sources, sourceOutcomes, matches, matchCount, summary };

  if (run && run.status !== "RUNNING" && !resultAvailable) {
    return {
      ...base,
      sourceOutcomes: [],
      matches: [],
      matchCount: 0,
      summary: "",
      state: "unavailable_history",
      headline: "历史知识匹配结果不可恢复",
      description: "该次运行发生在运行级结果开始保存之前，无法还原当时的知识匹配内容。",
    };
  }

  if (matchCount > 0) {
    return {
      ...base,
      state: "matched",
      headline: `命中 ${matchCount} 条知识`,
      description: "知识结果提供机制和处置参考，但不能单独证明本次事故根因。",
    };
  }

  if (run?.config_snapshot && sources.length === 0) {
    return {
      ...base,
      state: "not_configured",
      headline: "未配置知识来源",
      description: "本次运行未选择知识来源，不影响 Agent 继续依据告警与实时证据分析。",
    };
  }

  if (sourceOutcomes.length > 0) {
    const allUnavailable = sourceOutcomes.every((outcome) => outcome.status === "unavailable");
    return {
      ...base,
      state: allUnavailable ? "unavailable" : "no_match",
      headline: allUnavailable ? "已配置的知识来源不可用" : "未匹配到符合条件的知识",
      description: allUnavailable
        ? "知识来源本次查询失败，Agent 已跳过知识匹配并继续分析实时证据。"
        : "已配置的知识来源未返回达到匹配条件的结果，Agent 仍会继续分析实时证据。",
    };
  }

  const completedMatchCount = progressKnowledgeCount(progress);
  if (run?.status === "RUNNING" && recommendation == null && completedMatchCount === null) {
    return {
      ...base,
      state: "matching",
      headline: "正在匹配知识",
      description: "正在并行检索本次运行选择的知识来源；检索失败不会阻断 Agent 排查。",
    };
  }

  return {
    ...base,
    state: "no_match",
    headline: "未匹配到符合条件的知识",
    description: "已配置的知识来源未返回达到匹配条件的结果，Agent 仍会继续分析实时证据。",
  };
}
