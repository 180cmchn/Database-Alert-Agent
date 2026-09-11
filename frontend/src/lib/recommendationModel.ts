import type { Recommendation, RecommendationStep } from "../types/api";

export interface RecommendationGroup {
  key: "temporary" | "long-term";
  title: string;
  description: string;
  steps: RecommendationStep[];
}

export function buildRecommendationGroups(
  recommendation: Recommendation,
): RecommendationGroup[] {
  return [
    {
      key: "temporary",
      title: "临时解决",
      description: "用于控制当前影响、恢复服务或降低当前风险。",
      steps: recommendation.temporary_solutions,
    },
    {
      key: "long-term",
      title: "长期优化",
      description: "用于消除已证实根因或降低同类问题复发概率。",
      steps: recommendation.long_term_optimizations,
    },
  ];
}
