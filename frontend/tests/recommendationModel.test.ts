import assert from "node:assert/strict";
import test from "node:test";
import { buildRecommendationGroups } from "../src/lib/recommendationModel.ts";
import type { Recommendation } from "../src/types/api.ts";

function recommendation(): Recommendation {
  return {
    summary: "已建立根因",
    knowledge_match_summary: "",
    likely_causes: ["已建立的因果机制"],
    analysis_bases: [{ source: "AI", statement: "实时证据依据" }],
    temporary_solutions: [{ order: 1, action: "临时处置 A" }],
    long_term_optimizations: [
      { order: 1, action: "长期优化 A" },
      { order: 2, action: "长期优化 B" },
    ],
    risks: [],
    confidence: 0.9,
    knowledge_matches: [],
    root_causes: [],
  };
}

test("recommendations remain in the model-provided categories and order", () => {
  const groups = buildRecommendationGroups(recommendation());

  assert.deepEqual(groups.map((group) => group.title), ["临时解决", "长期优化"]);
  assert.deepEqual(groups[0]?.steps.map((step) => step.action), ["临时处置 A"]);
  assert.deepEqual(groups[1]?.steps.map((step) => step.action), ["长期优化 A", "长期优化 B"]);
});

test("an empty category remains explicit instead of receiving inferred steps", () => {
  const value = recommendation();
  value.temporary_solutions = [];

  const groups = buildRecommendationGroups(value);

  assert.deepEqual(groups[0]?.steps, []);
  assert.equal(groups[1]?.steps.length, 2);
});
