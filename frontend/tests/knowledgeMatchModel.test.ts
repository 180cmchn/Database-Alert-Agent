import assert from "node:assert/strict";
import test from "node:test";
import { buildKnowledgeCardModel } from "../src/lib/knowledgeMatchModel.ts";
import type {
  InvestigationRun,
  KnowledgeExcerpt,
  ProgressRecord,
  Recommendation,
} from "../src/types/api.ts";

function run(
  status: InvestigationRun["status"],
  knowledgeSources: string[] | null,
): InvestigationRun {
  return {
    id: "run-1",
    alert_id: "alert-1",
    attempt: 1,
    status,
    current_stage: status === "RUNNING" ? "KNOWLEDGE_MATCHING" : "COMPLETED",
    config_snapshot: knowledgeSources === null ? null : {
      knowledge_sources: knowledgeSources,
      external_knowledge_enabled: knowledgeSources.includes("external_knowledge"),
      external_knowledge_base_url: "https://knowledge.example.test",
      external_knowledge_min_relevance: 0.6,
      react_max_rounds: 8,
      analysis_timeout_seconds: 1800,
      validation_enabled: true,
      ai_fallback_enabled: true,
      stream_main_agent_reasoning: false,
      ai_model: "test-model",
      ai_provider: "fake",
    },
    created_at: "2026-08-20T00:00:00Z",
    updated_at: "2026-08-20T00:00:00Z",
  };
}

function progress(details: Record<string, unknown>): ProgressRecord {
  return {
    id: "progress-1",
    run_id: "run-1",
    sequence: 1,
    stage: "KNOWLEDGE_MATCHING",
    message: "知识匹配完成。",
    details,
    created_at: "2026-08-20T00:00:00Z",
  };
}

function match(): KnowledgeExcerpt {
  return {
    source: "incident_library",
    knowledge_id: "knowledge-1",
    title: "连接耗尽案例",
    content: "核查活跃连接来源。",
    source_uri: "https://knowledge.example.test/knowledge-1",
    score: 0.91,
    raw_score: 0.09,
    metadata: {},
  };
}

function recommendation(matches: KnowledgeExcerpt[], summary = ""): Recommendation {
  return {
    summary: "现有结果无法得出根因",
    knowledge_match_summary: summary,
    likely_causes: [],
    analysis_bases: [{ source: "AI", statement: "AI 依据" }],
    steps: [],
    risks: [],
    confidence: 0,
    knowledge_matches: matches,
    root_causes: [],
  };
}

test("no configured source is explicit and does not imply an investigation block", () => {
  const model = buildKnowledgeCardModel({
    run: run("RUNNING", []),
    recommendation: null,
    progress: [],
    resultAvailable: true,
  });

  assert.equal(model.state, "not_configured");
  assert.match(model.description, /不影响 Agent/);
});

test("a configured running source reports matching in progress", () => {
  const model = buildKnowledgeCardModel({
    run: run("RUNNING", ["external_knowledge", "incident_library"]),
    recommendation: null,
    progress: [],
    resultAvailable: true,
  });

  assert.equal(model.state, "matching");
  assert.deepEqual(model.sources, ["external_knowledge", "incident_library"]);
});

test("a completed zero-count search reports no qualifying match and keeps its summary", () => {
  const summary = "知识匹配结果：external_knowledge 命中 0 条。";
  const model = buildKnowledgeCardModel({
    run: run("RUNNING", ["external_knowledge"]),
    recommendation: null,
    progress: [progress({ knowledge_match_count: 0, knowledge_match_summary: summary })],
    resultAvailable: true,
  });

  assert.equal(model.state, "no_match");
  assert.equal(model.summary, summary);
});

test("a failed provider is explicitly unavailable and non-blocking", () => {
  const summary = "知识匹配结果：incident_library 查询失败（TimeoutError），已忽略。";
  const model = buildKnowledgeCardModel({
    run: run("RUNNING", ["incident_library"]),
    recommendation: null,
    progress: [progress({
      sources: [{ source: "incident_library", match_count: 0, error: "TimeoutError" }],
      knowledge_match_count: 0,
      knowledge_match_summary: summary,
    })],
    resultAvailable: true,
  });

  assert.equal(model.state, "unavailable");
  assert.deepEqual(model.sourceOutcomes, [{
    source: "incident_library",
    status: "unavailable",
    matchCount: 0,
    error: "TimeoutError",
    durationMs: null,
  }]);
  assert.equal(model.summary, summary);
  assert.match(model.description, /继续分析实时证据/);
});

test("matched knowledge exposes every persisted entry", () => {
  const knowledge = match();
  const model = buildKnowledgeCardModel({
    run: run("COMPLETED", ["incident_library"]),
    recommendation: recommendation([knowledge], "命中一条知识。"),
    progress: [],
    resultAvailable: true,
  });

  assert.equal(model.state, "matched");
  assert.deepEqual(model.matches, [knowledge]);
  assert.equal(model.summary, "命中一条知识。");
});

test("an unrecoverable historical result takes precedence over an empty payload", () => {
  const model = buildKnowledgeCardModel({
    run: run("COMPLETED", null),
    recommendation: null,
    progress: [],
    resultAvailable: false,
  });

  assert.equal(model.state, "unavailable_history");
  assert.match(model.headline, /不可恢复/);
});
