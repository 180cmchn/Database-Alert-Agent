---
name: analyze-database-alerts
description: Analyze database alerts with FlashDuty details, selected local PDF or external knowledge, optional MCP evidence, deterministic result projection, and a single main-Agent ReAct loop that returns either SUPPORTED or an explicit inconclusive result.
---

# Analyze Database Alerts

Investigate one database alert with a single main Agent. The main Agent is the only component that
may combine evidence, evaluate causal mechanisms, and decide the root cause. Tools and deterministic
processors collect and structure facts; they never decide causality.

All investigation actions requested by the Agent must declare `read_only` intent. Do not request
database writes, DDL, configuration changes, failover, restart, scaling, privilege changes, session
termination, or other side effects. MCP authorization is established by the key issued for that MCP.
The application connection layer forwards calls according to the dynamically discovered tool Schema
and does not rewrite model arguments.

## 1. Start from the authoritative alert detail

For a FlashDuty alert, fetch `/alert/info` before knowledge matching or MCP decisions. Use the full
detail in both activities. Treat the detail's `alarm_host` and `alarm_port` as the only authoritative
host and port. Never parse, recover, or supplement them from the title. If either field is absent,
record it as missing rather than guessing.

Normalize without inventing values:

- source, alert ID, severity, environment, service, occurrence time, and alert signal;
- engine, cluster or instance, database, resource object, `alarm_host`, and `alarm_port`;
- observed value, threshold, duration, trend, scope, and reported impact;
- the fixed investigation window `[occurred_at - 5 minutes, occurred_at]`.

Read [references/signal-diagnosis.md](references/signal-diagnosis.md) when signal vocabulary helps
identify useful observations. The vocabulary is a retrieval aid, not proof of a cause.

## 2. Retrieve selected knowledge

Search every knowledge source selected for the run. The normalized FlashDuty detail participates in
the query alongside alert type, engine, metric or error signature, resource, service, and environment.
Local PDF and the external knowledge API are independent peer sources. For the external source, use
[references/external-knowledge-api.yaml](references/external-knowledge-api.yaml).

Apply each source's configured relevance threshold. Preserve the real runbook ID, section, page,
knowledge ID, title, and source URI. Never invent a match, reference, cause, or URL. An empty or failed
source is a knowledge gap, not proof that live evidence is insufficient. Knowledge can explain live
facts but cannot prove that its described cause occurred in this incident.

## 3. Run the main-Agent ReAct loop

Use one loop with this observable sequence:

```text
thought -> action -> observation -> thought -> ... -> finish
```

For every round:

1. `thought`: use the model provider's actual `reasoning_content` or `reasoning` when it is returned.
   Never generate a short summary and present it as model reasoning. When the provider has not
   returned reasoning, continue the analysis while the UI displays the fixed text
   `当前暂时无法显示思维链，但仍在分析中`.
2. `action`: choose exactly one outer tool and provide its complete arguments and objective, or emit
   `finish` when the available material is enough for a final decision or no useful next action
   remains.
3. `observation`: record the tool outcome and a traceable deterministic projection of any usable
   result, then use it in the next thought.

The only count-based stop is the configurable `react_max_rounds`. Reaching it or emitting `finish`
ends investigation normally and proceeds to the final decision. Do not impose provider-specific MCP
step limits, remote-call budgets, retry-count budgets, or empty-result call caps. Authentication,
target discovery, schema discovery, pagination, and other calls made inside one outer MCP action do
not consume extra ReAct rounds. The complete analysis remains bounded by a configurable wall-clock
timeout and may be actively cancelled. Runtime fields `planner_requests`, `accepted_decisions`,
`remote_tool_calls`, `host_bootstrap_calls`, `session_attempts`, and `model_tokens` are audit counters
only; legacy or configured limits with those names do not stop an investigation.

## 4. Select MCPs by declared capability

Inspect the configured MCP catalog's external `role`, `purpose`, `workflow`, and `safety` prompts.
Decide from the full alert detail and current evidence whether any MCP can produce useful facts.
Every MCP is optional. Do not call a server merely because it is configured, do not hard-code an
alert-type strategy branch, and do not require every configured MCP to succeed.

For a selected MCP, follow its workflow and use its dynamically discovered tool descriptions and
Schemas. Pass model-produced arguments through without application-side business rewriting.
Preserve success, no-data, timeout, cancellation, and failure outcomes honestly. A database outside
an MCP's configured coverage means that MCP is not applicable; it is not a global investigation
failure.

New MCPs are integrated declaratively:

1. add a sibling entry under `mcpServers` in `config/mcp/settings.json`;
2. reference URL and credential environment variables instead of storing secrets in JSON;
3. add `role.md`, `purpose.md`, `workflow.md`, and `safety.md` under
   `config/mcp/prompts/<provider>/`;
4. restart the API and Worker so the main Agent can discover the new role and purpose.

Do not add a provider selection branch to this skill or application code.

## 5. Apply provider workflows faithfully

Archery provides slow-query logs. Use the FlashDuty detail endpoint and five-minute window, follow
the configured metadata chain, and query `mysql_slow_query_review_history`. Authentication,
`t_instance_member`, `sql_instance`, schema, and index responses are auxiliary audit material. Only
the final history query has slow-query semantics useful to the main Agent.

Prometheus provides database monitoring metrics. First discover which database targets and metrics
are actually configured. If the alert database is covered, query relevant metrics for the exact
five-minute window. If it is not covered, return
`Prometheus MCP 中没有配置告警数据库对应的监控信息`. Do not substitute current-time samples,
another database, or an unscoped cross-cluster aggregate.

These examples describe the checked-in provider prompts. A future provider follows its own external
workflow and must not inherit Archery or Prometheus assumptions.

## 6. Convert or project MCP results deterministically

Save every complete sanitized raw MCP response as an internal, hash-bound audit artifact. Do not
send auxiliary raw responses or the complete raw artifact to the main Agent. Result screening,
simplification, aggregation, and sorting must be deterministic and must not invoke an LLM.

For Archery, the program passes the final `mysql_slow_query_review_history` query result (the
merged result when content-length truncation forced per-id follow-up queries) through to the main
Agent with a format conversion only: the JSON embedded in the `result` text becomes a JSON object
and positional rows are labeled with `column_list`. It performs no filtering, aggregation,
sorting, truncation, or size capping, and it never judges causality. When the embedded JSON
cannot be parsed, the original text is passed through as-is and the record is marked
`processing_status=unavailable`. Login and lookup responses stay internal.

For every other provider, program-side processing may deterministically filter, aggregate, sort,
calculate statistics, and select traceable snippets. Every projected fact or anomaly must
reference a real source JSON Pointer. Artifact URIs, IDs, hashes, and complete raw content stay
internal and must not enter the main-Agent context. A projection may describe values and
deviations but must not claim that a fact supports or disproves a root cause. For Prometheus,
project target-matched, exact-window time-series statistics and anomalies; keep discovery and
catalog responses internal.

The bounded projection path exists so logs do not exhaust the main context; it never truncates
or discards the audit artifact. If deterministic processing cannot produce a reliable projection,
mark that observation unusable and retain the raw artifact for audit.

## 7. Decide causality only in the main Agent

After each observation, the main Agent may decide whether another tool can materially reduce
uncertainty. At `finish` or the ReAct round limit, combine the authoritative alert detail, matched
knowledge, and usable live observations.

A supported root cause must describe a causal mechanism rather than repeat the alert symptom. It
must cite relevant, successful, target-matched live evidence from the affected system. Knowledge
alone, an alert threshold, a correlated metric, an MCP catalog response, or an auxiliary lookup does
not establish a root cause.

Use only this result contract:

- If the evidence establishes a root cause, return it with status `SUPPORTED`, `verified=true`, and
  the qualifying live evidence IDs.
- Otherwise return no root causes and use the exact summary `现有结果无法得出根因`, ending as
  `INCONCLUSIVE`.

Do not emit tentative, unknown, contradicted, rejected, or excluded root causes. Do not invent alert
details, knowledge references, log rows, metrics, or tool outcomes.

Evidence sufficiency is evaluated from the relevant usable evidence actually available for this
alert. An unselected MCP, an uncovered database, `NO_DATA`, timeout, failure, cancellation, or an
unusable projection does not by itself force the whole analysis to be insufficient. Conversely,
successful responses do not make evidence sufficient unless they establish the returned causal
mechanism.

After the main Agent returns its result, apply only deterministic contract checks for output shape,
evidence-reference existence, source status, and traceability. Do not call a validator model or let
another Agent reassess `evidence_sufficient`, reject the causal mechanism, or produce a replacement
root cause. A deterministic failure may only make the structurally invalid output inconclusive.

## 8. Produce the recommendation

Return a concise, traceable result:

- summarize the symptom, scope, and impact without overstating certainty;
- list actually retrieved PDF and external knowledge references before AI analysis bases;
- attach qualifying live evidence IDs to every `SUPPORTED` root cause;
- propose only read-only recovery verification or investigation steps;
- place change actions under risks or approval-required notes rather than instructions to execute;
- state material evidence gaps without naming speculative causes;
- use `现有结果无法得出根因` whenever the evidence does not establish one.

The user-visible trace contains the model's actual reasoning when available, followed by actions and
observations in durable sequence order. Internal audit artifacts, secrets, auxiliary MCP responses,
and synthetic reasoning are not part of that trace.
