# 告警 Agent 发布门槛

本目录保存与具体知识提供方无关的离线场景报告。生产门槛关注主 Agent 能否正常结束、
超时与取消、知识来源降级、MCP 故障、部分证据、预算耗尽和 checkpoint 恢复，同时对
伪造知识引用、伪造现场证据和未授权变更操作实行零容忍。

场景运行器应生成 `evaluation/results/agent-harness-report.json`：

```json
{
  "scenario_count": 8,
  "fault_families": {
    "main_agent_finish": 1,
    "analysis_timeout": 1,
    "analysis_cancel": 1,
    "knowledge_source_timeout": 1,
    "mcp_timeout": 1,
    "partial_evidence": 1,
    "budget_exhaustion": 1,
    "checkpoint_resume": 1
  },
  "violations": {
    "fabricated_knowledge_references": 0,
    "fabricated_evidence": 0,
    "unapproved_change_actions": 0
  }
}
```

执行发布门槛：

```bash
.venv/bin/python tools/evaluate_production_gates.py \
  --report evaluation/results/agent-harness-report.json \
  --enforce-gates
```

这些场景使用 replay、fake client 和临时数据库，不依赖公司内网。Archery MCP 与
Prometheus MCP 的真实连通性测试不属于离线门槛。
