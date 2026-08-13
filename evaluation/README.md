# 告警 Agent 离线评测

`datasets/runbook_matching.jsonl` 评测手册召回、首位排序、章节命中和无手册拒识；
`datasets/root_cause_diagnosis.jsonl` 评测结构化诊断图能否覆盖目标候选原因。

## 从本地 PDF 同步自动回归数据

生成器会实际读取 PDF 文字层，为每个有效的“手册 × 告警类型”生成确定性的匹配样本，为每个
告警类型生成不存在目录的拒识样本；只有索引已明确配置 `causes[].cause_id` 时才生成原因覆盖样本，
避免从普通段落中臆造根因。同一手册覆盖多个告警类型时，每个原因只生成一个样本，并按类型专属
告警名、指标、别名和关键词自动选择最相关的类型。自动样本用于验证摄取、召回和结构化知识覆盖，
不冒充独立真实效果数据。

Linux/macOS：

```bash
.venv/bin/python tools/generate_evaluation_datasets.py --sync
```

Windows PowerShell：

```powershell
.\.venv\Scripts\python.exe tools\generate_evaluation_datasets.py --sync
```

默认读取生成后的 `runbooks/pdfs-typed`，写入：

- `datasets/runbook_matching.jsonl`
- `datasets/root_cause_diagnosis.jsonl`

输入既可以是 `pdfs-typed/<alert_type>/*.pdf` 的类型目录，也可以是遗留的平铺 PDF。平铺目录有旧全局
索引时可显式传入：

```bash
.venv/bin/python tools/generate_evaluation_datasets.py \
  --pdf-dir /path/to/flat-pdfs \
  --source-index /path/to/index.json \
  --output-dir evaluation/datasets \
  --sync
```

没有索引时，生成器优先读取 PDF 正文中明确标注的告警类型；仍无法识别时使用正文首个有效标题。
语义自动索引应使用 `process_pdf_runbooks.py --auto-index`，而不是依赖这个标题兜底。需要禁止标题
兜底时增加 `--strict-alert-types`。PDF 加密、损坏或没有可提取文字层时生成失败，纯扫描件必须先
OCR。`--sync` 会替换 PDF 自动生成样本并保留其他来源记录；`--force` 才会整体替换两份文件。

生产门槛按当前语料的覆盖率、内容哈希新鲜度、召回、拒识、章节和原因指标判断，不再要求每个
JSONL 固定达到 100 条，也不要求逐条修改 `review_status`。但诊断数据集至少必须达到
`dataset_policy.minimum_diagnosis_cases`；空诊断集的 `cause_candidate_recall` 和
`cause_case_coverage` 均为 `0.0`，不能用空集合覆盖率形成假通过。历史生产事件仍应作为独立来源
持续积累困难负样本、同告警不同根因和反事实样本，并按事故与时间隔离；这些数据用于衡量真实
效果，不会在 `--sync` 时被覆盖。

当前评测工具只测确定性的检索和诊断知识覆盖。主 Agent 的 `SUPPORTED`/不确定结论、证据忠实性
和行为边界应通过带预期结果的离线场景集、回放与按时间隔离的历史事件结果统计。评测报告必须在
顶层 `violations` 中显式给出
`policies/production-gates.json` 所列每个零容忍项的非负整数计数；任意非零、缺失或非法计数都会
使生产门槛失败。检索评测产生的零值只表示其执行范围内没有观察到违规，不替代完整 Agent 场景
评测。

## Agent harness 场景报告

Agent 运行时有两层验证。第一层使用 `ReplayMCPConnector`、fake client 和临时 SQLite 进行离线
replay/fault injection，验证 ReAct `finish`、轮次上限、整次分析超时、主动取消、MCP 超时、断线
重连、部分证据、checkpoint 恢复和 fencing；这些测试不访问公司内网。第二层是下面的发布门槛场景
报告，用于汇总端到端场景
运行结果，不能由单元测试的通过状态代替。

`harness_policy` 已支持独立 Agent harness 报告输入。当前默认关闭，是因为 CI/发布流程尚未接入
生成 `evaluation/results/harness-report.json` 的场景运行器；现有单元测试不会自动生成该文件。
启用 `harness_policy.enabled=true` 前，CI 必须先生成报告，并通过以下命令执行准入：

```bash
.venv/bin/python tools/evaluate_runbooks.py \
  --harness-report evaluation/results/harness-report.json \
  --enforce-gates
```

报告格式如下；每个必需场景族的数量至少为 `1`。场景族包括 `react_finish`、
`react_round_limit`、`analysis_timeout`、`analysis_cancel`、`mcp_timeout`、`mcp_reconnect`、
`partial_evidence` 和 `checkpoint_resume`：

```json
{
  "scenario_count": 22,
  "fault_families": {
    "react_finish": 2,
    "react_round_limit": 2,
    "analysis_timeout": 2,
    "analysis_cancel": 2,
    "mcp_timeout": 3,
    "mcp_reconnect": 3,
    "partial_evidence": 3,
    "checkpoint_resume": 5
  },
  "violations": {
    "fabricated_runbook_references": 0,
    "fabricated_evidence": 0,
    "unapproved_change_actions": 0
  }
}
```
