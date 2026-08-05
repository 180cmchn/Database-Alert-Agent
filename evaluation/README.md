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

默认读取 `runbooks/pdfs`，写入：

- `datasets/runbook_matching.jsonl`
- `datasets/root_cause_diagnosis.jsonl`

输入既可以是 `pdfs/<alert_type>/*.pdf` 的类型目录，也可以是遗留的平铺 PDF。平铺目录有旧全局
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
JSONL 固定达到 100 条，也不要求逐条修改 `review_status`。历史生产事件仍应作为独立来源持续
积累困难负样本、同告警不同根因和反事实样本，并按事故与时间隔离；这些数据用于衡量真实效果，
不会在 `--sync` 时被覆盖。

当前评测工具只测确定性的检索和诊断知识覆盖。生成模型的根因三态、证据忠实性和安全性应在
影子运行中由人工反馈统计；`policies/production-gates.json` 中列出的零容忍项必须保持为零。
