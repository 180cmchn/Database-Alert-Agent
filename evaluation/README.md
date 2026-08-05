# 告警 Agent 离线评测

`datasets/runbook_matching.jsonl` 评测手册召回、首位排序、章节命中和无手册拒识；
`datasets/root_cause_diagnosis.jsonl` 评测结构化诊断图能否覆盖目标候选原因。

## 从本地 PDF 重新生成初标数据

生成器会实际读取 PDF 文字层，并为每个可用手册生成确定性的匹配样本；只有同目录
`index.json` 已明确配置 `causes[].cause_id` 时才生成根因样本，避免从普通段落中臆造根因。
所有记录统一标记为 `review_required`，不能未经专家复核直接用于生产准入。

Linux/macOS：

```bash
.venv/bin/python tools/generate_evaluation_datasets.py --force
```

Windows PowerShell：

```powershell
.\.venv\Scripts\python.exe tools\generate_evaluation_datasets.py --force
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
  --force
```

没有索引时，生成器优先读取 PDF 正文中明确标注的告警类型；仍无法识别时使用正文首个有效标题
产生待审核类型。需要禁止标题兜底时增加 `--strict-alert-types`。PDF 加密、损坏或没有可提取文字层
时生成失败，纯扫描件必须先 OCR。目标 JSONL 已存在时必须显式使用 `--force`，两份文件都在
全部 PDF 校验完成后才写入。

当前记录来自手册人工初标或合成改写，统一标记为 `review_required`。数据库专家审核时应：

1. 核对告警字段、正确手册、章节和原因 ID；有正确手册的样例必须填写与该手册类型目录一致的
   `alert.alert_type`，原因和标题的改写不能替代告警类型；
2. 删除无法从原文或真实事故闭环支持的样例；
3. 将审核通过的记录改为 `review_status=approved`；
4. 从历史生产事件补充困难负样本、拒识样本和同告警不同根因的反事实样本；
5. 按事故和时间切分训练集、验证集与测试集，禁止把同一事件的改写泄漏到不同集合。

当前评测工具只测确定性的检索和诊断知识覆盖。生成模型的根因三态、证据忠实性和安全性应在
影子运行中由人工反馈统计；`policies/production-gates.json` 中列出的零容忍项必须保持为零。
