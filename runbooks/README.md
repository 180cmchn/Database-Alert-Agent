# 本地 PDF 告警处理手册

`pdfs/` 保存 Agent 使用的告警手册审计原文，`index.json` 保存与 PDF 对应的结构化检索与
诊断索引。服务读取 PDF 文字层并按索引中的章节页码切分，结合告警名、指标名、别名、适用
范围和正文做混合检索；命中的具体章节作为分析首要依据。

维护规则：

1. 一份手册对应一个 `.pdf` 文件，文件名（不含扩展名）作为稳定的手册 ID；
2. PDF 必须未加密，并带可提取的文字层；扫描件应先完成 OCR；
3. `index.json` 中的 `runbook_id` 必须对应现有 PDF，章节页码不得超出 PDF 页数；
4. 新资料先标为 `draft` 或 `review_required`，经数据库专家复核后才能改为 `approved`；
5. `incomplete` 和 `deprecated` 不参与检索，未批准资料的分析结果必须人工复核；
6. 变更类动作必须标记 `execution_class=change` 和 `approval_required=true`；
7. 替换、新增或删除 PDF/索引后重启 API 与 Worker，使各进程使用同一版本；
8. 不维护网页地址、Cookie、Bearer Token 或内网页面白名单；
9. 管理 API 和前端手册页只读，不提供在线修改或审批。

默认配置：

```dotenv
RUNBOOK_PDF_DIR=./runbooks/pdfs
RUNBOOK_LIMIT=5
RUNBOOK_PDF_MAX_FILE_BYTES=20000000
RUNBOOK_PDF_MAX_TEXT_CHARS=200000
RUNBOOK_MATCH_MIN_SCORE=12
RUNBOOK_MATCH_MIN_CONFIDENCE=0.35
```

目录中任意 PDF 缺少文字层、已加密、损坏、超过大小限制，或索引引用缺失 PDF/无效页码时，
服务会明确报错，不会悄悄回退。批准前请运行：

```bash
.venv/bin/python tools/evaluate_runbooks.py --enforce-gates
```
