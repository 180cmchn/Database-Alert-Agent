# 本地 PDF 告警处理手册

`pdfs/` 保存 Agent 使用的告警手册审计原文，`index.json` 保存与 PDF 对应的结构化检索与
诊断索引。服务同时读取 PDF 文字层、检测含图页面，并把索引中人工识别的红框报错、截图字段
和关键字作为 `visual_evidence`；它们与告警名、指标名、章节特征、别名、适用范围和正文一起
参与混合检索。命中的具体章节及其对应原因、动作和视觉证据作为分析首要依据。

维护规则：

1. 一份手册对应一个 `.pdf` 文件，文件名（不含扩展名）作为稳定的手册 ID；
2. PDF 必须未加密，并带可提取的文字层；扫描件应先完成 OCR，但 OCR 不能替代图片视觉审核；
3. `index.json` 中的 `runbook_id` 必须对应现有 PDF，章节页码不得超出 PDF 页数；
4. 对每个含图页面渲染检查图片，提取红框/高亮报错、命令、配置值、界面字段和流程分支，写入带
   `page`、`kind`、`text`、`keywords`、可选 `section_ids` 的 `visual_evidence`；
5. 原因和动作可用 `section_ids` 绑定章节，动作可用 `cause_id` 与原因一一对应；同页包含多个原因时，
   必须为章节配置互不混淆的 `match_terms`；
6. 新资料先标为 `draft` 或 `review_required`；数据库专家同时复核文字和视觉证据后，才能把手册及
   对应视觉证据改为 `approved`；含图页面未标注或视觉证据未批准时，服务拒绝加载 `approved` 手册；
7. `incomplete` 和 `deprecated` 不参与检索，未批准资料的分析结果必须人工复核；
8. 变更类动作必须标记 `execution_class=change` 和 `approval_required=true`；
9. 替换、新增或删除 PDF/索引后重启 API 与 Worker，使各进程使用同一版本；
10. 不维护网页地址、Cookie、Bearer Token 或内网页面白名单；
11. 管理 API 和前端手册页只读，不提供在线修改或审批。

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
.venv/bin/python tools/audit_runbook_visuals.py
.venv/bin/python tools/evaluate_runbooks.py --enforce-gates
```

第一条命令在存在未覆盖的含图页面时失败；正式批准时追加 `--require-approved`，确保所有视觉证据
也已由专家批准。
