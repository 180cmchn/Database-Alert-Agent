# 本地 PDF 告警处理手册

`pdfs/` 保存待处理的平铺 PDF 原文；`pdfs-typed/<alert_type>/` 是自动生成的运行时目录，
类型目录内的 `index.json` 保存这些 PDF 对应的结构化检索与诊断结果。服务同时读取 PDF 文字层、检测含图页面，并把索引中识别的红框报错、截图字段
和关键字作为 `visual_evidence`；它们与告警名、指标名、章节特征、别名、适用范围和正文一起
参与混合检索。命中的具体章节及其对应原因、动作和视觉证据作为可追溯知识依据。

维护规则：

1. 一份手册对应一个 `.pdf` 文件，文件名（不含扩展名）作为稳定的手册 ID；单类型 PDF 放在对应
   类型目录中，多类型 PDF 以相同 ID、相同字节和等价注解复制到每个对应类型目录；
2. PDF 必须未加密，并带可提取的文字层；扫描件应先完成 OCR，含图页面还应提取图片中的关键信息；
3. 每个类型目录的 `index.json` 使用 `schema_version=3`，顶层 `alert_type` 必须与目录名一致；其中
   的 `runbook_id` 必须对应该目录现有 PDF，章节页码不得超出 PDF 页数；
4. 对每个含图页面渲染检查图片，提取红框/高亮报错、命令、配置值、界面字段和流程分支，写入带
   `page`、`kind`、`text`、`keywords`、可选 `section_ids` 的 `visual_evidence`；
5. 原因和动作可用 `section_ids` 绑定章节，动作可用 `cause_id` 与原因一一对应；同页包含多个原因时，
   必须为章节配置互不混淆的 `match_terms`；
6. 含图页面必须按第 4 条完成 `visual_evidence` 标注；手册和视觉证据不维护质量等级或审核状态，
   所有可检索手册按相同规则参与匹配；
7. `knowledge_type=incomplete` 或 `deprecated=true` 的资料不参与检索；`deprecated` 只表示资料已停用，
   不表示质量等级；
8. 变更类动作必须标记 `execution_class=change` 和 `approval_required=true`；
9. 替换、新增或删除 PDF/索引后重启 API 与 Worker，使各进程使用同一版本；
10. 不维护网页地址、Cookie、Bearer Token 或内网页面白名单；
11. 管理 API 和前端手册页只读，不提供在线修改；
12. 告警分析只检索 `alert_type` 对应的目录，不跨类型兜底；目录不存在时返回
    `匹配本地pdf失败，pdf中没有该类型告警的处理方法`。

默认配置：

```dotenv
RUNBOOK_PDF_DIR=./runbooks/pdfs-typed
RUNBOOK_LIMIT=5
RUNBOOK_PDF_MAX_FILE_BYTES=20000000
RUNBOOK_PDF_MAX_TEXT_CHARS=200000
RUNBOOK_MATCH_MIN_SCORE=12
RUNBOOK_MATCH_MIN_CONFIDENCE=0.35
```

将旧的平铺目录和全局索引转换为新布局：

```bash
.venv/bin/python tools/process_pdf_runbooks.py \
  --source-pdf-dir /path/to/flat-pdfs \
  --output-dir /path/to/typed-pdfs
```

持续接入新 PDF 时使用自动摄取命令；它会调用项目已配置的 AI 模型抽取所有告警类型和结构化
诊断内容，同步评测样本并执行覆盖率门槛。首轮类型为空时会自动复查案件标题、触发条件和
处置流程，并对明确的应急处置标题使用受限的原文回退。重复运行只处理新增或内容发生变化的 PDF；
Windows 拒绝目录重命名时，`--sync` 会自动改用完整复制，失败则恢复原目录：

```powershell
python .\tools\process_pdf_runbooks.py --source-pdf-dir .\runbooks\pdfs --output-dir .\runbooks\pdfs-typed --auto-index --sync --enforce-gates
```

`--auto-index` 遵循当前 `AI_PROVIDER`，支持 `openai_compatible`（Chat Completions）和
`openai_responses`（Responses API）；切换协议后不会复用另一协议生成的自动索引缓存。

自动模式不需要源索引。`--source-index` 仅用于显式覆盖；指定单个类型时使用 `alert_type`，一份
PDF 覆盖多个类型时使用 `alert_types`，且显式传入的路径必须存在：

```json
{
  "schema_version": 2,
  "runbooks": [
    {
      "runbook_id": "shared-database-guide",
      "alert_types": ["mysql_crash", "mysql_connections_high"]
    }
  ]
}
```

转换工具会为每个类型生成一份 PDF 副本和单数 `alert_type` 注解。AI 自动结果还包含
`alert_type_profiles`，使同一手册在不同类型目录使用各自的告警名、指标名和别名。运行时仅在副本的 PDF
字节及除目录归属外的结构化注解完全一致时按稳定 ID 聚合，否则拒绝加载，避免引用歧义。

默认模式要求输出目录尚不存在；`--sync` 会先在同级临时目录完整生成并校验，再原子替换已有的
派生目录，始终不会改写平铺源 PDF。目录中任意 PDF 缺少文字层、已加密、损坏、超过大小限制，或索引引用缺失 PDF/无效页码时，
服务会明确报错，不会悄悄回退。提交或部署手册目录前请运行：

```bash
.venv/bin/python tools/audit_runbook_visuals.py
.venv/bin/python tools/evaluate_runbooks.py --enforce-gates
```

第一条命令在存在未覆盖的含图页面时失败；第二条命令按生产准入策略校验检索与诊断覆盖率。
