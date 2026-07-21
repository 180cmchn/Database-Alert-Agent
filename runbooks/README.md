# 本地 PDF 告警处理手册

`pdfs/` 是 Agent 唯一使用的告警手册数据源。服务启动后直接读取每份 PDF 的文字层，按告警
名称、原因、指标名、故障描述、标题等字段做全文匹配；命中的 PDF 正文作为分析的首要依据。

维护规则：

1. 一份手册对应一个 `.pdf` 文件，文件名（不含扩展名）作为稳定的手册 ID；
2. PDF 必须未加密，并带可提取的文字层；扫描件应先完成 OCR；
3. 替换、新增或删除 PDF 后重启 API 与 Worker，使各进程使用同一份目录；
4. 不再维护 Markdown 索引、网页地址、Cookie、Bearer Token 或内网页面白名单；
5. 管理 API 和前端手册页只提供清单与提取正文查看，不提供在线修改。

默认配置：

```dotenv
RUNBOOK_PDF_DIR=./runbooks/pdfs
RUNBOOK_LIMIT=5
RUNBOOK_PDF_MAX_FILE_BYTES=20000000
RUNBOOK_PDF_MAX_TEXT_CHARS=200000
```

目录中任意 PDF 缺少可用文字层、已加密、损坏或超过单文件大小限制时，服务会明确报错，
不会悄悄回退到网页或旧版本地 Markdown 手册。
