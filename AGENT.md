# AGENT.md

本文面向在本仓库中工作的自动化编码 Agent。除非子目录中存在更具体的 `AGENT.md`，本文适用于整个仓库。

## 1. 项目目标

Database Alert Agent 从 FlashDuty 等来源接收数据库告警，持久化并调度分析，由单一主 Agent 结合权威告警详情、可选知识来源和按需获取的只读 MCP 实时证据判断根因。

新分析的根因契约只有两种结果：

- `SUPPORTED`：实时证据已建立因果机制，`verified=true`，并引用具备根因资格的证据；
- `INCONCLUSIVE`：`root_causes=[]`，摘要固定为 `现有结果无法得出根因`。

不要引入第三种结论、暂定根因、猜测性处置步骤，或让程序投影器代替主 Agent 做因果判断。

## 2. 信息源与工作边界

开始修改前，先阅读相关实现、测试和配置。主要信息源：

- `README.md`：运行方式、环境变量、API 和验证命令；
- `docs/project-architecture.md`：系统边界、Agent 流程、MCP 与证据契约；
- `.env.example`：可配置项及说明；
- `pyproject.toml`、`frontend/package.json`：语言版本、依赖和可用脚本；
- `config/mcp/settings.json` 与 `config/mcp/prompts/`：当前 MCP 声明和 provider 行为边界；
- 现有测试：行为契约的可执行说明。

实现、配置、测试和文档发生冲突时，不要凭猜测新增第二套约定；确认当前运行路径，修正相关内容使其重新一致。

除任务明确要求外：

- 不读取、输出或提交 `.env` 中的秘密；
- 不扫描、复制或修改 `data/alerts.db`、备份、审计日志和运行时锁文件；
- 不修改 `.venv/`、`__pycache__/`、缓存、构建产物或 `frontend/node_modules/`；
- 不覆盖用户已有的无关改动，不做顺手重构；
- 不调用真实 FlashDuty、Archery、Prometheus、模型或知识服务完成普通离线测试。

## 3. 仓库结构

| 路径 | 职责 |
| --- | --- |
| `app/domain/` | Pydantic 领域模型、状态枚举、端口协议、领域错误和纯预处理逻辑 |
| `app/application/` | 用例编排、依赖装配、调度、运行时设置、取消和管理逻辑 |
| `app/agents/` | LangGraph 状态、节点和主调查图 |
| `app/agent_runtime/` | Durable dispatch、事件、预算、租约、checkpoint、恢复和轨迹 |
| `app/adapters/` | AI、FlashDuty、MCP、知识、通知、持久化和确定性结果投影 |
| `app/mcp_catalog/` | MCP 配置与提示词目录加载、校验 |
| `app/mcp_runtime/` | MCP 会话、调用契约、持久化与重放基础设施 |
| `app/api/` | FastAPI 应用、鉴权、路由和请求/响应 Schema |
| `app/workers/` | Redis Streams Worker 入口 |
| `config/mcp/` | MCP provider 声明及 `role/purpose/workflow/safety` 提示词 |
| `migrations/` | Alembic 环境和不可变的顺序迁移 |
| `tests/unit/` | 隔离的单元与组件行为测试，使用 fake、replay 和临时数据库 |
| `tests/integration/` | API、管理接口和可选外部基础设施集成测试 |
| `tests/live/` | 仅在显式启用真实凭据时运行的测试 |
| `frontend/src/` | React 页面、组件、API 客户端、类型与展示模型 |
| `frontend/tests/` | Node 内置 test runner 驱动的 TypeScript 测试 |
| `tools/`、`policies/`、`evaluation/` | 生产门槛评估及其策略、数据和报告入口 |
| `runbooks/`、`docs/` | 运维知识和架构说明 |

依赖方向应保持清晰：领域层定义模型和端口，应用层编排用例，Adapter 实现外部能力，`app/application/factory.py` 负责装配。不要从领域层反向依赖 API、具体 Adapter 或运行时基础设施。

## 4. 不可破坏的系统契约

### 4.1 调查与结论

- 主路径保持 `enrich_alert -> fingerprint -> knowledge -> react_decide <-> execute_react_tool -> advise -> validate -> report`。
- FlashDuty `/alert/info` 是目标、时间和告警语义的权威来源；不得从标题猜测或补全 `alarm_host`、`alarm_port`。
- 告警详情说明“发生了什么”，知识说明“可能的机制”，二者都不能单独证明本次根因。
- 只有唯一主 Agent 可以综合证据判断根因；MCP 内部 Agent、投影器和 `validate` 节点都不能做新的因果判断。
- 每个主 Agent ReAct 轮次最多选择一个外层工具或 `finish`。MCP 内部认证、发现、Schema、分页和恢复调用不额外消耗 ReAct 轮次。
- 达到 `REACT_MAX_ROUNDS` 是正常收束，不应自动标记为失败；整次运行仍受超时、主动取消和租约约束。
- 工具失败、超时、`NO_DATA` 或不适用不能机械地否决其它合格证据。

### 4.2 证据与持久化

- 完整、净化后的原始工具结果进入内部 artifact；主 Agent 只接收有界、可追溯的 observation。
- 程序投影只能过滤、聚合、排序、计算统计量并标注真实 source path；必须确定性执行，不得调用模型，也不得输出“支持/反驳某根因”的判断。
- 新证据必须保持 artifact、调用、父记录和具体 evidence unit 的可追溯关系。
- 用户轨迹只展示真实 `thought/action/observation`；不得伪造 reasoning，也不得暴露认证响应、秘密或内部 artifact。
- Durable dispatch、幂等键、fencing token、checkpoint 版本、租约和取消检查是正确性边界。修改恢复路径时必须覆盖中断、重放、重复执行和所有权丢失。

### 4.3 MCP 与外部系统

- 调查工具保持只读。系统可以生成带风险、前提、审批和回滚要求的处置建议，但不能执行变更。
- 新通用 MCP 优先声明式接入：更新 `config/mcp/settings.json`，并新增四个非空提示词文件：`role.md`、`purpose.md`、`workflow.md`、`safety.md`。
- 不要按告警类型新增“必调某 MCP”的 Python 分支。主 Agent 根据 provider 的角色和用途在运行时选择工具。
- URL、Header 和 Key 只通过环境变量引用解析；禁止把真实连接信息写进 JSON、提示词、测试快照或日志。
- 只有远端结果确实需要领域化、确定性的聚合或安全门禁时，才增加 provider 专用 Adapter/投影器，并配套测试。

## 5. 本地开发

要求 Python 3.12+；前端要求 Node.js 20.19+ 或 22.12+。

### 5.1 后端

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
alembic upgrade head
uvicorn app.api.main:app --reload
```

以 `.env.example` 为模板创建本地 `.env`，只填写本机需要的值。`STREAM_MAIN_AGENT_REASONING` 是必填部署基线。API 默认监听 `http://127.0.0.1:8000`。

### 5.2 前端

```bash
cd frontend
npm install
npm run dev
```

Vite 开发服务默认使用 `http://127.0.0.1:5173`；Compose 中的静态前端映射到 `http://127.0.0.1:3000`。

### 5.3 Docker Compose

Compose 强制加载项目根目录 `.env`。完成必填部署配置后运行：

```bash
docker compose up -d --build
```

`migrate` 服务执行 `alembic upgrade head`，API 与 Worker 只在迁移和 Redis 健康检查成功后启动；前端可独立启动。不要让 API 与 Worker 使用不同的 `APP_CODE_VERSION` 或数据库迁移状态。

## 6. 修改规则

### 6.1 Python

- 遵循 Python 3.12、完整类型标注和现有异步风格；行宽 100。
- Ruff 规则以 `pyproject.toml` 为准：`E`、`F`、`I`、`B`、`UP`、`ASYNC`。
- 外部 I/O 使用异步客户端、显式超时和已有取消语义；不要在事件循环中加入阻塞 I/O。
- 在系统边界使用 Pydantic 校验。复用 `app/domain/ports.py` 中的协议、现有 registry 和 factory 装配方式，避免平行抽象。
- 日志记录稳定标识和状态，不记录密钥、完整认证 Header 或未经净化的外部负载。
- 保持 fake/replay 可注入；不要把外部客户端直接构造在领域逻辑或测试目标内部。

### 6.2 API 与前端

- API 契约变化时同步检查 `app/api/schemas.py`、路由、`frontend/src/types/api.ts`、`frontend/src/lib/api.ts`、页面消费者和测试。
- TypeScript 保持 `strict`、`noUncheckedIndexedAccess`、`noUnusedLocals` 和 `noUnusedParameters` 通过。
- 复用现有组件和展示模型；不要在多个页面复制状态转换或 API 类型。
- 用户可见状态必须来自持久化契约，不在前端猜测根因、工具状态或证据资格。
- UI 变化要在真实页面验证加载、空态、失败态和增量更新，而不只验证构建成功。

### 6.3 数据库与配置

- 持久化 Schema 变化必须新增 Alembic 迁移并更新模型、Repository 和测试；不要改写已发布迁移，也不要手工修改数据库文件。
- 迁移同时考虑 SQLite 与已声明的 PostgreSQL/MySQL 可选驱动，避免只在本机方言成立的语句。
- SQLite 到 MySQL 的数据迁移统一使用 `tools/migrate_sqlite_to_mysql.py`；目标使用独立空库，停服并备份后执行，禁止手写跨方言 dump 或跳过逐表摘要校验。
- 新环境变量同步更新 `app/config.py`、`.env.example`、相关 Compose 配置和文档。
- 只有 `RUNTIME_SETTINGS_KEYS` 中的配置可以通过管理 API 在线修改。新增在线配置时同步更新校验、管理 API Schema、持久化覆盖逻辑和设置页。
- 配置快照和 manifest 必须冻结影响分析重放的非秘密值；不得持久化密钥。

### 6.4 依赖、文档与生成文件

- 优先使用现有依赖。新增依赖必须有直接用途，并同步更新 `pyproject.toml` 或 `frontend/package.json`；前端依赖变化同时更新 `package-lock.json`。
- 行为、配置、API 或运维流程变化时同步更新现有 README/docs/runbook，不新建重复说明。
- Shell 脚本和 Dockerfile 保持 LF；不要提交缓存、运行数据、评估结果或构建产物。

## 7. 测试与验证

先运行能覆盖改动契约的最小测试，再按影响面扩大。测试应对可观察行为、边界、状态转换、恢复和真实错误负责，不测试实现文本或无意义的 mock 调用次数。

常用定向命令：

```bash
pytest tests/unit/test_workflow.py -q
pytest tests/integration/test_api.py -q
cd frontend && npm test
```

提交前按改动范围执行：

```bash
pytest -m "not live"
ruff check app tests migrations
python -m compileall -q app tests
npm --prefix frontend test
npm --prefix frontend run typecheck
npm --prefix frontend run build
```

约束：

- 纯后端改动至少运行相关 pytest、Ruff 和 compileall；
- 前端逻辑改动至少运行相关前端测试、typecheck 和 build；
- API 跨层改动同时验证后端接口与前端消费者；
- 数据库改动验证全新数据库升级和已有 Schema 到 head 的升级路径；
- 并发、重放或恢复改动必须覆盖重复执行、中断恢复、版本冲突、租约丢失和取消；
- `tests/live/` 及真实外部服务测试只在任务明确要求、凭据已安全提供且环境允许时运行；
- 本机无法连接公司内网 MCP 不等于离线测试可以忽略失败。离线测试必须使用 fake/replay，且自身保持全绿；
- 文档或配置说明改动无需运行无关全套测试，但必须核对引用路径、命令和默认值与当前配置一致。

## 8. 完成标准

交付前确认：

1. 根因、证据、只读工具、秘密和持久化边界未被破坏；
2. 所有调用者、API 类型、配置模板、迁移和现有文档已按需要同步；
3. 没有兼容别名、废弃分支、临时开关、占位实现或无主代码残留；
4. 已运行覆盖实际改动的命令或场景，并准确记录结果；
5. 未提交秘密、运行数据、缓存、构建产物或无关格式化改动。
