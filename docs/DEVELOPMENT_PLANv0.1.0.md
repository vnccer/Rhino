# AI-Agent Security Monitor 施工文档 v0.1.0

## 1. 项目目标

构建一个面向 AI 驱动攻击的行为检测与风险分析平台，完成以下闭环：

```text
事件采集 → 标准化 → 规则检测 → 行为关联 → 攻击链 → 风险评分 → 可视化报告
```

MVP 聚焦三类数据：

- AI Agent：Prompt、Tool Call、参数、执行结果。
- 主机行为：进程、文件、命令和网络连接。
- Web 行为：请求路径、方法、状态码和来源 IP。

## 2. 精简技术栈

| 层 | 技术 |
|---|---|
| API / 分析引擎 | Python 3.12、FastAPI、SQLAlchemy |
| 数据库 | PostgreSQL 16 |
| 前端 | React、TypeScript、Vite、ECharts |
| 部署 | Docker Compose |
| 测试 | Pytest、Vitest |

MVP 暂不引入 Kafka、Neo4j、机器学习模型。事件量增大后再替换队列和图存储。

## 3. 总体目录

```text
AI-Agent-Security-Monitor/
├─ backend/
│  ├─ app/
│  │  ├─ api/             # HTTP 接口
│  │  ├─ core/            # 配置与日志
│  │  ├─ models/          # 数据库模型
│  │  ├─ schemas/         # Pydantic 事件模型
│  │  ├─ services/        # 检测、关联、评分
│  │  └─ main.py
│  └─ tests/
├─ frontend/
│  └─ src/
├─ collectors/            # Agent/Web/主机采集示例
├─ rules/                 # YAML 检测规则
├─ demo/                  # 演示事件与回放脚本
├─ docs/
├─ compose.yaml
├─ .env.example
└─ README.md
```

## 4. 核心事件模型

所有来源统一为一个事件结构，后续模块只依赖该结构：

```json
{
  "event_id": "uuid",
  "timestamp": "2026-08-18T12:00:00Z",
  "source": "agent|host|web",
  "event_type": "tool_call|process_start|file_write|network_connect|http_request",
  "actor": {"type": "agent|user|process|ip", "id": "agent-01"},
  "action": "execute",
  "object": {"type": "command", "id": "cmd-01", "name": "curl"},
  "result": "success|failure|unknown",
  "severity": 0,
  "trace_id": "session-or-request-id",
  "parent_event_id": null,
  "attributes": {}
}
```

硬性要求：事件必须带 `event_id`、`timestamp`、`source`、`event_type`；能关联的数据尽量携带 `trace_id`、`parent_event_id`、PID、IP 和文件哈希。

---

## 阶段 0：工程骨架

### 目标

建立可启动、可测试、可持续迭代的空平台。

### 施工

- 创建 FastAPI 服务，提供 `GET /health`。
- 配置 PostgreSQL、SQLAlchemy 和数据库迁移。
- 创建 React 页面，显示后端健康状态。
- 添加 `compose.yaml`、`.env.example`、基础测试和 README。

### 验收

```bash
docker compose up --build
curl http://localhost:8000/health
```

预期：接口返回 `{"status":"ok"}`，前端可访问且显示服务正常。

### Git

```bash
git add .
git commit -m "chore: scaffold monitor platform"
```

---

## 阶段 1：统一事件接入

### 目标

打通“事件写入数据库 → 查询事件”的最小数据闭环。

### 施工

- 实现事件表、Pydantic 校验模型和数据库迁移。
- 实现 `POST /api/events`，支持单条和批量写入。
- 实现 `GET /api/events`，支持时间、来源、类型和 `trace_id` 过滤。
- 添加事件去重：相同 `event_id` 重复提交不产生新记录。
- 在 `collectors/` 提供 Agent Tool Call 上报示例。

### 验收

- 合法事件可写入并查询。
- 非法枚举值或缺少必填字段时返回 `422`。
- 重放同一事件后数据库仍只有一条记录。
- 后端事件接口测试通过。

### Git

```bash
git add .
git commit -m "feat: add normalized event ingestion"
```

---

## 阶段 2：规则检测引擎

### 目标

根据单事件或短时间窗口产生可解释告警。

### 施工

- 定义 YAML 规则格式：`id`、`name`、`conditions`、`window`、`threshold`、`severity`、`mitre`。
- 实现字段匹配、计数阈值和时间窗口检测。
- 首批规则：
  - Agent 高频 Tool Call。
  - 短时间多路径探测。
  - 连续认证失败后成功。
  - 命令解释器启动下载工具。
  - 文件落地后创建新进程。
- 实现 `GET /api/alerts` 和告警证据字段。

### 验收

- `demo/events-stage2.jsonl` 回放后命中预期规则。
- 每条告警包含规则 ID、严重度、命中事件 ID、时间范围和 MITRE 技术编号。
- 正常事件样本不产生高危告警。

### Git

```bash
git add .
git commit -m "feat: implement rule-based behavior detection"
```

---

## 阶段 3：攻击链关联

### 目标

把孤立告警和事件关联成一条可追踪的攻击链。

### 施工

- 建立实体：Agent、用户、进程、文件、IP、域名和会话。
- 建立关系：调用、创建、写入、执行、连接、派生。
- 关联优先级：
  1. `parent_event_id` 直接关系。
  2. 相同 `trace_id` 或 Agent Session。
  3. PID/PPID、文件哈希、源/目标 IP。
  4. 同主体的时间窗口近邻。
- 实现攻击链阶段：侦察、凭证访问、执行、持久化、横向、外联。
- 实现 `GET /api/chains` 和 `GET /api/chains/{id}`。

### 验收

- 回放一组演示事件后生成一条链，而不是多个孤立告警。
- 链中每个节点都能追溯原始事件。
- 不同 `trace_id` 的无关行为不会被错误合并。

### Git

```bash
git add .
git commit -m "feat: correlate events into attack chains"
```

---

## 阶段 4：风险评分与解释

### 目标

输出稳定、可解释、可复测的 0–100 风险等级。

### 施工

采用确定性评分：

```text
Risk =
  告警严重度 × 0.30
+ 攻击链完整度 × 0.25
+ 资产重要度 × 0.20
+ 自动化强度 × 0.15
+ 关联置信度 × 0.10
```

- 定义等级：低 `0–29`、中 `30–59`、高 `60–79`、严重 `80–100`。
- 自动化强度考虑频率、并发度、失败后切换速度和跨工具连续性。
- 输出各评分项、加分原因、证据事件和建议处置。
- 资产重要度先用配置文件维护，后续再接 CMDB。

### 验收

- 同一批事件重复计算得到相同分数。
- 删除关键攻击阶段后，攻击链完整度和总分下降。
- API 同时返回总分、等级、分项和解释，不只返回一个数字。

### Git

```bash
git add .
git commit -m "feat: add explainable attack risk scoring"
```

---

## 阶段 5：分析控制台

### 目标

让面试官在 3 分钟内看懂发生了什么、为什么危险。

### 施工

- 总览：首页展示事件数、告警数、高危链和趋势。
- 告警页：按等级、规则、来源和时间筛选。
- 攻击链页：时间线 + 关系图 + MITRE 阶段。
- 详情抽屉：原始事件、关联原因、评分解释和处置建议。
- 提供加载、空数据、错误状态和基础响应式布局。

### 验收

- 从高危卡片可进入攻击链详情。
- 点击任意链节点可查看原始证据。
- 图表数据全部来自 API，不硬编码演示结果。
- 前后端测试和生产构建通过。

### Git

```bash
git add .
git commit -m "feat: add attack analysis dashboard"
```

---

## 阶段 6：演示场景与最终交付

### 目标

形成可一键启动、回放和讲解的实习作品。

### 施工

- 编写演示回放器，按时间顺序发送 JSONL 事件。
- 准备两组数据：
  - 正常运维：低频命令、正常部署和健康检查。
  - AI 自动攻击：快速枚举、认证尝试、命令执行、下载落地、外联。
- 提供一键演示命令和数据清理命令。
- README 补充架构图、截图、演示步骤、规则说明和设计取舍。
- 输出一份示例攻击链 JSON 和风险分析报告。

### 验收

```bash
docker compose up -d --build
python demo/replay.py demo/ai_attack.jsonl
```

预期：控制台出现完整攻击链、MITRE 映射、风险分数及解释；正常样本不出现高危攻击链。

### Git

```bash
git add .
git commit -m "feat: add reproducible attack-chain demo"
git tag v0.1.0
```

---

## 5. 每阶段统一完成标准

每次提交前必须满足：

- 当前阶段功能能独立演示，不提交不可运行的半成品。
- API 输入有校验，异常有明确状态码和日志。
- 新增核心逻辑至少包含一个正常用例和一个异常用例。
- 不在代码、样本或 Git 历史中提交密钥和真实凭证。
- `README.md` 的启动命令与实际代码一致。
- 执行测试、构建和 `git diff --check` 后再提交。

## 6. MVP 结束后的升级方向

按实际瓶颈升级，不提前堆组件：

1. Redis Streams / Kafka：异步事件流与削峰。
2. Neo4j：复杂实体图查询和攻击路径探索。
3. Sigma 兼容层：复用社区检测规则。
4. Sysmon、Auditd、Zeek 采集器：接入真实遥测。
5. LLM 分析助手：仅负责攻击链摘要、规则解释和报告生成，检测与评分仍由确定性引擎完成。

## 7. 推荐演示话术

> 平台不依赖大模型猜测风险，而是先把 Agent Tool Call、主机行为和 Web 请求统一成事件，再通过规则和实体关系还原攻击链。风险分数由可解释指标计算，最后由 LLM 辅助生成摘要，因此检测结果可追溯、可复测。
