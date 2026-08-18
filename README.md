# AI-Agent Security Monitor

AI Agent、主机和 Web 行为的统一检测与风险分析平台。当前完成阶段 4：风险评分与解释。

## 当前能力

- FastAPI 健康检查：`GET /health`
- 统一事件单条/批量写入：`POST /api/events`
- 事件查询与时间、来源、类型、`trace_id` 过滤：`GET /api/events`
- 基于 `event_id` 的幂等去重
- YAML 驱动的字段匹配、分组计数、去重计数和时间窗口序列检测
- 首批五条检测规则：Agent 高频调用、Web 多路径探测、认证失败后成功、解释器启动下载工具、文件落地后启动进程
- 可解释告警查询：`GET /api/alerts`，包含证据事件、时间范围和 MITRE 技术编号
- 按父事件、会话、PID/PPID、文件哈希、IP 和主体时间近邻关联攻击行为
- Agent、用户、进程、文件、IP、域名和会话实体图，以及调用、创建、写入、执行、连接和派生关系
- 攻击链列表与详情：`GET /api/chains`、`GET /api/chains/{id}`，节点可追溯到原始事件
- 六个攻击阶段：侦察、凭证访问、执行、持久化、横向和外联
- 确定性的 0–100 风险评分，包含告警严重度、攻击链完整度、资产重要度、自动化强度和关联置信度
- 低、中、高、严重四级风险，以及分项贡献、加分原因、证据事件和建议处置
- YAML 资产重要度配置，便于在接入 CMDB 前维护关键身份、Agent、主机和地址
- PostgreSQL 16、SQLAlchemy 2 和 Alembic 迁移骨架
- React + TypeScript 健康状态页面
- Docker Compose 一键启动
- Pytest 与 Vitest 基础测试

## 快速启动

环境要求：Docker Desktop 或 Docker Engine（含 Compose 插件）。

```bash
docker compose up --build
```

启动后访问：

- 控制台：http://localhost:3000
- API：http://localhost:8000/health
- OpenAPI：http://localhost:8000/docs

验证 API：

```bash
curl http://localhost:8000/health
```

预期响应：

```json
{"status":"ok"}
```

上报一条 Agent Tool Call 示例：

```bash
python collectors/agent_tool_call.py
```

查询事件：

```bash
curl "http://localhost:8000/api/events?source=agent&event_type=tool_call&trace_id=demo-session-01"
```

`POST /api/events` 接受一个事件对象或事件对象数组（每批最多 1000 条）。查询接口还支持 `start_time`、`end_time`、`limit` 和 `offset`；时间使用带时区的 ISO 8601 格式。

回放阶段 2 攻击样本并查询告警：

```bash
python demo/replay.py demo/events-stage2.jsonl
curl "http://localhost:8000/api/alerts?severity=critical"
```

告警接口支持 `rule_id`、`severity`、`start_time`、`end_time`、`limit` 和 `offset` 过滤。规则位于 `rules/*.yaml`；每条规则包含 `id`、`name`、`conditions`、`window`、`threshold`、`severity` 和 `mitre`。修改规则后需重启后端进程。

回放阶段 3 完整攻击链并查看详情：

```bash
python demo/replay.py demo/events-stage3.jsonl
curl "http://localhost:8000/api/chains"
curl "http://localhost:8000/api/chains/<chain-id>"
```

攻击链列表支持 `stage`、`min_confidence`、`limit` 和 `offset` 过滤。详情返回实体节点、带关联原因和置信度的关系边，以及按时间排序的完整原始事件。

列表与详情中的 `risk` 字段均返回总分、等级和完整解释。评分公式为：

```text
告警严重度 × 0.30 + 攻击链完整度 × 0.25 + 资产重要度 × 0.20
+ 自动化强度 × 0.15 + 关联置信度 × 0.10
```

资产重要度维护在 `assets.yaml`。修改规则或资产配置后需重启后端；再次回放已有事件会重建攻击链并刷新风险评分。

停止服务：

```bash
docker compose down
```

如需同时删除本地数据库卷：

```bash
docker compose down -v
```

## 本地开发

### 后端

Python 3.12：

```bash
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
copy ..\.env.example ..\.env
alembic upgrade head
uvicorn app.main:app --reload
```

运行测试：

```bash
cd backend
pytest
```

### 前端

Node.js 20+：

```bash
cd frontend
npm install
npm run dev
```

Vite 开发服务器会将 `/api` 请求代理到 `http://localhost:8000`。

运行测试与构建：

```bash
cd frontend
npm test -- --run
npm run build
```

## 数据库迁移

后端容器启动时自动执行：

```bash
alembic upgrade head
```

创建新迁移：

```bash
cd backend
alembic revision --autogenerate -m "describe change"
```

## 目录

```text
backend/       FastAPI、SQLAlchemy、Alembic 与测试
frontend/      React、TypeScript、Vite 与 Vitest
collectors/    Agent Tool Call 上报示例及后续采集器
rules/         YAML 检测规则
assets.yaml    资产重要度配置
demo/          阶段 2/3 演示数据和 JSONL 回放器
docs/          施工文档
```
