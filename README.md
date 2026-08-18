# AI-Agent Security Monitor

AI Agent、主机和 Web 行为的统一检测与风险分析平台。当前完成阶段 1：统一事件接入。

## 当前能力

- FastAPI 健康检查：`GET /health`
- 统一事件单条/批量写入：`POST /api/events`
- 事件查询与时间、来源、类型、`trace_id` 过滤：`GET /api/events`
- 基于 `event_id` 的幂等去重
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
rules/         后续阶段的 YAML 检测规则
demo/          后续阶段的演示数据和回放器
docs/          施工文档
```
