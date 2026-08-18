# AI-Agent Security Monitor

AI Agent、主机和 Web 行为的统一检测与风险分析平台。当前完成阶段 0：可启动、可测试的工程骨架。

## 当前能力

- FastAPI 健康检查：`GET /health`
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
collectors/    后续阶段的数据采集器
rules/         后续阶段的 YAML 检测规则
demo/          后续阶段的演示数据和回放器
docs/          施工文档
```
