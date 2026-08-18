import { useEffect, useState } from "react";

type HealthState = "loading" | "healthy" | "unavailable";

interface HealthResponse {
  status: "ok";
}

export default function App() {
  const [health, setHealth] = useState<HealthState>("loading");

  useEffect(() => {
    const controller = new AbortController();

    async function loadHealth() {
      try {
        const response = await fetch("/api/health", {
          signal: controller.signal,
          headers: { Accept: "application/json" },
        });
        if (!response.ok) throw new Error(`Health check failed: ${response.status}`);

        const payload = (await response.json()) as HealthResponse;
        setHealth(payload.status === "ok" ? "healthy" : "unavailable");
      } catch (error) {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setHealth("unavailable");
      }
    }

    void loadHealth();
    return () => controller.abort();
  }, []);

  const copy = {
    loading: { label: "正在连接", detail: "等待分析服务响应", tone: "pending" },
    healthy: { label: "服务正常", detail: "API 已连接，可以开始接入安全事件", tone: "ok" },
    unavailable: { label: "服务异常", detail: "无法连接 API，请检查后端容器", tone: "error" },
  }[health];

  return (
    <main className="shell">
      <header className="topbar">
        <div className="brand-mark" aria-hidden="true">AM</div>
        <div>
          <p className="product">AI-Agent Security Monitor</p>
          <p className="environment">MONITORING CONSOLE · LOCAL</p>
        </div>
      </header>

      <section className="workspace" aria-labelledby="page-title">
        <div className="title-row">
          <div>
            <p className="eyebrow">SYSTEM OVERVIEW</p>
            <h1 id="page-title">平台状态</h1>
          </div>
          <span className="stage">STAGE 0</span>
        </div>

        <div className="status-panel">
          <div className={`status-icon ${copy.tone}`} aria-hidden="true">
            <span />
          </div>
          <div className="status-copy" aria-live="polite">
            <p className="status-label">API HEALTH</p>
            <h2>{copy.label}</h2>
            <p>{copy.detail}</p>
          </div>
          <code>GET /health</code>
        </div>

        <div className="metrics" aria-label="平台组件">
          <article>
            <span>API</span>
            <strong>FastAPI</strong>
            <small>HTTP analysis service</small>
          </article>
          <article>
            <span>DATABASE</span>
            <strong>PostgreSQL 16</strong>
            <small>Persistent event storage</small>
          </article>
          <article>
            <span>MIGRATIONS</span>
            <strong>Alembic</strong>
            <small>Schema lifecycle ready</small>
          </article>
        </div>
      </section>
    </main>
  );
}

