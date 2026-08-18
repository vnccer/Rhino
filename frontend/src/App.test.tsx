import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import App from "./App";

vi.mock("./charts", () => ({
  init: () => ({ setOption: vi.fn(), on: vi.fn(), resize: vi.fn(), dispose: vi.fn() }),
}));

const risk = {
  score: 88,
  level: "critical",
  breakdown: {
    alert_severity: { score: 100, weight: 0.3, contribution: 30, reasons: ["critical alert"] },
    chain_completeness: { score: 80, weight: 0.25, contribution: 20, reasons: ["stages"] },
  },
  reasons: ["检测到严重告警"],
  evidence_event_ids: ["event-1"],
  recommendations: ["隔离受影响主机"],
};

const chain = {
  chain_id: "chain-1",
  title: "demo chain",
  start_time: "2026-08-18T14:00:00Z",
  end_time: "2026-08-18T14:02:00Z",
  stages: ["reconnaissance", "execution"],
  event_ids: ["event-1"],
  alert_ids: ["alert-1"],
  confidence: 92,
  risk,
};

const detail = {
  ...chain,
  nodes: [{ node_id: "node-1", entity_type: "agent", entity_id: "agent-1", label: "agent-1", stage: "execution", event_ids: ["event-1"] }],
  edges: [],
  events: [{
    event_id: "event-1", timestamp: "2026-08-18T14:01:00Z", source: "agent",
    event_type: "tool_call", actor: { type: "agent", id: "agent-1" }, action: "execute",
    object: { type: "command", id: "cmd-1", name: "powershell" }, result: "success",
    severity: 80, trace_id: "trace-1", parent_event_id: null, attributes: { command: "whoami" },
  }],
};

function responseFor(input: RequestInfo | URL) {
  const url = String(input);
  if (url.startsWith("/api/overview")) return { event_count: 16, alert_count: 3, critical_alert_count: 1, high_risk_chain_count: 1, chain_count: 1, source_counts: { agent: 2, host: 4, web: 10 }, trend: [{ bucket: "2026-08-18", events: 16, alerts: 3 }] };
  if (url === "/api/chains?limit=100") return [chain];
  if (url === "/api/chains/chain-1") return detail;
  if (url.startsWith("/api/alerts")) return [];
  throw new Error(`Unexpected request: ${url}`);
}

describe("App", () => {
  afterEach(() => vi.restoreAllMocks());

  it("opens a high-risk chain and exposes raw event evidence", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) =>
      new Response(JSON.stringify(responseFor(input)), { status: 200 }),
    );

    render(<App />);

    expect(await screen.findByText("16")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /侦察 → 执行.*1 个事件/ }));

    expect(await screen.findByText("攻击阶段")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /tool_call.*agent-1/ }));
    expect(await screen.findByText("原始事件")).toBeInTheDocument();
    expect(screen.getByText(/"command": "whoami"/)).toBeInTheDocument();
    expect(fetch).toHaveBeenCalledWith("/api/chains/chain-1", expect.any(Object));
  });

  it("shows an error state and retries API requests", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("offline"));

    render(<App />);

    const errors = await screen.findAllByText("数据加载失败");
    expect(errors.length).toBeGreaterThan(0);
    fireEvent.click(screen.getAllByRole("button", { name: /重新加载/ })[0]);
    await waitFor(() => expect(fetchMock.mock.calls.length).toBeGreaterThan(3));
  });
});
