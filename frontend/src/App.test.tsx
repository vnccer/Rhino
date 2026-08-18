import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import App from "./App";

describe("App", () => {
  afterEach(() => vi.restoreAllMocks());

  it("shows a healthy backend", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ status: "ok" }), { status: 200 }),
    );

    render(<App />);

    expect(await screen.findByText("服务正常")).toBeInTheDocument();
    expect(fetch).toHaveBeenCalledWith("/api/health", expect.any(Object));
  });

  it("shows an unavailable state when the request fails", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("offline"));

    render(<App />);

    expect(await screen.findByText("服务异常")).toBeInTheDocument();
  });
});

