import type { Alert, ChainDetail, ChainSummary, Overview } from "./types";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const token = sessionStorage.getItem("admin_access_token");
  const response = await fetch(path, {
    signal,
    headers: {
      Accept: "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!response.ok) {
    if (response.status === 401) window.dispatchEvent(new Event("admin-auth-required"));
    throw new ApiError(response.status, `请求失败 (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export async function login(username: string, password: string) {
  const response = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!response.ok) throw new ApiError(response.status, "用户名或密码错误");
  return response.json() as Promise<{ access_token: string; expires_at: string }>;
}

export function getOverview(signal?: AbortSignal) {
  return getJson<Overview>("/api/overview?days=7", signal);
}

export function getAlerts(params: URLSearchParams, signal?: AbortSignal) {
  const query = params.toString();
  return getJson<Alert[]>(`/api/alerts${query ? `?${query}` : ""}`, signal);
}

export function getChains(signal?: AbortSignal) {
  return getJson<ChainSummary[]>("/api/chains?limit=100", signal);
}

export function getChain(id: string, signal?: AbortSignal) {
  return getJson<ChainDetail>(`/api/chains/${id}`, signal);
}
