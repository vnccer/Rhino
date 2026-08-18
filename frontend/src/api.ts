import type { Alert, ChainDetail, ChainSummary, Overview } from "./types";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, { signal, headers: { Accept: "application/json" } });
  if (!response.ok) throw new ApiError(response.status, `请求失败 (${response.status})`);
  return response.json() as Promise<T>;
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
