export const levelLabel = {
  low: "低",
  medium: "中",
  high: "高",
  critical: "严重",
} as const;

export const stageLabel: Record<string, string> = {
  reconnaissance: "侦察",
  credential_access: "凭证访问",
  execution: "执行",
  persistence: "持久化",
  lateral_movement: "横向移动",
  external_communication: "外联",
};

export const sourceLabel: Record<string, string> = {
  agent: "Agent",
  host: "主机",
  web: "Web",
};

export const factorLabel: Record<string, string> = {
  alert_severity: "告警严重度",
  chain_completeness: "攻击链完整度",
  asset_importance: "资产重要度",
  automation_intensity: "自动化强度",
  correlation_confidence: "关联置信度",
};

export function formatDate(value: string) {
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(value));
}

export function duration(start: string, end: string) {
  const seconds = Math.max(0, Math.round((Date.parse(end) - Date.parse(start)) / 1000));
  return seconds < 60 ? `${seconds} 秒` : `${Math.floor(seconds / 60)} 分 ${seconds % 60} 秒`;
}
