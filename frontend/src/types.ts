export type View = "overview" | "alerts" | "chains";
export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface TrendPoint {
  bucket: string;
  events: number;
  alerts: number;
}

export interface Overview {
  event_count: number;
  alert_count: number;
  critical_alert_count: number;
  high_risk_chain_count: number;
  chain_count: number;
  source_counts: Record<string, number>;
  trend: TrendPoint[];
}

export interface Alert {
  alert_id: string;
  rule_id: string;
  rule_name: string;
  severity: number;
  severity_label: RiskLevel;
  mitre: string[];
  start_time: string;
  end_time: string;
  evidence_event_ids: string[];
  sources: string[];
  evidence: Record<string, unknown>;
  created_at: string;
}

export interface RiskFactor {
  score: number;
  weight: number;
  contribution: number;
  reasons: string[];
}

export interface RiskAssessment {
  score: number;
  level: RiskLevel;
  breakdown: Record<string, RiskFactor>;
  reasons: string[];
  evidence_event_ids: string[];
  recommendations: string[];
}

export interface ChainSummary {
  chain_id: string;
  title: string;
  start_time: string;
  end_time: string;
  stages: string[];
  event_ids: string[];
  alert_ids: string[];
  confidence: number;
  risk: RiskAssessment;
}

export interface EventRecord {
  event_id: string;
  timestamp: string;
  source: string;
  event_type: string;
  actor: { type: string; id: string } | null;
  action: string | null;
  object: { type: string; id: string; name?: string | null } | null;
  result: string;
  severity: number;
  trace_id: string | null;
  parent_event_id: string | null;
  attributes: Record<string, unknown>;
}

export interface ChainNode {
  node_id: string;
  entity_type: string;
  entity_id: string;
  label: string;
  stage: string;
  event_ids: string[];
}

export interface ChainEdge {
  edge_id: string;
  source_node_id: string;
  target_node_id: string;
  relationship: string;
  event_id: string | null;
  reason: string;
  priority: number;
  confidence: number;
}

export interface ChainDetail extends ChainSummary {
  nodes: ChainNode[];
  edges: ChainEdge[];
  events: EventRecord[];
}
