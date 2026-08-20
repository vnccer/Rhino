import {
  Activity, AlertTriangle, BarChart3, ChevronRight, CircleAlert, GitBranch, LogIn, LogOut,
  RefreshCw, Search, ShieldAlert,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

import { getAlerts, getChain, getChains, getOverview, login } from "./api";
import { ChainGraph } from "./components/ChainGraph";
import { DetailDrawer } from "./components/DetailDrawer";
import { TrendChart } from "./components/TrendChart";
import { duration, factorLabel, formatDate, levelLabel, sourceLabel, stageLabel } from "./format";
import type { Alert, ChainDetail, ChainNode, ChainSummary, EventRecord, Overview, View } from "./types";

type LoadState = "loading" | "ready" | "error";
const emptyFilters = { severity: "", rule: "", source: "", start: "", end: "" };

function Badge({ level }: { level: string }) {
  return <span className={`badge badge-${level}`}>{levelLabel[level as keyof typeof levelLabel] ?? level}</span>;
}

function EmptyState({ title, detail }: { title: string; detail: string }) {
  return <div className="empty-state"><Search size={28} /><strong>{title}</strong><p>{detail}</p></div>;
}

function ErrorState({ retry }: { retry: () => void }) {
  return <div className="error-state"><CircleAlert size={26} /><strong>数据加载失败</strong><p>分析服务暂时不可用，请检查后端连接。</p><button onClick={retry}><RefreshCw size={15} />重新加载</button></div>;
}

function LoadingRows() {
  return <div className="loading-rows" aria-label="正在加载"><span /><span /><span /></div>;
}

export default function App() {
  const [authRequired, setAuthRequired] = useState(false);
  const [authenticated, setAuthenticated] = useState(() => Boolean(sessionStorage.getItem("admin_access_token")));
  const [view, setView] = useState<View>("overview");
  const [overview, setOverview] = useState<Overview | null>(null);
  const [chains, setChains] = useState<ChainSummary[]>([]);
  const [baseState, setBaseState] = useState<LoadState>("loading");
  const [reload, setReload] = useState(0);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [alertState, setAlertState] = useState<LoadState>("loading");
  const [filters, setFilters] = useState(emptyFilters);
  const [appliedFilters, setAppliedFilters] = useState(emptyFilters);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [selectedChainId, setSelectedChainId] = useState<string | null>(null);
  const [chainDetail, setChainDetail] = useState<ChainDetail | null>(null);
  const [chainState, setChainState] = useState<LoadState>("ready");
  const [selectedEvent, setSelectedEvent] = useState<EventRecord | null>(null);
  const [selectedNode, setSelectedNode] = useState<ChainNode | null>(null);

  useEffect(() => {
    const requireAuth = () => { setAuthenticated(false); setAuthRequired(true); };
    window.addEventListener("admin-auth-required", requireAuth);
    return () => window.removeEventListener("admin-auth-required", requireAuth);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    setBaseState("loading");
    Promise.all([getOverview(controller.signal), getChains(controller.signal)])
      .then(([overviewData, chainData]) => {
        setOverview(overviewData);
        setChains(chainData);
        setSelectedChainId((current) => current ?? chainData[0]?.chain_id ?? null);
        setBaseState("ready");
      })
      .catch((error: unknown) => {
        if (!(error instanceof DOMException && error.name === "AbortError")) setBaseState("error");
      });
    return () => controller.abort();
  }, [reload]);

  useEffect(() => {
    const controller = new AbortController();
    const params = new URLSearchParams();
    if (appliedFilters.severity) params.set("severity", appliedFilters.severity);
    if (appliedFilters.rule) params.set("rule_id", appliedFilters.rule);
    if (appliedFilters.source) params.set("source", appliedFilters.source);
    if (appliedFilters.start) params.set("start_time", new Date(appliedFilters.start).toISOString());
    if (appliedFilters.end) params.set("end_time", new Date(appliedFilters.end).toISOString());
    setAlertState("loading");
    getAlerts(params, controller.signal)
      .then((data) => { setAlerts(data); setAlertState("ready"); })
      .catch((error: unknown) => {
        if (!(error instanceof DOMException && error.name === "AbortError")) setAlertState("error");
      });
    return () => controller.abort();
  }, [appliedFilters, reload]);

  useEffect(() => {
    if (!selectedChainId || view !== "chains") return;
    const controller = new AbortController();
    setChainState("loading");
    getChain(selectedChainId, controller.signal)
      .then((data) => { setChainDetail(data); setChainState("ready"); })
      .catch((error: unknown) => {
        if (!(error instanceof DOMException && error.name === "AbortError")) setChainState("error");
      });
    return () => controller.abort();
  }, [selectedChainId, view, reload]);

  const openChain = (id: string) => { setSelectedChainId(id); setView("chains"); };
  const rules = useMemo(() => [...new Map(alerts.map((alert) => [alert.rule_id, alert.rule_name])).entries()], [alerts]);
  const onGraphNode = useCallback((id: string) => {
    setSelectedNode(chainDetail?.nodes.find((item) => item.node_id === id) ?? null);
  }, [chainDetail]);

  if (authRequired) {
    return <LoginPage onAuthenticated={() => { setAuthenticated(true); setAuthRequired(false); setReload((value) => value + 1); }} />;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><div className="brand-mark"><ShieldAlert size={20} /></div><div><strong>AI-Agent</strong><span>Security Monitor</span></div></div>
        <nav aria-label="主导航">
          <button className={view === "overview" ? "active" : ""} onClick={() => setView("overview")}><BarChart3 size={18} />总览</button>
          <button className={view === "alerts" ? "active" : ""} onClick={() => setView("alerts")}><AlertTriangle size={18} />告警<span className="nav-count">{overview?.alert_count ?? 0}</span></button>
          <button className={view === "chains" ? "active" : ""} onClick={() => setView("chains")}><GitBranch size={18} />攻击链<span className="nav-count">{overview?.chain_count ?? 0}</span></button>
        </nav>
        <div className="service-status"><span className={baseState === "error" ? "offline" : ""} /><div><strong>{baseState === "error" ? "服务异常" : "监测运行中"}</strong><small>LOCAL ENVIRONMENT</small></div></div>
      </aside>

      <main className="main">
        <header className="topbar"><div><p className="eyebrow">ANALYSIS CONSOLE</p><h1>{view === "overview" ? "安全态势总览" : view === "alerts" ? "检测告警" : "攻击链分析"}</h1></div><div className="topbar-actions"><button className="icon-button" onClick={() => setReload((value) => value + 1)} aria-label="刷新数据" title="刷新数据"><RefreshCw size={18} /></button>{authenticated && <button className="icon-button" onClick={() => { sessionStorage.removeItem("admin_access_token"); setAuthenticated(false); setAuthRequired(true); }} aria-label="退出登录" title="退出登录"><LogOut size={18} /></button>}</div></header>

        {view === "overview" && <OverviewPage state={baseState} overview={overview} chains={chains} retry={() => setReload((value) => value + 1)} openChain={openChain} openChains={() => setView("chains")} />}
        {view === "alerts" && <AlertsPage alerts={alerts} state={alertState} filters={filters} setFilters={setFilters} rules={rules} apply={() => setAppliedFilters(filters)} retry={() => setReload((value) => value + 1)} select={setSelectedAlert} />}
        {view === "chains" && <ChainsPage chains={chains} baseState={baseState} selectedId={selectedChainId} selectId={setSelectedChainId} state={chainState} detail={chainDetail} retry={() => setReload((value) => value + 1)} onGraphNode={onGraphNode} selectEvent={setSelectedEvent} />}
      </main>

      {selectedAlert && <AlertDrawer alert={selectedAlert} onClose={() => setSelectedAlert(null)} />}
      {selectedEvent && <EventDrawer event={selectedEvent} onClose={() => setSelectedEvent(null)} />}
      {selectedNode && chainDetail && <NodeDrawer node={selectedNode} detail={chainDetail} onClose={() => setSelectedNode(null)} onEvent={(event) => { setSelectedNode(null); setSelectedEvent(event); }} />}
    </div>
  );
}

function LoginPage({ onAuthenticated }: { onAuthenticated: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  return <main className="login-page">
    <form className="login-panel" onSubmit={(event) => {
      event.preventDefault();
      setSubmitting(true);
      setError("");
      login(username, password)
        .then((result) => {
          sessionStorage.setItem("admin_access_token", result.access_token);
          onAuthenticated();
        })
        .catch(() => setError("用户名或密码错误"))
        .finally(() => setSubmitting(false));
    }}>
      <div className="brand-mark"><ShieldAlert size={22} /></div>
      <div><p className="eyebrow">SECURE CONSOLE</p><h1>管理员登录</h1></div>
      <label>用户名<input autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} required /></label>
      <label>密码<input type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required /></label>
      {error && <p className="login-error" role="alert">{error}</p>}
      <button type="submit" disabled={submitting}><LogIn size={17} />{submitting ? "正在验证" : "登录"}</button>
    </form>
  </main>;
}

function OverviewPage({ state, overview, chains, retry, openChain, openChains }: { state: LoadState; overview: Overview | null; chains: ChainSummary[]; retry: () => void; openChain: (id: string) => void; openChains: () => void }) {
  if (state === "error") return <section className="page-content"><ErrorState retry={retry} /></section>;
  if (state === "loading" || !overview) return <section className="page-content"><LoadingRows /></section>;
  const risky = chains.filter((chain) => ["high", "critical"].includes(chain.risk.level));
  return <section className="page-content">
    <div className="metric-grid">
      <article><div className="metric-icon teal"><Activity size={19} /></div><span>事件总数</span><strong>{overview.event_count.toLocaleString()}</strong><small>{Object.entries(overview.source_counts).map(([source, count]) => `${sourceLabel[source]} ${count}`).join(" · ")}</small></article>
      <article><div className="metric-icon amber"><AlertTriangle size={19} /></div><span>检测告警</span><strong>{overview.alert_count.toLocaleString()}</strong><small>严重告警 {overview.critical_alert_count}</small></article>
      <article className={overview.high_risk_chain_count ? "metric-danger" : ""}><div className="metric-icon red"><ShieldAlert size={19} /></div><span>高危攻击链</span><strong>{overview.high_risk_chain_count}</strong><small>高风险及严重等级</small></article>
      <article><div className="metric-icon blue"><GitBranch size={19} /></div><span>关联攻击链</span><strong>{overview.chain_count}</strong><small>跨源行为关联结果</small></article>
    </div>
    <div className="overview-grid">
      <section className="panel trend-panel"><div className="panel-heading"><div><p className="eyebrow">ACTIVITY TREND</p><h2>事件与告警趋势</h2></div><span>最近 7 天</span></div><TrendChart data={overview.trend} /></section>
      <section className="panel risk-panel"><div className="panel-heading"><div><p className="eyebrow">HIGH RISK CHAINS</p><h2>优先调查</h2></div><button className="text-button" onClick={openChains}>查看全部<ChevronRight size={15} /></button></div><div className="risk-list">{risky.slice(0, 4).map((chain) => <button key={chain.chain_id} onClick={() => openChain(chain.chain_id)}><span className={`risk-score ${chain.risk.level}`}>{chain.risk.score}</span><span><strong>{chain.stages.map((stage) => stageLabel[stage]).join(" → ")}</strong><small>{chain.event_ids.length} 个事件 · 置信度 {chain.confidence}%</small></span><ChevronRight size={16} /></button>)}{risky.length === 0 && <EmptyState title="暂无高危攻击链" detail="当前关联行为未达到高风险阈值" />}</div></section>
    </div>
  </section>;
}

type Filters = typeof emptyFilters;
function AlertsPage({ alerts, state, filters, setFilters, rules, apply, retry, select }: { alerts: Alert[]; state: LoadState; filters: Filters; setFilters: (value: Filters) => void; rules: [string, string][]; apply: () => void; retry: () => void; select: (alert: Alert) => void }) {
  return <section className="page-content">
    <form className="filters" onSubmit={(event) => { event.preventDefault(); apply(); }}>
      <label>等级<select value={filters.severity} onChange={(event) => setFilters({ ...filters, severity: event.target.value })}><option value="">全部等级</option><option value="critical">严重</option><option value="high">高</option><option value="medium">中</option><option value="low">低</option></select></label>
      <label>规则<select value={filters.rule} onChange={(event) => setFilters({ ...filters, rule: event.target.value })}><option value="">全部规则</option>{rules.map(([id, name]) => <option value={id} key={id}>{name}</option>)}</select></label>
      <label>来源<select value={filters.source} onChange={(event) => setFilters({ ...filters, source: event.target.value })}><option value="">全部来源</option><option value="agent">Agent</option><option value="host">主机</option><option value="web">Web</option></select></label>
      <label>开始时间<input type="datetime-local" value={filters.start} onChange={(event) => setFilters({ ...filters, start: event.target.value })} /></label>
      <label>结束时间<input type="datetime-local" value={filters.end} onChange={(event) => setFilters({ ...filters, end: event.target.value })} /></label>
      <button type="submit"><Search size={16} />筛选</button>
    </form>
    <section className="panel table-panel"><div className="panel-heading"><div><p className="eyebrow">DETECTION RESULTS</p><h2>告警列表</h2></div><span>{alerts.length} 条结果</span></div>{state === "loading" ? <LoadingRows /> : state === "error" ? <ErrorState retry={retry} /> : alerts.length === 0 ? <EmptyState title="没有匹配的告警" detail="调整筛选条件或等待新的检测结果" /> : <div className="table-scroll"><table><thead><tr><th>等级</th><th>检测规则</th><th>来源</th><th>MITRE</th><th>证据</th><th>发生时间</th><th /></tr></thead><tbody>{alerts.map((alert) => <tr key={alert.alert_id} onClick={() => select(alert)}><td><Badge level={alert.severity_label} /></td><td><strong>{alert.rule_name}</strong><small>{alert.rule_id}</small></td><td>{alert.sources.map((source) => <span className="source-chip" key={source}>{sourceLabel[source]}</span>)}</td><td>{alert.mitre.map((item) => <code key={item}>{item}</code>)}</td><td>{alert.evidence_event_ids.length} 个事件</td><td>{formatDate(alert.end_time)}</td><td><ChevronRight size={16} /></td></tr>)}</tbody></table></div>}</section>
  </section>;
}

function ChainsPage({ chains, baseState, selectedId, selectId, state, detail, retry, onGraphNode, selectEvent }: { chains: ChainSummary[]; baseState: LoadState; selectedId: string | null; selectId: (id: string) => void; state: LoadState; detail: ChainDetail | null; retry: () => void; onGraphNode: (id: string) => void; selectEvent: (event: EventRecord) => void }) {
  return <section className="page-content chain-layout">
    <aside className="chain-list panel"><div className="panel-heading"><div><p className="eyebrow">CORRELATED CHAINS</p><h2>攻击链</h2></div><span>{chains.length}</span></div>{baseState === "loading" ? <LoadingRows /> : chains.length === 0 ? <EmptyState title="暂无攻击链" detail="至少两个相关事件可生成攻击链" /> : chains.map((chain) => <button className={selectedId === chain.chain_id ? "active" : ""} key={chain.chain_id} onClick={() => selectId(chain.chain_id)}><span className={`risk-score ${chain.risk.level}`}>{chain.risk.score}</span><span><strong>{chain.stages.map((stage) => stageLabel[stage]).join(" → ")}</strong><small>{formatDate(chain.end_time)} · {chain.event_ids.length} 个事件</small></span></button>)}</aside>
    <div className="chain-detail">{state === "loading" ? <LoadingRows /> : state === "error" ? <ErrorState retry={retry} /> : !detail ? <EmptyState title="选择一条攻击链" detail="关联分析结果将在此显示" /> : <>
      <section className="chain-hero"><div><div className="chain-title-row"><Badge level={detail.risk.level} /><span>置信度 {detail.confidence}%</span><span>持续 {duration(detail.start_time, detail.end_time)}</span></div><h2>{detail.stages.map((stage) => stageLabel[stage]).join(" → ")}</h2><p>{formatDate(detail.start_time)} 至 {formatDate(detail.end_time)} · {detail.events.length} 个事件 · {detail.alert_ids.length} 条告警</p></div><div className={`score-ring ${detail.risk.level}`}><strong>{detail.risk.score}</strong><span>风险分</span></div></section>
      <section className="panel stage-panel"><div className="panel-heading"><div><p className="eyebrow">MITRE ATTACK FLOW</p><h2>攻击阶段</h2></div></div><div className="stage-flow">{Object.keys(stageLabel).map((stage, index) => <div className={detail.stages.includes(stage) ? "hit" : ""} key={stage}><span>{index + 1}</span><strong>{stageLabel[stage]}</strong></div>)}</div></section>
      <section className="panel graph-panel"><div className="panel-heading"><div><p className="eyebrow">ENTITY RELATIONSHIP</p><h2>关系图</h2></div><span>{detail.nodes.length} 实体 · {detail.edges.length} 关系</span></div><ChainGraph detail={detail} onNode={onGraphNode} /></section>
      <section className="panel"><div className="panel-heading"><div><p className="eyebrow">EVENT TIMELINE</p><h2>行为时间线</h2></div></div><div className="timeline">{detail.events.map((item) => <button key={item.event_id} onClick={() => selectEvent(item)}><span className={`source-dot ${item.source}`} /><time>{formatDate(item.timestamp)}</time><span><strong>{item.event_type}</strong><small>{item.actor?.id ?? "未知主体"} · {item.action ?? "unknown"} · {item.object?.name ?? item.object?.id ?? "未知对象"}</small></span><ChevronRight size={16} /></button>)}</div></section>
    </>}</div>
  </section>;
}

function DetailSection({ title, children }: { title: string; children: React.ReactNode }) { return <section className="detail-section"><h3>{title}</h3>{children}</section>; }

function AlertDrawer({ alert, onClose }: { alert: Alert; onClose: () => void }) {
  return <DetailDrawer title={alert.rule_name} onClose={onClose}><div className="detail-meta"><Badge level={alert.severity_label} /><span>{alert.severity} 分</span><span>{alert.sources.map((source) => sourceLabel[source]).join(" / ")}</span></div><DetailSection title="检测信息"><dl><dt>规则 ID</dt><dd>{alert.rule_id}</dd><dt>时间范围</dt><dd>{formatDate(alert.start_time)} - {formatDate(alert.end_time)}</dd><dt>MITRE 技术</dt><dd>{alert.mitre.join(", ")}</dd></dl></DetailSection><DetailSection title="证据事件"><div className="id-list">{alert.evidence_event_ids.map((id) => <code key={id}>{id}</code>)}</div></DetailSection><DetailSection title="命中依据"><pre>{JSON.stringify(alert.evidence, null, 2)}</pre></DetailSection></DetailDrawer>;
}

function EventDrawer({ event, onClose }: { event: EventRecord; onClose: () => void }) {
  return <DetailDrawer title={`${event.event_type} 事件`} onClose={onClose}><div className="detail-meta"><span className="source-chip">{sourceLabel[event.source]}</span><span>{formatDate(event.timestamp)}</span><span>{event.result}</span></div><DetailSection title="事件上下文"><dl><dt>事件 ID</dt><dd className="mono">{event.event_id}</dd><dt>主体</dt><dd>{event.actor ? `${event.actor.type}: ${event.actor.id}` : "-"}</dd><dt>动作</dt><dd>{event.action ?? "-"}</dd><dt>对象</dt><dd>{event.object ? `${event.object.type}: ${event.object.name ?? event.object.id}` : "-"}</dd><dt>Trace ID</dt><dd>{event.trace_id ?? "-"}</dd><dt>父事件</dt><dd className="mono">{event.parent_event_id ?? "-"}</dd></dl></DetailSection><DetailSection title="原始事件"><pre>{JSON.stringify(event, null, 2)}</pre></DetailSection></DetailDrawer>;
}

function NodeDrawer({ node, detail, onClose, onEvent }: { node: ChainNode; detail: ChainDetail; onClose: () => void; onEvent: (event: EventRecord) => void }) {
  const events = detail.events.filter((event) => node.event_ids.includes(event.event_id));
  const edges = detail.edges.filter((edge) => edge.source_node_id === node.node_id || edge.target_node_id === node.node_id);
  return <DetailDrawer title={node.label} onClose={onClose}><div className="detail-meta"><span className="source-chip">{node.entity_type}</span><span>{stageLabel[node.stage] ?? node.stage}</span><span>{events.length} 条证据</span></div><DetailSection title="关联原因"><ul className="reason-list">{edges.map((edge) => <li key={edge.edge_id}><strong>{edge.relationship}</strong><span>{edge.reason} · 置信度 {edge.confidence}%</span></li>)}</ul></DetailSection><DetailSection title="原始证据">{events.map((event) => <button className="evidence-button" key={event.event_id} onClick={() => onEvent(event)}><span><strong>{event.event_type}</strong><small>{formatDate(event.timestamp)} · {event.action}</small></span><ChevronRight size={16} /></button>)}</DetailSection><DetailSection title="评分解释"><div className="factor-list">{Object.entries(detail.risk.breakdown).map(([key, factor]) => <div key={key}><span><strong>{factorLabel[key] ?? key}</strong><small>权重 {Math.round(factor.weight * 100)}%</small></span><span>{factor.score}<small>+{factor.contribution}</small></span></div>)}</div><ul className="reason-list">{detail.risk.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul></DetailSection><DetailSection title="处置建议"><ol className="recommendations">{detail.risk.recommendations.map((item) => <li key={item}>{item}</li>)}</ol></DetailSection></DetailDrawer>;
}
