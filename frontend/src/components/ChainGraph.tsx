import { useEffect, useRef } from "react";

import { init } from "../charts";
import { stageLabel } from "../format";
import type { ChainDetail } from "../types";

const colors = ["#387f8c", "#9f6b28", "#b8484e", "#7f5ba1", "#24725f", "#525e69"];

export function ChainGraph({ detail, onNode }: { detail: ChainDetail; onNode: (id: string) => void }) {
  const element = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!element.current) return;
    const chart = init(element.current, undefined, { renderer: "svg" });
    const stages = [...new Set(detail.nodes.map((node) => node.stage))];
    chart.setOption({
      animationDurationUpdate: 300,
      tooltip: { formatter: (item: { data: { tooltip?: string } }) => item.data.tooltip ?? "" },
      series: [{
        type: "graph",
        layout: "force",
        roam: true,
        draggable: true,
        force: { repulsion: 250, edgeLength: [75, 150], gravity: 0.12 },
        label: { show: true, position: "bottom", color: "#303a3e", fontSize: 11 },
        lineStyle: { color: "#9aa6aa", width: 1.3, curveness: 0.08 },
        emphasis: { focus: "adjacency", lineStyle: { width: 3 } },
        categories: stages.map((stage, index) => ({ name: stageLabel[stage] ?? stage, itemStyle: { color: colors[index % colors.length] } })),
        data: detail.nodes.map((node) => ({
          id: node.node_id,
          name: node.label,
          symbolSize: 30 + Math.min(node.event_ids.length * 3, 16),
          category: stages.indexOf(node.stage),
          tooltip: `${node.entity_type}: ${node.entity_id}<br/>${stageLabel[node.stage] ?? node.stage}<br/>${node.event_ids.length} 条证据`,
        })),
        links: detail.edges.map((edge) => ({ source: edge.source_node_id, target: edge.target_node_id, value: edge.relationship })),
      }],
    });
    chart.on("click", (params) => {
      const data = params.data as { id?: string } | null;
      if (params.dataType === "node" && data?.id) onNode(data.id);
    });
    const resize = () => chart.resize();
    window.addEventListener("resize", resize);
    return () => {
      window.removeEventListener("resize", resize);
      chart.dispose();
    };
  }, [detail, onNode]);

  return <div className="chain-graph" ref={element} role="img" aria-label="攻击链实体关系图" />;
}
