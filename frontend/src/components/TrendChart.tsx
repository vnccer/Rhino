import { useEffect, useRef } from "react";

import { init } from "../charts";
import type { TrendPoint } from "../types";

export function TrendChart({ data }: { data: TrendPoint[] }) {
  const element = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!element.current) return;
    const chart = init(element.current, undefined, { renderer: "svg" });
    chart.setOption({
      animationDuration: 350,
      color: ["#16a085", "#d84b50"],
      grid: { left: 10, right: 12, top: 28, bottom: 8, containLabel: true },
      tooltip: { trigger: "axis" },
      legend: { top: 0, right: 0, itemWidth: 12, textStyle: { color: "#657176" } },
      xAxis: {
        type: "category",
        boundaryGap: false,
        data: data.map((point) => point.bucket.slice(5)),
        axisLine: { lineStyle: { color: "#d7dddf" } },
        axisLabel: { color: "#758187" },
      },
      yAxis: {
        type: "value",
        minInterval: 1,
        splitLine: { lineStyle: { color: "#edf0f1" } },
        axisLabel: { color: "#758187" },
      },
      series: [
        { name: "事件", type: "line", smooth: true, symbolSize: 7, data: data.map((point) => point.events), areaStyle: { opacity: 0.08 } },
        { name: "告警", type: "line", smooth: true, symbolSize: 7, data: data.map((point) => point.alerts) },
      ],
    });
    const resize = () => chart.resize();
    window.addEventListener("resize", resize);
    return () => {
      window.removeEventListener("resize", resize);
      chart.dispose();
    };
  }, [data]);

  return <div className="chart" ref={element} role="img" aria-label="最近七天事件与告警趋势" />;
}
