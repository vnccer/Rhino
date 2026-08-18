import { GraphChart, LineChart } from "echarts/charts";
import { GridComponent, LegendComponent, TooltipComponent } from "echarts/components";
import { init, use } from "echarts/core";
import { SVGRenderer } from "echarts/renderers";

use([LineChart, GraphChart, GridComponent, LegendComponent, TooltipComponent, SVGRenderer]);

export { init };
