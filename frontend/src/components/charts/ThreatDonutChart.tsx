import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";
import { cn } from "../../lib/utils";

interface ThreatDonutData {
  name: string;
  value: number;
  color: string;
}

interface ThreatDonutChartProps {
  data: ThreatDonutData[];
  size?: number;
  className?: string;
}

export function ThreatDonutChart({ data, size = 200, className }: ThreatDonutChartProps) {
  const total = data.reduce((sum, d) => sum + d.value, 0);
  const inner = size * 0.36;
  const outer = size * 0.48;

  return (
    <div className={cn("flex flex-col items-center gap-3", className)}>
      <div className="relative" style={{ width: size, height: size }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={inner}
              outerRadius={outer}
              paddingAngle={2}
              dataKey="value"
              nameKey="name"
              label={false}
              startAngle={90}
              endAngle={-270}
              stroke="transparent"
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const item = payload[0].payload as ThreatDonutData;
                  const percent = total > 0 ? ((item.value / total) * 100).toFixed(1) : "0";
                  return (
                    <div className="bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)] rounded-[6px] p-3">
                      <div className="flex items-center gap-2 mb-1">
                        <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                        <span className="font-medium text-[var(--color-text-primary)]">{item.name}</span>
                      </div>
                      <div className="text-sm text-[var(--color-text-secondary)]">
                        <span className="font-mono tabular-nums text-[var(--color-text-primary)]">{item.value.toLocaleString()}</span>
                        <span className="text-[var(--color-text-muted)] ml-2">({percent}%)</span>
                      </div>
                    </div>
                  );
                }
                return null;
              }}
            />
          </PieChart>
        </ResponsiveContainer>

        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div className="text-center">
            <p className="text-[32px] leading-none font-light tabular-nums font-mono text-[var(--color-text-primary)]">{total.toLocaleString()}</p>
            <p className="text-[10px] text-[var(--color-text-muted)] uppercase tracking-wider mt-2">ACTIVE THREATS</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-x-4 gap-y-1 w-full max-w-[280px]">
        {data.map((entry) => (
          <div key={entry.name} className="flex items-center gap-1.5 min-w-0">
            <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: entry.color }} />
            <span className="text-[10px] text-[var(--color-text-secondary)] truncate">{entry.name}</span>
            <span className="text-[10px] font-mono tabular-nums text-[var(--color-text-primary)] ml-auto flex-shrink-0">{entry.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
