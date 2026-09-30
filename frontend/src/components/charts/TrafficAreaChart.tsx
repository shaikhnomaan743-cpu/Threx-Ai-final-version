import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { cn } from "../../lib/utils";

interface TrafficAreaData {
  time: string;
  [key: string]: string | number;
}

interface TrafficAreaChartProps {
  data: TrafficAreaData[];
  series: { key: string; name: string; color: string }[];
  height?: number;
  className?: string;
  showLegend?: boolean;
}

export function TrafficAreaChart({ data, series, height = 280, className, showLegend = true }: TrafficAreaChartProps) {
  const colors = series.map(s => s.color);

  return (
    <div className={cn("w-full", className)} style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 10, right: 20, bottom: 10, left: 0 }}>
          <defs>
{series.map((s) => (
              <linearGradient key={s.key} id={`color-${s.key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={s.color} stopOpacity={0.25} />
                <stop offset="95%" stopColor={s.color} stopOpacity={0} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid strokeDasharray="4 4" stroke="#22262F" vertical={false} />
          <XAxis
            dataKey="time"
            axisLine={false}
            tickLine={false}
            tick={{ fill: "var(--color-text-muted)", fontSize: 11, fontFamily: "var(--font-mono)" }}
            interval="preserveStartEnd"
            dy={8}
          />
          <YAxis
            axisLine={false}
            tickLine={false}
            tick={{ fill: "var(--color-text-muted)", fontSize: 11, fontFamily: "var(--font-mono)" }}
            tickFormatter={(value) => {
              if (value >= 1e6) return (value / 1e6).toFixed(1) + "M";
              if (value >= 1e3) return (value / 1e3).toFixed(1) + "K";
              return value.toString();
            }}
            dx={-8}
          />
          <Tooltip
            content={({ active, payload, label }) => {
              if (active && payload && payload.length) {
                return (
                  <div className="bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)] rounded-[6px] p-3 shadow-lg">
                    <p className="text-xs text-[var(--color-text-muted)] font-mono mb-2">{label}</p>
                    {payload.map((entry, i) => (
                      <div key={i} className="flex items-center gap-2 text-sm">
                        <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: colors[i % colors.length] }} />
                        <span className="text-[var(--color-text-secondary)]">{series[i % series.length].name}</span>
                        <span className="font-mono tabular-nums text-[var(--color-text-primary)] ml-auto">
                          {(entry.value as number).toLocaleString()}
                        </span>
                      </div>
                    ))}
                  </div>
                );
              }
              return null;
            }}
          />
          {series.map((s, i) => (
            <Area
              key={s.key}
              type="monotone"
              dataKey={s.key}
              name={s.name}
              stroke={s.color}
              strokeWidth={1.5}
              fillOpacity={1}
              fill={`url(#color-${s.key})`}
              dot={false}
              activeDot={{ r: 4, strokeWidth: 2 }}
              animationDuration={800}
              animationEasing="ease-out"
            />
          ))}
          {showLegend && (
            <Legend
              wrapperStyle={{ paddingTop: 10 }}
              layout="horizontal"
              align="center"
              verticalAlign="bottom"
              iconType="circle"
              iconSize={8}
              formatter={(value) => value}
            />
          )}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
