import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { cn } from "../../lib/utils";

interface WeatherMapData {
  time: string;
  [key: string]: string | number;
}

interface ThreatWeatherMapProps {
  data: WeatherMapData[];
  threatClasses: { key: string; name: string; color: string }[];
  height?: number;
  className?: string;
}

export function ThreatWeatherMap({ data, threatClasses, height = 200, className }: ThreatWeatherMapProps) {
  const maxValue = Math.max(1, ...data.flatMap(d => threatClasses.map(tc => Number(d[tc.key]) || 0)));

  return (
    <div className={cn("w-full relative", className)} style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 5, right: 10, bottom: 5, left: 0 }}>
          <defs>
            {threatClasses.map((tc) => (
              <linearGradient key={tc.key} id={`weather-${tc.key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={tc.color} stopOpacity={0.4} />
                <stop offset="100%" stopColor={tc.color} stopOpacity={0.05} />
              </linearGradient>
            ))}
          </defs>
          
          <CartesianGrid strokeDasharray="0" vertical={false} horizontal={false} />
          
          <XAxis
            type="category"
            dataKey="time"
            axisLine={false}
            tickLine={false}
            tick={false}
            interval="preserveStartEnd"
          />
          
          <YAxis
            type="number"
            domain={[0, maxValue * 1.1]}
            axisLine={false}
            tickLine={false}
            tick={false}
          />
          
          <Tooltip
            content={({ active, payload, label }) => {
              if (active && payload && payload.length) {
                return (
                  <div className="bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)] rounded-[6px] p-3 shadow-lg min-w-[180px]">
                    <p className="text-xs text-[var(--color-text-muted)] font-mono mb-2">{label}</p>
                    {payload.map((entry, i) => {
                      const tc = threatClasses.find(t => t.key === entry.dataKey) || threatClasses[i % threatClasses.length];
                      return (
                        <div key={i} className="flex items-center gap-2 text-sm">
                          <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: tc.color }} />
                          <span className="text-[var(--color-text-secondary)] text-xs truncate">{tc.name}</span>
                          <span className="font-mono tabular-nums text-[var(--color-text-primary)] ml-auto text-xs">
                            {(entry.value as number).toLocaleString()}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                );
              }
              return null;
            }}
          />
          
          {threatClasses.map((tc) => (
            <Area
              key={tc.key}
              type="monotone"
              dataKey={tc.key}
              stroke={tc.color}
              strokeWidth={1}
              fill={`url(#weather-${tc.key})`}
              fillOpacity={1}
              dot={false}
              activeDot={false}
              animationDuration={600}
              animationEasing="ease-out"
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>

      <div className="absolute bottom-1 left-0 right-0 flex items-center justify-center pointer-events-none">
        <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-0.5">
          {threatClasses.map((tc) => (
            <div key={tc.key} className="flex items-center gap-1">
              <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: tc.color }} />
              <span className="text-[9px] font-medium text-[var(--color-text-muted)] whitespace-nowrap">
                {tc.name}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div className="absolute bottom-1 left-2 flex items-center pointer-events-none">
        <span className="text-[9px] text-[var(--color-text-muted)] font-mono">-60m</span>
      </div>
      <div className="absolute bottom-1 right-2 flex items-center pointer-events-none">
        <span className="text-[9px] text-[var(--color-text-muted)] font-mono">NOW</span>
      </div>
    </div>
  );
}
