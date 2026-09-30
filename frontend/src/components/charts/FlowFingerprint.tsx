import { LineChart, Line, ResponsiveContainer } from "recharts";
import { cn } from "../../lib/utils";

interface FlowFingerprintProps {
  data: number[];
  color?: string;
  width?: number;
  height?: number;
  className?: string;
}

export function FlowFingerprint({ data, color = "var(--color-accent-cyan)", width = 100, height = 30, className }: FlowFingerprintProps) {
  if (!data || data.length === 0) return null;

  const chartData = data.map((value, index) => ({ value, index }));

  return (
    <div className={cn("relative", className)} style={{ width, height }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={chartData} margin={{ top: 0, right: 0, bottom: 0, left: 0 }}>
          <Line
            type="monotone"
            dataKey="value"
            stroke={color}
            strokeWidth={1.5}
            dot={false}
            activeDot={false}
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
