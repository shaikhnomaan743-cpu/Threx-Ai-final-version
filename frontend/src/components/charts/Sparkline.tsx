import { cn } from "../../lib/utils";

interface SparklineProps {
  data: number[];
  color?: string;
  height?: number;
  className?: string;
  fill?: boolean;
}

export function Sparkline({ data, color = "var(--color-accent-cyan)", height = 30, className, fill = false }: SparklineProps) {
  if (!data || data.length < 2) return null;

  const min = Math.min(...data);
  const max = Math.max(...data);
  // Pad the domain so a steady (constant) series renders mid-chart
  // instead of hugging the bottom edge.
  const span = max - min;
  const pad = span > 0 ? span * 0.25 : Math.max(Math.abs(max) * 0.25, 1);
  const lo = min - pad;
  const hi = max + pad;
  const range = hi - lo || 1;

  const coords = data.map((value, index) => {
    const x = (index / (data.length - 1)) * 100;
    const y = 100 - ((value - lo) / range) * 100;
    return { x, y };
  });
  const points = coords.map(p => `${p.x},${p.y}`).join(" ");
  const area = `0,100 ${points} 100,100`;

  return (
    <svg
      viewBox="0 0 100 100"
      preserveAspectRatio="none"
      className={cn("w-full h-full", className)}
      style={{ height: `${height}px` }}
    >
      {fill && (
        <polygon
          points={area}
          fill={color}
          opacity="0.12"
        />
      )}
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}