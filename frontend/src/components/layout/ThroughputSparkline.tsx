import { useEffect, useState } from "react";
import { cn } from "../../lib/utils";

interface ThroughputSparklineProps {
  data?: number[];
  color?: string;
  height?: number;
}

export function ThroughputSparkline({ data, color = "#00D9FF", height = 14 }: ThroughputSparklineProps) {
  const [sparklineData, setSparklineData] = useState<number[]>(data || generateInitialData());

  useEffect(() => {
    const id = window.setInterval(() => {
      setSparklineData((prev) => {
        const last = prev[prev.length - 1] ?? 0.55;
        const next = Math.max(0.28, Math.min(0.95, last + (Math.random() - 0.5) * 0.12));
        return [...prev.slice(1), next];
      });
    }, 900);
    return () => clearInterval(id);
  }, []);

  const w = 1200;
  const h = height;
  const max = 1;
  const min = 0;
  const pts = sparklineData
    .map((v, i) => {
      const x = (i / Math.max(1, sparklineData.length - 1)) * w;
      const y = h - ((v - min) / (max - min)) * (h - 2) - 1;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");

  return (
    <div
      className={cn("w-full relative border-b border-[var(--color-border-subtle)]")}
      style={{ height, background: "var(--color-bg-deep)" }}
      aria-hidden="true"
    >
      <svg width="100%" height={height} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="block">
        <polyline fill="none" stroke={color} strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round" points={pts} opacity="0.9" />
      </svg>
    </div>
  );
}

function generateInitialData(length = 160): number[] {
  let v = 0.55;
  return Array.from({ length }, () => {
    v = Math.max(0.3, Math.min(0.9, v + (Math.random() - 0.5) * 0.1));
    return v;
  });
}
