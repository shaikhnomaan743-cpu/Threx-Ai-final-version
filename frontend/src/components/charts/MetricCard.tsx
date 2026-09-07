import { cn } from "../../lib/utils";
import { TrendingUp, TrendingDown, Minus } from "lucide-react";
import { CountUp } from "../ui/CountUp";

interface MetricCardProps {
  label: string;
  value: string | number;
  unit?: string;
  trend?: number;
  trendLabel?: string;
  icon?: React.ReactNode;
  className?: string;
  loading?: boolean;
  accent?: string;
}

export function MetricCard({ label, value, unit, trend, trendLabel, icon, className, loading, accent }: MetricCardProps) {
  const trendColor = trend === undefined ? "var(--color-text-muted)" : trend > 0 ? "var(--color-success)" : trend < 0 ? "var(--color-danger)" : "var(--color-text-muted)";
  const TrendIcon = trend === undefined ? Minus : trend > 0 ? TrendingUp : TrendingDown;
  const numeric = typeof value === "number";

  return (
    <div
      className={cn("card card-hover card-inner-highlight p-4 min-w-0 overflow-hidden", className)}
      style={{ borderLeft: `2px solid ${accent ?? "var(--color-accent-cyan)"}` }}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <p className="metric-label truncate">{label}</p>
          <p className={cn("mt-2 tabular-nums font-mono font-light text-[clamp(1.4rem,1.8vw,2rem)] leading-none whitespace-nowrap", loading && "animate-pulse")}>
            {numeric ? <CountUp end={value} duration={700} /> : value}
            {unit && <span className="ml-1.5 text-sm font-sans font-medium text-[var(--color-text-muted)]">{unit}</span>}
          </p>
          {(trend !== undefined || trendLabel) && (
            <div className="flex items-center gap-1.5 mt-3 text-xs">
              <TrendIcon className="w-3 h-3" style={{ color: trendColor }} aria-hidden="true" />
              <span className="font-medium tabular-nums" style={{ color: trendColor }}>
                {trend !== undefined ? (trend > 0 ? "+" : "") + trend.toFixed(1) + "%" : "—"}
              </span>
              {trendLabel && <span className="text-[var(--color-text-muted)]">{trendLabel}</span>}
            </div>
          )}
        </div>
        {icon && <div className="text-[var(--color-text-muted)] flex-shrink-0">{icon}</div>}
      </div>
    </div>
  );
}
