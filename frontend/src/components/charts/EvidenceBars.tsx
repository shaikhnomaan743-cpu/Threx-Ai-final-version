import { useEffect, useState } from "react";
import { cn } from "../../lib/utils";
import { EvidenceFeature } from "../../types";

interface EvidenceBarsProps {
  features: EvidenceFeature[];
  className?: string;
}

export function EvidenceBars({ features, className }: EvidenceBarsProps) {
  const [animatedWidths, setAnimatedWidths] = useState<number[]>([]);

  useEffect(() => {
    const timer = setTimeout(() => {
      setAnimatedWidths(features.map(f => (f.value / f.maxValue) * 100));
    }, 100);
    return () => clearTimeout(timer);
  }, [features]);

  return (
    <div className={cn("space-y-4", className)}>
      {features.map((feature, index) => {
        const width = animatedWidths[index] || 0;
        const color = getFeatureColor(feature.name);
        
        return (
          <div key={feature.name} className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-[var(--color-text-primary)]">{feature.name}</span>
                <span className="text-xs text-[var(--color-text-muted)] font-mono tabular-nums">
                  {(feature.value * 100).toFixed(0)}%
                </span>
              </div>
              <span className="text-xs text-[var(--color-text-muted)] font-mono tabular-nums">
                Weight: {(feature.weight * 100).toFixed(0)}%
              </span>
            </div>
            <div className="relative h-3 bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)] rounded-[4px] overflow-hidden">
              <div
                className="h-full rounded-[4px] transition-all duration-1000 ease-out"
                style={{
                  width: `${width}%`,
                  background: `linear-gradient(90deg, ${color}, ${color}CC)`,
                  boxShadow: `0 0 8px ${color}80`,
                }}
              />
            </div>
            <p className="text-xs text-[var(--color-text-muted)]">{feature.description}</p>
          </div>
        );
      })}
    </div>
  );
}

function getFeatureColor(name: string): string {
  const lower = name.toLowerCase();
  if (lower.includes("periodicity") || lower.includes("rate")) return "var(--color-threat-c2)";
  if (lower.includes("rarity") || lower.includes("destination")) return "var(--color-threat-recon)";
  if (lower.includes("entropy") || lower.includes("n-gram")) return "var(--color-threat-dga)";
  if (lower.includes("ja3") || lower.includes("cipher") || lower.includes("cert") || lower.includes("sni")) return "var(--color-threat-tls)";
  if (lower.includes("spread") || lower.includes("syn") || lower.includes("target") || lower.includes("timing")) return "var(--color-threat-recon)";
  if (lower.includes("byte") || lower.includes("baseline") || lower.includes("deviation") || lower.includes("transfer")) return "var(--color-threat-exfil)";
  if (lower.includes("symmetry") || lower.includes("diversity") || lower.includes("uniformity")) return "var(--color-threat-ddos)";
  return "var(--color-accent-cyan)";
}
