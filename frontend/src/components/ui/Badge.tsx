import { forwardRef, HTMLAttributes } from "react";
import { cn } from "../../lib/utils";

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  variant?: "default" | "ddos" | "c2" | "dga" | "tls" | "recon" | "exfil" | 
            "critical" | "high" | "medium" | "low" | "info" | "success" | "warning" | "danger";
  size?: "sm" | "md";
  dot?: boolean;
}

export const Badge = forwardRef<HTMLSpanElement, BadgeProps>(
  ({ className, variant = "default", size = "md", dot, children, ...props }, ref) => {
    const variants = {
      default: "bg-[var(--color-bg-elevated-2)] text-[var(--color-text-secondary)] border border-[var(--color-border-card)]",
      ddos: "bg-[var(--color-threat-ddos)]/15 text-[var(--color-threat-ddos)] border border-[var(--color-threat-ddos)]/30",
      c2: "bg-[var(--color-threat-c2)]/15 text-[var(--color-threat-c2)] border border-[var(--color-threat-c2)]/30",
      dga: "bg-[var(--color-threat-dga)]/15 text-[var(--color-threat-dga)] border border-[var(--color-threat-dga)]/30",
      tls: "bg-[var(--color-threat-tls)]/15 text-[var(--color-threat-tls)] border border-[var(--color-threat-tls)]/30",
      recon: "bg-[var(--color-threat-recon)]/15 text-[var(--color-threat-recon)] border border-[var(--color-threat-recon)]/30",
      exfil: "bg-[var(--color-threat-exfil)]/15 text-[var(--color-threat-exfil)] border border-[var(--color-threat-exfil)]/30",
      critical: "bg-[var(--color-danger)]/15 text-[var(--color-danger)] border border-[var(--color-danger)]/30",
      high: "bg-[var(--color-warning)]/15 text-[var(--color-warning)] border border-[var(--color-warning)]/30",
      medium: "bg-[var(--color-accent-cyan)]/15 text-[var(--color-accent-cyan)] border border-[var(--color-accent-cyan)]/30",
      low: "bg-[var(--color-success)]/15 text-[var(--color-success)] border border-[var(--color-success)]/30",
      info: "bg-[var(--color-text-muted)]/15 text-[var(--color-text-muted)] border border-[var(--color-text-muted)]/30",
      success: "bg-[var(--color-success)]/15 text-[var(--color-success)] border border-[var(--color-success)]/30",
      warning: "bg-[var(--color-warning)]/15 text-[var(--color-warning)] border border-[var(--color-warning)]/30",
      danger: "bg-[var(--color-danger)]/15 text-[var(--color-danger)] border border-[var(--color-danger)]/30",
    };

    const sizes = {
      sm: "px-2 py-0.5 text-[10px]",
      md: "px-2.5 py-0.5 text-xs",
    };

    return (
      <span
        ref={ref}
        className={cn(
          "inline-flex items-center gap-1.5 rounded-[4px] font-medium tabular-nums font-mono",
          variants[variant],
          sizes[size],
          className
        )}
        {...props}
      >
        {dot && (
          <span className={cn("w-1.5 h-1.5 rounded-full", {
            "bg-[var(--color-threat-ddos)]": variant === "ddos",
            "bg-[var(--color-threat-c2)]": variant === "c2",
            "bg-[var(--color-threat-dga)]": variant === "dga",
            "bg-[var(--color-threat-tls)]": variant === "tls",
            "bg-[var(--color-threat-recon)]": variant === "recon",
            "bg-[var(--color-threat-exfil)]": variant === "exfil",
            "bg-[var(--color-danger)]": variant === "critical",
            "bg-[var(--color-warning)]": variant === "high",
            "bg-[var(--color-accent-cyan)]": variant === "medium",
            "bg-[var(--color-success)]": variant === "low",
            "bg-[var(--color-text-muted)]": variant === "info",
          })} />
        )}
        {children}
      </span>
    );
  }
);

Badge.displayName = "Badge";