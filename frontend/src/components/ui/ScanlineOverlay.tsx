import { cn } from "../../lib/utils";

interface ScanlineOverlayProps {
  className?: string;
  speed?: number;
  opacity?: number;
}

export function ScanlineOverlay({ className, speed = 8, opacity = 0.03 }: ScanlineOverlayProps) {
  return (
    <div
      className={cn(
        "absolute inset-0 pointer-events-none overflow-hidden",
        className
      )}
      style={{
        background: `repeating-linear-gradient(
          0deg,
          transparent,
          transparent 2px,
          rgba(0, 0, 0, ${opacity}) 2px,
          rgba(0, 0, 0, ${opacity}) 4px
        )`,
        animation: `scanline ${speed}s linear infinite`,
      }}
    />
  );
}