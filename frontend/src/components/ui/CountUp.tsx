import { useEffect, useState } from "react";
import { cn } from "../../lib/utils";

interface CountUpProps {
  end: number;
  start?: number;
  duration?: number;
  decimals?: number;
  prefix?: string;
  suffix?: string;
  className?: string;
  onComplete?: () => void;
}

export function CountUp({ 
  end, 
  start = 0, 
  duration = 800, 
  decimals = 0, 
  prefix = "", 
  suffix = "", 
  className,
  onComplete 
}: CountUpProps) {
  const [count, setCount] = useState(start);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    const startTime = Date.now();
    const endTime = startTime + duration;

    const animate = () => {
      const now = Date.now();
      const progress = Math.min((now - startTime) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = start + (end - start) * eased;
      setCount(current);

      if (progress < 1) {
        requestAnimationFrame(animate);
      } else {
        setCount(end);
        onComplete?.();
      }
    };

    requestAnimationFrame(animate);
  }, [end, start, duration, onComplete]);

  const formatted = count.toLocaleString(undefined, {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  });

  return (
    <span className={cn("tabular-nums font-mono", className)}>
      {prefix}{formatted}{suffix}
    </span>
  );
}