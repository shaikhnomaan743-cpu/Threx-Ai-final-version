import { useEffect, useState } from "react";
import { Zap } from "lucide-react";
import { cn } from "../../lib/utils";

export function SplashScreen({ onComplete }: { onComplete: () => void }) {
  const [isVisible, setIsVisible] = useState(true);
  const [isFading, setIsFading] = useState(false);

  useEffect(() => {
    // Start fading after 1.5 seconds
    const fadeTimer = setTimeout(() => {
      setIsFading(true);
    }, 1500);

    // Remove after fade completes (0.5s fade duration)
    const completeTimer = setTimeout(() => {
      setIsVisible(false);
      onComplete();
    }, 2000);

    return () => {
      clearTimeout(fadeTimer);
      clearTimeout(completeTimer);
    };
  }, [onComplete]);

  if (!isVisible) return null;

  return (
    <div
      className={cn(
        "fixed inset-0 z-50 flex items-center justify-center bg-[#090a0f]",
        "transition-opacity duration-500 ease-out",
        isFading ? "opacity-0" : "opacity-100"
      )}
    >
      <div className="flex flex-col items-center gap-6">
        {/* Logo */}
        <div className="relative">
          <div className="w-24 h-24 rounded-[16px] bg-[var(--color-accent-cyan)] flex items-center justify-center shadow-[0_0_60px_rgba(0,217,255,0.3)]">
            <Zap className="w-14 h-14 text-[#090a0f]" />
          </div>
          {/* Subtle glow effect */}
          <div className="absolute inset-0 rounded-[16px] bg-[var(--color-accent-cyan)] blur-2xl opacity-20 animate-pulse" />
        </div>

        {/* Branding */}
        <div className="text-center space-y-2">
          <h1 className="text-4xl font-bold text-[var(--color-text-primary)] tracking-tight">
            THREX AI
          </h1>
          <p className="text-sm text-[var(--color-text-secondary)] tracking-widest uppercase">
            Observe · Analyze · Detect
          </p>
        </div>

        {/* Loading indicator */}
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-[var(--color-accent-cyan)] animate-bounce" style={{ animationDelay: '0ms' }} />
          <div className="w-2 h-2 rounded-full bg-[var(--color-accent-cyan)] animate-bounce" style={{ animationDelay: '150ms' }} />
          <div className="w-2 h-2 rounded-full bg-[var(--color-accent-cyan)] animate-bounce" style={{ animationDelay: '300ms' }} />
        </div>
      </div>
    </div>
  );
}