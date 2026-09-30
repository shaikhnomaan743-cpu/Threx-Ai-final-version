import { Loader2 } from "lucide-react";
import { cn } from "../../lib/utils";

interface LoadingSpinnerProps {
  className?: string;
  size?: number;
  text?: string;
}

export function LoadingSpinner({ className, size = 24, text }: LoadingSpinnerProps) {
  return (
    <div className={cn("flex flex-col items-center justify-center gap-3 py-12", className)}>
      <Loader2 className="animate-spin text-[var(--color-accent-cyan)]" size={size} />
      {text && <p className="text-sm text-[var(--color-text-muted)]">{text}</p>}
    </div>
  );
}

export function PageLoading() {
  return (
    <div className="flex items-center justify-center min-h-[400px]">
      <LoadingSpinner size={32} text="Loading data..." />
    </div>
  );
}

export function EmptyState({ title, description }: { title: string; description?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="w-16 h-16 rounded-full bg-[var(--color-bg-elevated-2)] flex items-center justify-center mb-4">
        <div className="w-8 h-8 border-2 border-[var(--color-border-card)] rounded-full" />
      </div>
      <h3 className="text-lg font-medium text-[var(--color-text-primary)] mb-1">{title}</h3>
      {description && <p className="text-sm text-[var(--color-text-muted)] max-w-sm">{description}</p>}
    </div>
  );
}
