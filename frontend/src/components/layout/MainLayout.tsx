import { useEffect, useState } from "react";
import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import { ThroughputSparkline } from "./ThroughputSparkline";
import { GlobalSearch } from "../GlobalSearch";
import { cn } from "../../lib/utils";

const SPARKLINE_H = 14;

export function MainLayout() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [searchOpen, setSearchOpen] = useState(false);

  useEffect(() => {
    const onToast = (e: Event) => {
      const message = (e as CustomEvent<string>).detail;
      setToast(message);
      window.setTimeout(() => setToast(null), 2800);
    };
    window.addEventListener("threx:toast", onToast);
    return () => window.removeEventListener("threx:toast", onToast);
  }, []);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setSearchOpen(true);
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, []);

  return (
    <div className="min-h-screen bg-[var(--color-bg-deep)] bg-radial-subtle relative">
      <div className="bg-noise-overlay" aria-hidden="true" />

      <GlobalSearch open={searchOpen} onClose={() => setSearchOpen(false)} />

      <div className="fixed inset-x-0 top-0 z-50">
        <ThroughputSparkline height={SPARKLINE_H} />
      </div>

      <Sidebar
        isCollapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        topOffset={SPARKLINE_H}
      />

      <TopBar
        sidebarCollapsed={sidebarCollapsed}
        topOffset={SPARKLINE_H}
        onSearchOpen={() => setSearchOpen(true)}
      />

      <main
        className={cn(
          "min-h-screen transition-all duration-200",
          sidebarCollapsed ? "ml-16" : "ml-64"
        )}
        style={{ paddingTop: SPARKLINE_H + 56 }}
      >
        <div className="p-6 relative z-[2]">
          <Outlet />
        </div>
      </main>

      {toast && (
        <div className="fixed bottom-6 right-6 z-[60] px-4 py-3 rounded-[8px] border border-[var(--color-accent-cyan-border)] bg-[var(--color-bg-elevated-2)]/95 backdrop-blur-md text-sm text-[var(--color-text-primary)] animate-slide-in">
          {toast}
        </div>
      )}
    </div>
  );
}
