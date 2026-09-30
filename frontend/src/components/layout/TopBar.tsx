import { useState, useEffect, useRef } from "react";
import { Search, User, Zap, Command, ChevronDown, Lock, HardDrive, UserCog } from "lucide-react";
import { cn } from "../../lib/utils";
import { Select } from "../ui/Select";
import { Badge } from "../ui/Badge";

interface TopBarProps {
  onSearchOpen?: () => void;
  onTimeRangeChange?: (range: string) => void;
  sidebarCollapsed?: boolean;
  topOffset?: number;
}

const TIME_RANGES = [
  { value: "1h", label: "Last Hour" },
  { value: "6h", label: "Last 6 Hours" },
  { value: "24h", label: "Last 24 Hours" },
  { value: "7d", label: "Last 7 Days" },
  { value: "30d", label: "Last 30 Days" },
];

interface ProfileMenuItem {
  label: string;
  icon: React.ReactNode;
  action: () => void;
  variant?: "default" | "danger";
}

export function TopBar({ onSearchOpen, onTimeRangeChange, sidebarCollapsed = false, topOffset = 0 }: TopBarProps) {
  const [timeRange, setTimeRange] = useState("1h");
  const [flowsPerSec, setFlowsPerSec] = useState("—");
  const [activeFlows, setActiveFlows] = useState("—");
  const [dataSource, setDataSource] = useState("LAB REPLAY");
  const [backendOnline, setBackendOnline] = useState(false);
  const [profileMenuOpen, setProfileMenuOpen] = useState(false);
  const profileMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (profileMenuRef.current && !profileMenuRef.current.contains(event.target as Node)) {
        setProfileMenuOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  useEffect(() => {
    async function poll() {
      try {
        const res = await fetch("http://localhost:8000/ingest/status");
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        setBackendOnline(true);
        // Show the backend's real data-source name (LAB_REPLAY / PCAP_REPLAY / LIVE_INGEST).
        const raw = String(data.data_source || "LAB_REPLAY");
        setDataSource(raw.replace(/_/g, " "));
        setActiveFlows(String(data.flows_processed ?? 0));
        const fps = Number(data.current_throughput_fps);
        setFlowsPerSec(Number.isFinite(fps) && fps > 0 ? `${fps.toFixed(1)} flows/s` : `${data.flows_processed ?? 0} flows`);
      } catch (e) {
        setBackendOnline(false);
        setFlowsPerSec("—");
        setActiveFlows("—");
      }
    }
    poll();
    const interval = setInterval(poll, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleClearCache = () => {
    if (typeof window !== "undefined") {
      localStorage.clear();
      sessionStorage.clear();
      window.dispatchEvent(new CustomEvent("threx:toast", { detail: "Local cache cleared" }));
    }
    setProfileMenuOpen(false);
  };

  const handleLockSession = () => {
    setProfileMenuOpen(false);
    window.dispatchEvent(new CustomEvent("threx:lock-session"));
  };

  const profileMenuItems: ProfileMenuItem[] = [
    { label: "Operator ID: Analyst-01", icon: <UserCog className="w-4 h-4" />, action: () => {} },
    { label: "Session: Secure Diode", icon: <HardDrive className="w-4 h-4" />, action: () => {} },
    { label: "Clear Local Cache", icon: <HardDrive className="w-4 h-4" />, action: handleClearCache },
    { label: "Lock Session (Return to Login)", icon: <Lock className="w-4 h-4" />, action: handleLockSession, variant: "danger" },
  ];

  return (
    <header
      className={cn(
        "fixed right-0 z-30 h-14 bg-[#12141a]/80 backdrop-blur-md border-b border-white/5 flex items-center justify-between px-6 transition-all duration-200",
        sidebarCollapsed ? "left-16" : "left-64"
      )}
      style={{ top: topOffset }}
    >
      <div className="flex-1 max-w-xl">
        <button
          onClick={onSearchOpen}
          className="w-full flex items-center gap-3 px-3 py-2 bg-[#1a1d26]/80 border border-white/5 rounded-[6px] text-sm text-[var(--color-text-muted)] hover:border-white/10 transition-colors text-left"
          aria-label="Open global search"
        >
          <Search className="w-4 h-4 flex-shrink-0" />
          <span className="flex-1">Search anything...</span>
          <kbd className="hidden sm:inline-flex items-center gap-1 px-2 py-0.5 rounded-[4px] bg-[#12141a]/80 border border-white/5 text-[10px] font-mono text-[var(--color-text-muted)]">
            <Command className="w-3 h-3" />
            <span>K</span>
          </kbd>
        </button>
      </div>

      <div className="flex items-center gap-4 ml-8">
        <div className="hidden lg:flex items-center gap-3 px-3 py-1.5 bg-[#1a1d26]/80 border border-white/5 rounded-[6px]">
          <span className="text-xs font-mono tabular-nums text-[var(--color-text-secondary)]">{flowsPerSec}</span>
          <span className="text-white/10">·</span>
          <span className="text-xs font-mono tabular-nums text-[var(--color-text-secondary)]">{activeFlows} active</span>
        </div>

        <Select
          value={timeRange}
          onChange={(value) => {
            setTimeRange(value);
            onTimeRangeChange?.(value);
          }}
          options={TIME_RANGES.map(r => ({ value: r.value, label: r.label }))}
          placeholder="Time Range"
          className="w-40"
        />

        <div ref={profileMenuRef} className="relative">
          <button
            onClick={() => setProfileMenuOpen(!profileMenuOpen)}
            className="flex items-center gap-2 px-3 py-1.5 bg-[#1a1d26]/80 border border-white/5 rounded-[6px] hover:border-white/10 transition-colors"
            aria-label="Profile menu"
            aria-expanded={profileMenuOpen}
            aria-haspopup="true"
          >
            <User className="w-4 h-4 text-[var(--color-text-muted)]" aria-hidden="true" />
            <span className="text-sm font-medium text-[var(--color-text-primary)]">Analyst</span>
            <ChevronDown className={cn("w-3 h-3 text-[var(--color-text-muted)] transition-transform", profileMenuOpen && "rotate-180")} aria-hidden="true" />
          </button>

          {profileMenuOpen && (
            <div
              className="absolute right-0 top-full mt-2 w-56 bg-[#1a1d26]/95 backdrop-blur-md border border-white/5 rounded-[8px] shadow-xl animate-slide-in z-50"
              role="menu"
            >
              <div className="px-3 py-2 border-b border-white/5">
                <p className="text-xs font-medium text-[var(--color-text-primary)]">Analyst-01</p>
                <p className="text-[10px] text-[var(--color-text-muted)] font-mono">Secure Diode Session</p>
              </div>
              <div className="py-1">
                {profileMenuItems.map((item, index) => (
                  <button
                    key={index}
                    onClick={item.action}
                    className={cn(
                      "w-full flex items-center gap-3 px-3 py-2 text-sm text-left transition-colors",
                      item.variant === "danger"
                        ? "text-[var(--color-danger)] hover:bg-[var(--color-danger)]/10"
                        : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[#12141a]/50"
                    )}
                    role="menuitem"
                  >
                    <span className="flex-shrink-0" aria-hidden="true">{item.icon}</span>
                    <span className="flex-1 truncate">{item.label}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1a1d26]/80 border border-white/5 rounded-[6px]">
          <Zap className="w-4 h-4 text-[var(--color-success)]" aria-hidden="true" />
          <span className="text-xs font-medium text-[var(--color-success)] uppercase tracking-wider">PASSIVE</span>
        </div>

        <Badge variant={backendOnline ? "success" : "warning"}>{backendOnline ? dataSource : "OFFLINE"}</Badge>
      </div>
    </header>
  );
}
