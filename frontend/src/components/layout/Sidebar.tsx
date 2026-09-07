import { useState, useEffect } from "react";
import { Link, useLocation, NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  Activity,
  Search,
  Wifi,
  Shield,
  AlertTriangle,
  BarChart2,
  Cpu,
  FileText,
  Server,
  ChevronRight,
  Zap,
  Radio,
  Network,
  Bug,
  HardDrive,
} from "lucide-react";
import { cn } from "../../lib/utils";
import { Badge } from "../ui/Badge";

const NAV_SECTIONS = [
  {
    label: "MONITORING",
    items: [
      { key: "overview", label: "Overview", icon: LayoutDashboard, href: "/" },
      { key: "traffic", label: "Traffic Analytics", icon: Activity, href: "/traffic" },
      { key: "dns", label: "DNS Analytics", icon: Wifi, href: "/dns" },
      { key: "tls", label: "TLS/QUIC Analytics", icon: Shield, href: "/tls" },
    ],
  },
  {
    label: "DETECTION",
    items: [
      { key: "threats", label: "Threats & Alerts", icon: AlertTriangle, href: "/threats" },
      { key: "recon", label: "Reconnaissance", icon: Search, href: "/recon" },
      { key: "exfil", label: "Exfiltration", icon: HardDrive, href: "/exfil" },
      { key: "threat-hunting", label: "Threat Hunting", icon: Bug, href: "/threats" },
      { key: "ai-engine", label: "AI Detection Engine", icon: Cpu, href: "/ai-engine" },
    ],
  },
  {
    label: "OPERATIONS",
    items: [
      { key: "alerts", label: "Alert Center", icon: BarChart2, href: "/alerts" },
      { key: "reports", label: "Reports", icon: FileText, href: "/reports" },
      { key: "system", label: "System / Ingest Status", icon: Server, href: "/system" },
    ],
  },
];

interface SidebarProps {
  isCollapsed?: boolean;
  onToggle?: () => void;
  topOffset?: number;
}

export function Sidebar({ isCollapsed = false, onToggle, topOffset = 0 }: SidebarProps) {
  const location = useLocation();
  const [activeSection, setActiveSection] = useState(0);
  const [dataSourceText, setDataSourceText] = useState("PASSIVE");
  const [fpsText, setFpsText] = useState("Loading...");

  const getActiveSection = () => {
    for (let i = 0; i < NAV_SECTIONS.length; i++) {
      if (NAV_SECTIONS[i].items.some(item => location.pathname === item.href || location.pathname.startsWith(item.href + "/"))) {
        return i;
      }
    }
    return 0;
  };

  useEffect(() => {
    setActiveSection(getActiveSection());
  }, [location.pathname]);

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await fetch("http://localhost:8000/ingest/status");
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        setDataSourceText(String(data.data_source || "LAB_REPLAY").replace(/_/g, " "));
        const fps = Number(data.current_throughput_fps);
        setFpsText(Number.isFinite(fps) && fps > 0
          ? `${fps.toFixed(1)} flows/sec`
          : `${data.flows_processed ?? 0} flows processed`);
      } catch (e) {
        console.error("Failed to fetch status:", e);
        setDataSourceText("OFFLINE");
        setFpsText("backend unreachable");
      }
    };
    fetchStatus();
    const interval = setInterval(fetchStatus, 4000);
    return () => clearInterval(interval);
  }, []);

  const dataSourceDisplay = dataSourceText;

  return (
    <aside
      className={cn(
        "fixed left-0 z-40 bg-[#12141a]/80 backdrop-blur-md border-r border-white/5 transition-all duration-200",
        "flex flex-col",
        isCollapsed ? "w-16" : "w-64"
      )}
      style={{ top: topOffset, height: `calc(100vh - ${topOffset}px)` }}
    >
      <div className="flex items-center justify-between h-16 px-4 border-b border-white/5">
        {!isCollapsed && (
          <Link to="/" className="flex items-center gap-2" aria-label="Threx AI Home">
            <div className="w-8 h-8 rounded-[6px] bg-[var(--color-accent-cyan)] flex items-center justify-center">
              <Zap className="w-5 h-5 text-[var(--color-bg-deep)]" />
            </div>
            <div className="flex flex-col">
              <span className="font-medium text-lg text-[var(--color-text-primary)] tracking-tight">THREX AI</span>
              <span className="text-[10px] text-[var(--color-text-muted)] tracking-wider">Observe · Analyze · Detect</span>
            </div>
          </Link>
        )}
        {isCollapsed && (
          <Link to="/" className="flex items-center justify-center" aria-label="Threx AI Home">
            <div className="w-8 h-8 rounded-[6px] bg-[var(--color-accent-cyan)] flex items-center justify-center">
              <Zap className="w-5 h-5 text-[var(--color-bg-deep)]" />
            </div>
          </Link>
        )}
        {!isCollapsed && onToggle && (
          <button
            onClick={onToggle}
            className="text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] p-1 rounded-[4px] hover:bg-[#1a1d26]/80 transition-colors"
            aria-label="Collapse sidebar"
          >
            <ChevronRight className="w-4 h-4 rotate-180" />
          </button>
        )}
      </div>

      <nav className="flex-1 overflow-y-auto px-2 py-4 space-y-6" role="navigation" aria-label="Main navigation">
        {NAV_SECTIONS.map((section, sectionIndex) => (
          <div key={section.label} className={cn("transition-all duration-200", isCollapsed && "opacity-0 pointer-events-none")}>
            <div className="px-3 py-1">
              <span className={cn(
                "text-[10px] font-medium uppercase tracking-widest",
                sectionIndex === activeSection ? "text-[var(--color-accent-cyan)]" : "text-[var(--color-text-muted)]"
              )}>
                {section.label}
              </span>
            </div>
            <ul className="space-y-1" role="list">
              {section.items.map((item) => {
                const isActive = location.pathname === item.href || location.pathname.startsWith(item.href + "/");
                const Icon = item.icon;
                return (
                  <li key={item.key}>
                    <NavLink
                      to={item.href}
                      className={cn(
                        "flex items-center gap-3 px-3 py-2.5 rounded-[6px] transition-all duration-150",
                        "group relative overflow-hidden",
                        isActive
                          ? "bg-[var(--color-accent-cyan-dim)] border-l-2 border-[var(--color-accent-cyan)]"
                          : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[#1a1d26]/80",
                        isCollapsed && "justify-center"
                      )}
                      aria-current={isActive ? "page" : undefined}
                      title={isCollapsed ? item.label : undefined}
                    >
                      <Icon className={cn(
                        "w-5 h-5 flex-shrink-0 transition-colors",
                        isActive ? "text-[var(--color-accent-cyan)]" : "text-[var(--color-text-muted)] group-hover:text-[var(--color-text-primary)]"
                      )} aria-hidden="true" />
                      {!isCollapsed && (
                        <span className={cn(
                          "font-medium text-sm transition-colors",
                          isActive ? "text-[var(--color-text-primary)]" : ""
                        )}>
                          {item.label}
                        </span>
                      )}
                      {isActive && !isCollapsed && (
                        <div className="absolute left-0 top-0 bottom-0 w-0.5 bg-[var(--color-accent-cyan)]" />
                      )}
                    </NavLink>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      {/* Architecture Status Section */}
      {!isCollapsed && (
        <div className="px-4 py-3 border-t border-white/5">
          <p className="text-[10px] font-medium text-[var(--color-text-muted)] uppercase tracking-wider mb-3">ARCHITECTURE STATUS</p>
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-[var(--color-text-secondary)]">Read-Only Ingest</span>
              <span className="text-[var(--color-success)] font-medium">ENABLED</span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-[var(--color-text-secondary)]">Payload Decryption</span>
              <span className="text-[var(--color-text-muted)] font-medium">DISABLED</span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-[var(--color-text-secondary)]">Return Path</span>
              <span className="text-[var(--color-text-muted)] font-medium">NONE</span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-[var(--color-text-secondary)]">Inline Blocking</span>
              <span className="text-[var(--color-text-muted)] font-medium">DISABLED</span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-[var(--color-text-secondary)]">Streaming Engine</span>
              <span className="text-[var(--color-success)] font-medium">ACTIVE</span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-[var(--color-text-secondary)]">Data Retention</span>
              <span className="text-[var(--color-success)] font-medium">ACTIVE</span>
            </div>
          </div>
        </div>
      )}

      <div className={cn("p-4 border-t border-white/5 transition-all duration-200", isCollapsed && "opacity-0 pointer-events-none")}>
        <div className="flex items-center gap-3 p-2 rounded-[6px] bg-[#1a1d26]/80">
          <div className="w-2 h-2 rounded-full bg-[var(--color-success)] animate-pulse-slow flex-shrink-0" />
          {!isCollapsed && (
            <div className="flex-1 min-w-0">
              <p className="text-[10px] font-medium text-[var(--color-text-primary)] truncate">{dataSourceDisplay}</p>
              <p className="text-[10px] text-[var(--color-text-muted)] truncate">{fpsText}</p>
            </div>
          )}
        </div>
        {!isCollapsed && (
          <div className="mt-3 text-center">
            <p className="text-[10px] text-[var(--color-text-muted)] mt-2">
              Data Diode: Connected · Return Path: None
            </p>
          </div>
        )}
        {!isCollapsed && (
          <div className="mt-4 text-center">
            <p className="text-[10px] text-[var(--color-text-muted)] uppercase tracking-wider">
              THREX AI v1.0.0
            </p>
            <p className="text-[10px] text-[var(--color-text-muted)] mt-1">
              Passive • Secure • Unidirectional
            </p>
          </div>
        )}
      </div>
    </aside>
  );
}