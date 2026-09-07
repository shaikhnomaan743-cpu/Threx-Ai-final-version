import { useState } from "react";
import { X, ChevronRight, TrendingUp, Activity, AlertTriangle } from "lucide-react";
import { cn } from "../../lib/utils";
import { Badge } from "./Badge";
import { ThreatAlert } from "../../types";
import { Sparkline } from "../charts/Sparkline";

interface AlertDrawerProps {
  alert: ThreatAlert | null;
  onClose: () => void;
}

export function AlertDrawer({ alert, onClose }: AlertDrawerProps) {
  const [activeTab, setActiveTab] = useState("evidence");

  if (!alert) return null;

  const tabs = [
    { id: "evidence", label: "Evidence" },
    { id: "flowStats", label: "Flow Stats" },
    { id: "sourceInfo", label: "Source Info" },
    { id: "destInfo", label: "Destination Info" },
    { id: "rawFeatures", label: "Raw Features" },
  ];

  const riskHistory = Array(20).fill(0).map(() => 0.5 + Math.random() * 0.4);

  return (
    <div className="fixed right-0 top-0 bottom-0 w-[400px] bg-[#12141a]/95 backdrop-blur-md border-l border-white/5 z-40 shadow-2xl">
      <div className="h-full flex flex-col">
        {/* Header */}
        <div className="p-4 border-b border-white/5 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-medium text-[var(--color-text-primary)]">
              {alert.threatClass} Attack Detected
            </h3>
            <p className="text-sm text-[var(--color-text-muted)]">
              Flow ID: {alert.id.slice(0, 8)}
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-[4px] hover:bg-[#1a1d26]/80 transition-colors"
          >
            <X className="w-5 h-5 text-[var(--color-text-muted)]" />
          </button>
        </div>

        {/* Alert Details */}
        <div className="p-4 space-y-3 border-b border-white/5">
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <p className="text-[var(--color-text-muted)] text-xs">Timestamp</p>
              <p className="font-mono text-[var(--color-text-primary)]">{alert.timestamp.toLocaleString()}</p>
            </div>
            <div>
              <p className="text-[var(--color-text-muted)] text-xs">Flow ID</p>
              <p className="font-mono text-[var(--color-text-primary)]">{alert.id.slice(0, 12)}</p>
            </div>
            <div>
              <p className="text-[var(--color-text-muted)] text-xs">Source IP</p>
              <p className="font-mono text-[var(--color-text-primary)]">{alert.sourceIp}</p>
            </div>
            <div>
              <p className="text-[var(--color-text-muted)] text-xs">Destination IP</p>
              <p className="font-mono text-[var(--color-text-primary)]">{alert.destinationIp}</p>
            </div>
            <div>
              <p className="text-[var(--color-text-muted)] text-xs">Dst Port</p>
              <p className="font-mono text-[var(--color-text-primary)]">{alert.destinationPort}</p>
            </div>
            <div>
              <p className="text-[var(--color-text-muted)] text-xs">Protocol</p>
              <p className="font-mono text-[var(--color-text-primary)]">{alert.protocol}</p>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-white/5 px-4">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                "px-3 py-2 text-sm font-medium transition-colors relative",
                activeTab === tab.id
                  ? "text-[var(--color-accent-cyan)]"
                  : "text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]"
              )}
            >
              {tab.label}
              {activeTab === tab.id && (
                <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-[var(--color-accent-cyan)]" />
              )}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div className="flex-1 overflow-y-auto p-4">
          {activeTab === "evidence" && (
            <div className="space-y-3">
              <div className="flex items-center gap-2 p-3 bg-[#1a1d26]/50 rounded-[6px]">
                <Activity className="w-4 h-4 text-[var(--color-accent-cyan)]" />
                <div className="flex-1">
                  <p className="text-sm text-[var(--color-text-primary)]">High packet rate detected</p>
                  <p className="text-xs text-[var(--color-text-muted)]">5,234 packets/sec (baseline: 234)</p>
                </div>
                <Badge variant="critical" size="sm">CRITICAL</Badge>
              </div>
              <div className="flex items-center gap-2 p-3 bg-[#1a1d26]/50 rounded-[6px]">
                <AlertTriangle className="w-4 h-4 text-[var(--color-warning)]" />
                <div className="flex-1">
                  <p className="text-sm text-[var(--color-text-primary)]">SYN flood pattern identified</p>
                  <p className="text-xs text-[var(--color-text-muted)]">92% SYN packets, no ACK responses</p>
                </div>
                <Badge variant="high" size="sm">HIGH</Badge>
              </div>
              <div className="flex items-center gap-2 p-3 bg-[#1a1d26]/50 rounded-[6px]">
                <TrendingUp className="w-4 h-4 text-[var(--color-success)]" />
                <div className="flex-1">
                  <p className="text-sm text-[var(--color-text-primary)]">Rapid connection attempts</p>
                  <p className="text-xs text-[var(--color-text-muted)]">1,247 unique destinations in 60s</p>
                </div>
                <Badge variant="medium" size="sm">MEDIUM</Badge>
              </div>
            </div>
          )}

          {activeTab === "flowStats" && (
            <div className="space-y-3">
              <div className="p-3 bg-[#1a1d26]/50 rounded-[6px]">
                <p className="text-xs text-[var(--color-text-muted)]">Total Packets</p>
                <p className="text-lg font-mono text-[var(--color-text-primary)]">{alert.metadata?.packets || 0}</p>
              </div>
              <div className="p-3 bg-[#1a1d26]/50 rounded-[6px]">
                <p className="text-xs text-[var(--color-text-muted)]">Total Bytes</p>
                <p className="text-lg font-mono text-[var(--color-text-primary)]">{alert.metadata?.bytes || 0}</p>
              </div>
              <div className="p-3 bg-[#1a1d26]/50 rounded-[6px]">
                <p className="text-xs text-[var(--color-text-muted)]">Duration</p>
                <p className="text-lg font-mono text-[var(--color-text-primary)]">{alert.metadata?.duration || 0}s</p>
              </div>
            </div>
          )}

          {activeTab === "sourceInfo" && (
            <div className="space-y-3">
              <div className="p-3 bg-[#1a1d26]/50 rounded-[6px]">
                <p className="text-xs text-[var(--color-text-muted)]">Source IP</p>
                <p className="text-lg font-mono text-[var(--color-text-primary)]">{alert.sourceIp}</p>
              </div>
              <div className="p-3 bg-[#1a1d26]/50 rounded-[6px]">
                <p className="text-xs text-[var(--color-text-muted)]">Source Port</p>
                <p className="text-lg font-mono text-[var(--color-text-primary)]">{alert.metadata?.sourcePort || 0}</p>
              </div>
              <div className="p-3 bg-[#1a1d26]/50 rounded-[6px]">
                <p className="text-xs text-[var(--color-text-muted)]">Geolocation</p>
                <p className="text-sm text-[var(--color-text-primary)]">Unknown (Internal)</p>
              </div>
            </div>
          )}

          {activeTab === "destInfo" && (
            <div className="space-y-3">
              <div className="p-3 bg-[#1a1d26]/50 rounded-[6px]">
                <p className="text-xs text-[var(--color-text-muted)]">Destination IP</p>
                <p className="text-lg font-mono text-[var(--color-text-primary)]">{alert.destinationIp}</p>
              </div>
              <div className="p-3 bg-[#1a1d26]/50 rounded-[6px]">
                <p className="text-xs text-[var(--color-text-muted)]">Destination Port</p>
                <p className="text-lg font-mono text-[var(--color-text-primary)]">{alert.destinationPort}</p>
              </div>
              <div className="p-3 bg-[#1a1d26]/50 rounded-[6px]">
                <p className="text-xs text-[var(--color-text-muted)]">Service</p>
                <p className="text-sm text-[var(--color-text-primary)]">HTTP/Web Server</p>
              </div>
            </div>
          )}

          {activeTab === "rawFeatures" && (
            <div className="space-y-3">
              <div className="p-3 bg-[#1a1d26]/50 rounded-[6px]">
                <p className="text-xs text-[var(--color-text-muted)]">Confidence Score</p>
                <p className="text-lg font-mono text-[var(--color-text-primary)]">{(alert.confidence * 100).toFixed(1)}%</p>
              </div>
              <div className="p-3 bg-[#1a1d26]/50 rounded-[6px]">
                <p className="text-xs text-[var(--color-text-muted)]">Threat Class</p>
                <p className="text-sm text-[var(--color-text-primary)]">{alert.threatClass}</p>
              </div>
              <div className="p-3 bg-[#1a1d26]/50 rounded-[6px]">
                <p className="text-xs text-[var(--color-text-muted)]">Severity</p>
                <p className="text-sm text-[var(--color-text-primary)]">{alert.severity.toUpperCase()}</p>
              </div>
            </div>
          )}
        </div>

        {/* Risk Score Chart */}
        <div className="p-4 border-t border-white/5">
          <p className="text-xs text-[var(--color-text-muted)] mb-2">Risk Score Over Time</p>
          <div className="h-16">
            <Sparkline data={riskHistory} color="var(--color-danger)" height={64} />
          </div>
        </div>
      </div>
    </div>
  );
}