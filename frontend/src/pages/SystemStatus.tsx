import { useEffect, useState, useCallback } from "react";
import {
  Server, Database, Cpu, HardDrive, Wifi, Zap, CheckCircle, AlertCircle, XCircle,
  ChevronRight, Radio, Network, Shield, RefreshCw
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { MetricCard } from "../components/charts/MetricCard";
import { TrafficAreaChart } from "../components/charts/TrafficAreaChart";
import { ScanlineOverlay } from "../components/ui/ScanlineOverlay";
import { generateSystemStatus, generatePipelineStages } from "../data/mockData";
import { formatNumber } from "../lib/utils";
import { SystemStatus, PipelineStage } from "../types";
import { Button } from "../components/ui/Button";
import { toast } from "../lib/export";
import { DataModeIndicator } from "../components/DataModeIndicator";
import { LoadingSpinner } from "../components/ui/LoadingStates";
import { getSystemStatus, getPipelineStages, getDataMode, isBackendAvailable } from "../services/apiClient";

export function SystemStatusPage() {
  const [system, setSystem] = useState<SystemStatus | null>(null);
  const [pipeline, setPipeline] = useState<PipelineStage[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [dataMode, setDataMode] = useState<string>(getDataMode());

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const backendAlive = isBackendAvailable() || getDataMode() === "backend";
      if (backendAlive) {
        try {
          const [s, p] = await Promise.all([getSystemStatus(), getPipelineStages()]);
          // system from backend always returns object, use it; pipeline may be empty before fallback
          setSystem(s);
          setPipeline(p.length ? p : generatePipelineStages());
          setDataMode(getDataMode());
          setLoading(false);
          return;
        } catch (e) {
          setError(e instanceof Error ? e.message : "Backend fetch failed");
        }
      }
      setSystem(generateSystemStatus());
      setPipeline(generatePipelineStages());
      setDataMode("simulation");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    const interval = setInterval(async () => {
      const backendAlive = isBackendAvailable() || getDataMode() === "backend";
      if (backendAlive) {
        try {
          const [s, p] = await Promise.all([getSystemStatus(), getPipelineStages()]);
          setSystem(s);
          if (p.length) setPipeline(p);
        } catch {}
      } else {
        setSystem(generateSystemStatus());
        setPipeline(generatePipelineStages());
      }
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleRefresh = useCallback(() => {
    toast(`Data refreshed (${dataMode === "backend" ? "backend" : "simulation"})`);
    load();
  }, [load, dataMode]);

  if (loading) return <LoadingSpinner text="Loading system status..." />;

  const uptimeDays = Math.floor((system?.uptime || 0) / 100);
  const uptimeHours = Math.floor(((system?.uptime || 0) % 100) * 24 / 100);

  return (
    <div className="space-y-6 page-enter">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-medium text-[var(--color-text-primary)] tracking-tight">System / Ingest Status</h1>
            <DataModeIndicator />
          </div>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">Ingest health · Throughput · Uptime · Data diode architecture</p>
        </div>
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="sm" onClick={handleRefresh}>
            <RefreshCw className="w-4 h-4 mr-1" />
            Refresh
          </Button>
        </div>
      </div>

      {error && (
        <div className="px-4 py-3 rounded-[6px] bg-red-500/10 border border-red-500/20 text-sm text-red-400 font-mono">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard label="Throughput" value={system ? formatNumber(system.throughput) + "/s" : "—"} trend={1.2} trendLabel="vs baseline" icon={<Zap className="w-6 h-6 text-[var(--color-accent-cyan)]" />} />
        <MetricCard label="Uptime" value={`${uptimeDays}d ${uptimeHours}h`} trend={0} trendLabel="99.997% SLA" icon={<CheckCircle className="w-6 h-6 text-[var(--color-success)]" />} />
        <MetricCard label="Active Alerts" value={system?.activeAlerts || 0} trend={5.3} trendLabel="vs 1h ago" icon={<AlertCircle className="w-6 h-6 text-[var(--color-warning)]" />} />
        <MetricCard label="Processed Flows" value={system ? formatNumber(system.processedFlows) : "—"} trend={2.8} trendLabel="total" icon={<Database className="w-6 h-6 text-[var(--color-threat-dga)]" />} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2 card-inner-highlight">
          <CardHeader>
            <CardTitle>Ingest Throughput — Last 60 Minutes</CardTitle>
          </CardHeader>
          <CardContent>
            <TrafficAreaChart
              data={generateThroughputTimeSeries()}
              series={[
                { key: "flowsPerSec", name: "Flows/sec", color: "var(--color-accent-cyan)" },
                { key: "bitsPerSec", name: "Gbps", color: "var(--color-success)" },
                { key: "packetsPerSec", name: "Mpps", color: "var(--color-threat-c2)" },
              ]}
              height={280}
            />
            <ScanlineOverlay speed={10} opacity={0.02} />
          </CardContent>
        </Card>

        <Card className="card-inner-highlight space-y-4">
          <CardHeader>
            <CardTitle>Data Diode Architecture</CardTitle>
          </CardHeader>
          <CardContent>
            <DiodeArchitectureDiagram />
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="card-inner-highlight">
          <CardHeader>
            <CardTitle>System Resources</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <ResourceBar label="CPU Usage" value={system?.cpuUsage || 0} max={100} unit="%" color="var(--color-threat-ddos)" warning={80} critical={90} />
            <ResourceBar label="Memory Usage" value={system?.memoryUsage || 0} max={100} unit="%" color="var(--color-warning)" warning={85} critical={95} />
            <ResourceBar label="Disk Usage" value={system?.diskUsage || 0} max={100} unit="%" color="var(--color-accent-cyan)" warning={90} critical={98} />
            <ResourceBar label="Network I/O" value={65} max={100} unit="%" color="var(--color-threat-tls)" warning={80} critical={90} />
          </CardContent>
        </Card>

        <Card className="card-inner-highlight">
          <CardHeader>
            <CardTitle>Pipeline Stages</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {pipeline.map((stage) => (
              <div key={stage.name} className="p-3 rounded-[6px] bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)]">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className={`w-2.5 h-2.5 rounded-full ${stage.status === "active" ? "bg-[var(--color-success)] animate-pulse-slow" : "bg-[var(--color-text-muted)]"}`} />
                    <span className="font-medium text-[var(--color-text-primary)]">{stage.name}</span>
                    <Badge variant={stage.status === "active" ? "success" : "info"} size="sm">{stage.status.toUpperCase()}</Badge>
                  </div>
                  <ChevronRight className="w-4 h-4 text-[var(--color-text-muted)]" />
                </div>
                <div className="grid grid-cols-3 gap-2 text-sm">
                  <div className="text-center p-2 bg-[var(--color-bg-elevated-1)] rounded-[4px]">
                    <p className="font-mono text-[var(--color-text-primary)] tabular-nums">{formatNumber(stage.throughput)}/s</p>
                    <p className="text-[10px] text-[var(--color-text-muted)] uppercase">THROUGHPUT</p>
                  </div>
                  <div className="text-center p-2 bg-[var(--color-bg-elevated-1)] rounded-[4px]">
                    <p className="font-mono text-[var(--color-text-primary)] tabular-nums">{stage.latency.toFixed(1)}ms</p>
                    <p className="text-[10px] text-[var(--color-text-muted)] uppercase">LATENCY</p>
                  </div>
                  <div className="text-center p-2 bg-[var(--color-bg-elevated-1)] rounded-[4px]">
                    <p className="font-mono text-[var(--color-text-primary)] tabular-nums">{stage.queueDepth}</p>
                    <p className="text-[10px] text-[var(--color-text-muted)] uppercase">QUEUE</p>
                  </div>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card className="card-inner-highlight">
          <CardHeader>
            <CardTitle>Health Checks</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <HealthCheckItem name="Data Diode Link" status={system?.diodeStatus === "connected" ? "healthy" : "critical"} detail="Optical link established" icon={<Wifi />} />
            <HealthCheckItem name="Packet Capture" status="healthy" detail="Zero packet loss (0.002%)" icon={<Network />} />
            <HealthCheckItem name="Flow Generation" status="healthy" detail={`${formatNumber(system?.throughput || 0)}/s flow export`} icon={<Zap />} />
            <HealthCheckItem name="ML Inference" status="healthy" detail="All models responding <5ms" icon={<Cpu />} />
            <HealthCheckItem name="Alert Forwarding" status="healthy" detail="SIEM webhook OK (12ms avg)" icon={<Shield />} />
            <HealthCheckItem name="Storage Write" status={system && system.diskUsage > 90 ? "warning" : "healthy"} detail={`${system?.diskUsage || 0}% disk used`} icon={<HardDrive />} />
            <HealthCheckItem name="Time Sync (NTP)" status="healthy" detail="Stratum 1, offset <1ms" icon={<Server />} />
            <HealthCheckItem name="License" status="healthy" detail="Enterprise - Valid until 2027" icon={<Shield />} />
          </CardContent>
        </Card>
      </div>

      <Card className="card-inner-highlight">
        <CardHeader>
          <CardTitle>Dropped Packets & Error Rates</CardTitle>
        </CardHeader>
        <CardContent>
          <TrafficAreaChart
            data={generateErrorTimeSeries()}
            series={[
              { key: "dropped", name: "Dropped Packets", color: "var(--color-danger)" },
              { key: "errors", name: "CRC Errors", color: "var(--color-warning)" },
              { key: "reassembled", name: "Reassembled Flows", color: "var(--color-success)" },
            ]}
            height={200}
          />
          <ScanlineOverlay speed={12} opacity={0.02} />
        </CardContent>
      </Card>
    </div>
  );
}

function DiodeArchitectureDiagram() {
  return (
    <div className="relative py-8 px-4">
      <div className="flex items-center justify-between relative z-10">
        <ArchitectureNode 
          label="PRODUCTION NETWORK" 
          sublabel="Critical Infrastructure" 
          icon={<Server />} 
          color="var(--color-threat-recon)"
          status="healthy"
        />
        <div className="flex flex-col items-center relative">
          <div className="w-20 h-20 rounded-[8px] bg-[var(--color-bg-elevated-2)] border-2 border-[var(--color-border-card)] flex items-center justify-center relative">
            <div className="w-12 h-12 rounded-[6px] bg-gradient-to-br from-[var(--color-threat-ddos)] to-[var(--color-threat-tls)] flex items-center justify-center">
              <Radio className="w-7 h-7 text-[var(--color-bg-deep)]" />
            </div>
            <div className="absolute -top-2 -right-2 w-4 h-4 rounded-full bg-[var(--color-success)] border-2 border-[var(--color-bg-elevated-1)] animate-pulse-slow" />
          </div>
          <p className="text-xs font-medium text-[var(--color-text-primary)] mt-2 text-center">DATA DIODE</p>
          <p className="text-[10px] text-[var(--color-text-muted)] text-center">One-Way Optical</p>
        </div>
        <ArchitectureNode 
          label="CYBERSENTINEL" 
          sublabel="Threx AI Platform" 
          icon={<Shield />} 
          color="var(--color-accent-cyan)"
          status="healthy"
        />
      </div>

      <div className="absolute top-1/2 left-0 right-0 -z-10 flex items-center justify-between px-8">
        <div className="w-1/3 h-0.5 bg-[var(--color-border-card)]" />
        <div className="w-1/3 h-0.5 bg-gradient-to-r from-[var(--color-threat-recon)] via-[var(--color-threat-ddos)] to-[var(--color-accent-cyan)]" />
        <div className="w-1/3 h-0.5 bg-[var(--color-border-card)]" />
      </div>

      <div className="mt-8 pt-6 border-t border-[var(--color-border-card)]/50">
        <div className="flex items-center justify-center gap-8 text-center">
          <div className="flex items-center gap-2 text-[var(--color-success)]">
            <CheckCircle className="w-5 h-5" />
            <span className="font-mono text-sm">INGRESS: ENABLED</span>
          </div>
          <div className="w-1 h-6 bg-[var(--color-border-card)]" />
          <div className="flex items-center gap-2 text-[var(--color-danger)]">
            <XCircle className="w-5 h-5" />
            <span className="font-mono text-sm">EGRESS: DISABLED</span>
          </div>
          <div className="w-1 h-6 bg-[var(--color-border-card)]" />
          <div className="flex items-center gap-2 text-[var(--color-accent-cyan)]">
            <Radio className="w-5 h-5" />
            <span className="font-mono text-sm">RETURN PATH: NONE</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function ArchitectureNode({ label, sublabel, icon, color, status }: { 
  label: string; sublabel: string; icon: React.ReactNode; color: string; status: "healthy" | "warning" | "critical" }) {
  const statusColors = { healthy: "var(--color-success)", warning: "var(--color-warning)", critical: "var(--color-danger)" };
  
  return (
    <div className="flex flex-col items-center flex-1">
      <div className="w-20 h-20 rounded-[8px] bg-[var(--color-bg-elevated-2)] border-2 border-[var(--color-border-card)] flex items-center justify-center relative"
        style={{ borderColor: statusColors[status] }}>
        <div className="w-12 h-12 rounded-[6px] flex items-center justify-center" style={{ backgroundColor: color + "20" }}>
          <span className="w-7 h-7" style={{ color }}>{icon}</span>
        </div>
        <div className="absolute -top-2 -right-2 w-4 h-4 rounded-full" style={{ backgroundColor: statusColors[status] }} />
      </div>
      <p className="text-xs font-medium text-[var(--color-text-primary)] mt-2 text-center">{label}</p>
      <p className="text-[10px] text-[var(--color-text-muted)] text-center">{sublabel}</p>
    </div>
  );
}

function ResourceBar({ label, value, max, unit, color, warning, critical }: { 
  label: string; value: number; max: number; unit: string; color: string; warning: number; critical: number }) {
  const percentage = (value / max) * 100;
  const statusColor = percentage >= critical ? "var(--color-danger)" : percentage >= warning ? "var(--color-warning)" : color;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-sm">
        <span className="text-[var(--color-text-secondary)]">{label}</span>
        <span className="font-mono text-[var(--color-text-primary)] tabular-nums">{value.toFixed(1)}{unit}</span>
      </div>
      <div className="h-2 bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)] rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-1000 ease-out"
          style={{ width: `${percentage}%`, backgroundColor: statusColor }}
        />
      </div>
      <div className="flex justify-between text-[10px] text-[var(--color-text-muted)]">
        <span>Warning: {warning}{unit}</span>
        <span>Critical: {critical}{unit}</span>
      </div>
    </div>
  );
}

function HealthCheckItem({ name, status, detail, icon }: { 
  name: string; status: "healthy" | "warning" | "critical"; detail: string; icon: React.ReactNode }) {
  const statusColors = { healthy: "var(--color-success)", warning: "var(--color-warning)", critical: "var(--color-danger)" };
  const StatusIcon = status === "healthy" ? CheckCircle : status === "warning" ? AlertCircle : XCircle;

  return (
    <div className="flex items-center gap-3 p-3 rounded-[6px] bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)]">
      <div className="w-8 h-8 rounded-[6px] bg-[var(--color-bg-elevated-1)] border border-[var(--color-border-card)] flex items-center justify-center">
        <span className="w-4 h-4" style={{ color: statusColors[status] }}>{icon}</span>
      </div>
      <div className="flex-1 min-w-0">
        <p className="font-medium text-[var(--color-text-primary)] truncate">{name}</p>
        <p className="text-xs text-[var(--color-text-muted)] truncate">{detail}</p>
      </div>
      <div className="flex items-center gap-2">
        <StatusIcon className="w-4 h-4" style={{ color: statusColors[status] }} />
        <Badge variant={status === "healthy" ? "success" : status === "warning" ? "warning" : "danger"} size="sm">
          {status.toUpperCase()}
        </Badge>
      </div>
    </div>
  );
}

function generateThroughputTimeSeries() {
  const data = [];
  const now = new Date();
  for (let i = 59; i >= 0; i--) {
    const time = new Date(now.getTime() - i * 60 * 1000);
    data.push({
      time: time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      flowsPerSec: Math.floor(Math.random() * 20000) + 40000,
      bitsPerSec: (Math.random() * 2 + 3).toFixed(1),
      packetsPerSec: (Math.random() * 1 + 1.5).toFixed(2),
    });
  }
  return data;
}

function generateErrorTimeSeries() {
  const data = [];
  const now = new Date();
  for (let i = 59; i >= 0; i--) {
    const time = new Date(now.getTime() - i * 60 * 1000);
    data.push({
      time: time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      dropped: Math.floor(Math.random() * 50),
      errors: Math.floor(Math.random() * 20),
      reassembled: Math.floor(Math.random() * 100) + 50,
    });
  }
  return data;
}
