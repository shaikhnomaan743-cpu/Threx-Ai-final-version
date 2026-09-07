import { useEffect, useState, useCallback } from "react";
import { Cpu, CheckCircle, AlertCircle, Database, Brain, RefreshCw, BarChart2, Zap } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { MetricCard } from "../components/charts/MetricCard";
import { TrafficAreaChart } from "../components/charts/TrafficAreaChart";
import { ScanlineOverlay } from "../components/ui/ScanlineOverlay";
import { generateModelStatuses, generatePipelineStages, generateSystemStatus } from "../data/mockData";
import { formatNumber, formatDuration } from "../lib/utils";
import { ModelStatus, PipelineStage, SystemStatus } from "../types";
import { Button } from "../components/ui/Button";
import { toast } from "../lib/export";
import { DataModeIndicator } from "../components/DataModeIndicator";
import { LoadingSpinner, EmptyState } from "../components/ui/LoadingStates";
import { getModelStatuses, getPipelineStages, getSystemStatus, getDataMode, isBackendAvailable } from "../services/apiClient";

const PIPELINE_STEPS = [
  { name: "Ingest", icon: Database, description: "Raw packet capture via data diode", color: "var(--color-accent-cyan)" },
  { name: "Feature Extraction", icon: Brain, description: "Flow metadata, statistical features", color: "var(--color-threat-c2)" },
  { name: "ML Models", icon: Cpu, description: "Ensemble classification + anomaly detection", color: "var(--color-threat-tls)" },
  { name: "Classification", icon: BarChart2, description: "Threat class assignment & scoring", color: "var(--color-threat-recon)" },
  { name: "Alerts", icon: AlertCircle, description: "Enrichment, deduplication, forwarding", color: "var(--color-threat-ddos)" },
];

export function AIDetectionEngine() {
  const [models, setModels] = useState<ModelStatus[]>([]);
  const [pipeline, setPipeline] = useState<PipelineStage[]>([]);
  const [system, setSystem] = useState<SystemStatus | null>(null);
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
          const [m, p, s] = await Promise.all([getModelStatuses(), getPipelineStages(), getSystemStatus()]);
          if (m.length > 0 || p.length > 0) {
            setModels(m.length ? m : generateModelStatuses());
            setPipeline(p.length ? p : generatePipelineStages());
            setSystem(s);
            setDataMode(getDataMode());
            setLoading(false);
            return;
          }
        } catch (e) {
          setError(e instanceof Error ? e.message : "Backend fetch failed");
        }
      }
      setModels(generateModelStatuses());
      setPipeline(generatePipelineStages());
      setSystem(generateSystemStatus());
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
          const [m, p, s] = await Promise.all([getModelStatuses(), getPipelineStages(), getSystemStatus()]);
          if (m.length) setModels(m);
          if (p.length) setPipeline(p);
          setSystem(s);
        } catch {}
      } else {
        setModels(generateModelStatuses());
        setPipeline(generatePipelineStages());
        setSystem(generateSystemStatus());
      }
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleRefresh = useCallback(() => {
    toast(`Data refreshed (${dataMode === "backend" ? "backend" : "simulation"})`);
    load();
  }, [load, dataMode]);

  if (loading) return <LoadingSpinner text="Loading AI detection engine..." />;

  return (
    <div className="space-y-6 page-enter">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-medium text-[var(--color-text-primary)] tracking-tight">AI Detection Engine</h1>
            <DataModeIndicator />
          </div>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">Model pipeline · Inference performance · Model health monitoring</p>
        </div>
        <div className="flex items-center gap-2">
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

      <Card className="card-inner-highlight">
        <CardHeader>
          <CardTitle>Detection Pipeline</CardTitle>
        </CardHeader>
        <CardContent>
          {pipeline.length === 0 ? <EmptyState title="No pipeline data" description="Pipeline stages unavailable." /> : <PipelineVisualization pipeline={pipeline} />}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <MetricCard label="Total Throughput" value={formatNumber(system?.throughput || 0) + "/s"} trend={2.1} trendLabel="vs baseline" icon={<Zap className="w-6 h-6 text-[var(--color-accent-cyan)]" />} />
        <MetricCard label="Avg Latency" value={formatDuration(getAvgLatency(pipeline))} trend={-3.2} trendLabel="vs 1h ago" icon={<Cpu className="w-6 h-6 text-[var(--color-threat-tls)]" />} />
        <MetricCard label="Active Models" value={models.filter(m => m.status === "active").length + " / " + models.length} trend={0} trendLabel="healthy" icon={<CheckCircle className="w-6 h-6 text-[var(--color-success)]" />} />
        <MetricCard label="Queue Depth" value={getTotalQueue(pipeline)} trend={5.1} trendLabel="vs baseline" icon={<Database className="w-6 h-6 text-[var(--color-threat-dga)]" />} />
        <MetricCard label="Alert Rate" value={formatNumber(system?.activeAlerts || 0) + "/min"} trend={12.3} trendLabel="vs 1h ago" icon={<AlertCircle className="w-6 h-6 text-[var(--color-danger)]" />} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="card-inner-highlight">
          <CardHeader>
            <CardTitle>Model Performance</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {models.length === 0 ? <EmptyState title="No models" description="No model statuses available." /> : models.map((model) => (
              <ModelCard key={model.name} model={model} />
            ))}
          </CardContent>
        </Card>

        <Card className="card-inner-highlight">
          <CardHeader>
            <CardTitle>Inference Latency Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <TrafficAreaChart
              data={generateLatencyTimeSeries()}
              series={[
                { key: "p50", name: "P50", color: "var(--color-success)" },
                { key: "p95", name: "P95", color: "var(--color-warning)" },
                { key: "p99", name: "P99", color: "var(--color-danger)" },
              ]}
              height={280}
            />
            <ScanlineOverlay speed={12} opacity={0.02} />
          </CardContent>
        </Card>
      </div>

      <Card className="card-inner-highlight">
        <CardHeader>
          <CardTitle>System Health</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <SystemHealthItem label="Ingest Health" value={system?.ingestHealth?.toUpperCase() || "—"} icon={<Database />} status={system?.ingestHealth === "healthy" ? "success" : "warning"} />
          <SystemHealthItem label="CPU Usage" value={(system?.cpuUsage || 0).toFixed(1) + "%"} icon={<Cpu />} status={(system?.cpuUsage || 0) < 70 ? "success" : "warning"} />
          <SystemHealthItem label="Memory Usage" value={(system?.memoryUsage || 0).toFixed(1) + "%"} icon={<Database />} status={(system?.memoryUsage || 0) < 80 ? "success" : "warning"} />
          <SystemHealthItem label="Disk Usage" value={(system?.diskUsage || 0).toFixed(1) + "%"} icon={<Database />} status={(system?.diskUsage || 0) < 85 ? "success" : "warning"} />
          <SystemHealthItem label="Processed Flows" value={formatNumber(system?.processedFlows || 0)} icon={<Zap />} status="info" />
          <SystemHealthItem label="Dropped Packets" value={formatNumber(system?.droppedPackets || 0)} icon={<AlertCircle />} status={(system?.droppedPackets || 0) < 1000 ? "success" : "warning"} />
          <SystemHealthItem label="Uptime" value={(system?.uptime || 0).toFixed(3) + "%"} icon={<CheckCircle />} status="success" />
          <SystemHealthItem label="Data Diode" value={system?.diodeStatus?.toUpperCase() || "—"} icon={<Cpu />} status={system?.diodeStatus === "connected" ? "success" : "danger"} />
        </CardContent>
      </Card>
    </div>
  );
}

function PipelineVisualization({ pipeline }: { pipeline: PipelineStage[] }) {
  return (
    <div className="relative py-8">
      <div className="flex items-center justify-between relative z-10">
        {PIPELINE_STEPS.map((step, i) => (
          <div key={step.name} className="flex flex-col items-center relative">
            <div className="flex items-center justify-center w-16 h-16 rounded-[8px] bg-[var(--color-bg-elevated-2)] border-2 border-[var(--color-border-card)] relative z-10"
              style={{ borderColor: i < pipeline.length && pipeline[i].status === "active" ? step.color : "var(--color-border-card)" }}>
              <step.icon className="w-7 h-7" style={{ color: i < pipeline.length && pipeline[i].status === "active" ? step.color : "var(--color-text-muted)" }} />
            </div>
            <p className="text-xs font-medium text-[var(--color-text-primary)] mt-2 text-center max-w-[100px]">{step.name}</p>
            <p className="text-[10px] text-[var(--color-text-muted)] text-center max-w-[100px]">{step.description}</p>
            {i < pipeline.length && (
              <Badge variant={pipeline[i].status === "active" ? "success" : "info"} size="sm" className="mt-1">
                {pipeline[i].status.toUpperCase()}
              </Badge>
            )}
            {i < PIPELINE_STEPS.length - 1 && (
              <div className="absolute top-8 left-[calc(50%+8px)] w-[calc(100%-16px)] h-0.5 bg-[var(--color-border-card)] -z-10" />
            )}
          </div>
        ))}
      </div>

      <div className="grid grid-cols-5 gap-0 mt-8 text-center">
        {pipeline.map((stage) => (
          <div key={stage.name} className="px-2">
            <p className="text-xs text-[var(--color-text-muted)] uppercase tracking-wider">{stage.name.toUpperCase()}</p>
            <div className="grid grid-cols-3 gap-2 mt-2 text-center">
              <div className="p-2 bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)] rounded-[6px]">
                <p className="font-mono text-lg text-[var(--color-text-primary)] tabular-nums">{formatNumber(stage.throughput)}/s</p>
                <p className="text-[10px] text-[var(--color-text-muted)]">THROUGHPUT</p>
              </div>
              <div className="p-2 bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)] rounded-[6px]">
                <p className="font-mono text-lg text-[var(--color-text-primary)] tabular-nums">{stage.latency.toFixed(1)}ms</p>
                <p className="text-[10px] text-[var(--color-text-muted)]">LATENCY</p>
              </div>
              <div className="p-2 bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)] rounded-[6px]">
                <p className="font-mono text-lg text-[var(--color-text-primary)] tabular-nums">{stage.queueDepth}</p>
                <p className="text-[10px] text-[var(--color-text-muted)]">QUEUE</p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ModelCard({ model }: { model: ModelStatus }) {
  return (
    <div className="p-4 rounded-[6px] bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)]">
      <div className="flex items-start justify-between mb-4">
        <div>
          <p className="font-medium text-[var(--color-text-primary)]">{model.name}</p>
          <p className="text-xs text-[var(--color-text-muted)]">v{model.version}</p>
        </div>
        <Badge variant={model.status === "active" ? "success" : model.status === "training" ? "warning" : model.status === "degraded" ? "danger" : "info"} size="sm" dot>
          {model.status.toUpperCase()}
        </Badge>
      </div>
      <div className="grid grid-cols-4 gap-4 mb-4">
        <div>
          <p className="text-2xl font-light tabular-nums font-mono text-[var(--color-text-primary)]">{(model.accuracy * 100).toFixed(1)}%</p>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase tracking-wider">ACCURACY</p>
        </div>
        <div>
          <p className="text-2xl font-light tabular-nums font-mono text-[var(--color-text-primary)]">{(model.precision * 100).toFixed(1)}%</p>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase tracking-wider">PRECISION</p>
        </div>
        <div>
          <p className="text-2xl font-light tabular-nums font-mono text-[var(--color-text-primary)]">{(model.recall * 100).toFixed(1)}%</p>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase tracking-wider">RECALL</p>
        </div>
        <div>
          <p className="text-2xl font-light tabular-nums font-mono text-[var(--color-text-primary)]">{(model.f1Score * 100).toFixed(1)}%</p>
          <p className="text-[10px] text-[var(--color-text-muted)] uppercase tracking-wider">F1 SCORE</p>
        </div>
      </div>
      <div className="flex items-center justify-between text-sm">
        <div className="flex items-center gap-2">
          <span className="text-[var(--color-text-muted)]">Latency:</span>
          <span className="font-mono text-[var(--color-text-primary)] tabular-nums">{model.inferenceLatency.toFixed(1)}ms</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[var(--color-text-muted)]">Throughput:</span>
          <span className="font-mono text-[var(--color-text-primary)] tabular-nums">{formatNumber(model.throughput)}/s</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[var(--color-text-muted)]">Updated:</span>
          <span className="font-mono text-[var(--color-text-primary)] tabular-nums">{model.lastUpdated.toLocaleTimeString()}</span>
        </div>
      </div>
    </div>
  );
}

function SystemHealthItem({ label, value, icon, status }: { label: string; value: string; icon: React.ReactNode; status: "success" | "warning" | "danger" | "info" }) {
  const statusColors = {
    success: "var(--color-success)",
    warning: "var(--color-warning)",
    danger: "var(--color-danger)",
    info: "var(--color-accent-cyan)",
  };

  return (
    <div className="p-4 rounded-[6px] bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)]">
      <div className="flex items-center gap-2 mb-2">
        <span className="w-5 h-5" style={{ color: statusColors[status] }}>{icon}</span>
        <p className="text-xs text-[var(--color-text-muted)] uppercase tracking-wider">{label}</p>
      </div>
      <p className="font-mono text-xl text-[var(--color-text-primary)] tabular-nums">{value}</p>
    </div>
  );
}

function getAvgLatency(pipeline: PipelineStage[]): number {
  if (pipeline.length === 0) return 0;
  return pipeline.reduce((sum, s) => sum + s.latency, 0) / pipeline.length;
}

function getTotalQueue(pipeline: PipelineStage[]): number {
  return pipeline.reduce((sum, s) => sum + s.queueDepth, 0);
}

function generateLatencyTimeSeries() {
  const data = [];
  const now = new Date();
  for (let i = 59; i >= 0; i--) {
    const time = new Date(now.getTime() - i * 60 * 1000);
    data.push({
      time: time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      p50: Math.random() * 1 + 1.5,
      p95: Math.random() * 2 + 3,
      p99: Math.random() * 3 + 6,
    });
  }
  return data;
}
