import { useEffect, useState, useCallback } from "react";
import { Activity, Network, Server, Download, RefreshCw } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "../components/ui/Card";
import { Button } from "../components/ui/Button";
import { MetricCard } from "../components/charts/MetricCard";
import { TrafficAreaChart } from "../components/charts/TrafficAreaChart";
import { ScanlineOverlay } from "../components/ui/ScanlineOverlay";
import { liveSimulation } from "../services/liveSimulation";
import { downloadAlerts, toast } from "../lib/export";
import { formatNumber, formatBits, formatBytes } from "../lib/utils";
import { TrafficMetrics } from "../types";
import { DataModeIndicator } from "../components/DataModeIndicator";
import { LoadingSpinner, EmptyState } from "../components/ui/LoadingStates";
import { getTrafficMetrics, getThreats, getDataMode, isBackendAvailable } from "../services/apiClient";

function generateTimeSeriesData() {
  const data = [];
  const now = new Date();
  for (let i = 59; i >= 0; i--) {
    const time = new Date(now.getTime() - i * 60 * 1000);
    data.push({
      time: time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      pps: Math.floor(Math.random() * 500000) + 1500000,
      fps: Math.floor(Math.random() * 10000) + 40000,
      bps: Math.floor(Math.random() * 1e9) + 3e9,
      flows: Math.floor(Math.random() * 200) + 800,
    });
  }
  return data;
}

export function TrafficAnalytics() {
  const [metrics, setMetrics] = useState<TrafficMetrics | null>(null);
  const [timeSeriesData, setTimeSeriesData] = useState<ReturnType<typeof generateTimeSeriesData>>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [dataMode, setDataMode] = useState<string>(getDataMode());

  const refreshData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const backendAlive = isBackendAvailable() || getDataMode() === "backend";
      if (backendAlive) {
        try {
          const apiMetrics = await getTrafficMetrics();
          if (apiMetrics && (apiMetrics.activeFlows !== 0 || apiMetrics.topTalkers.length > 0)) {
            setMetrics(apiMetrics);
            setTimeSeriesData(generateTimeSeriesData());
            setDataMode(getDataMode());
            setLoading(false);
            return;
          }
        } catch (e) {
          setError(e instanceof Error ? e.message : "Backend fetch failed");
        }
      }
      setMetrics(liveSimulation.getTrafficMetrics());
      setTimeSeriesData(generateTimeSeriesData());
      setDataMode("simulation");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refreshData(); }, [refreshData]);

  useEffect(() => {
    return liveSimulation.subscribe(() => {
      if (getDataMode() !== "backend" || !isBackendAvailable()) {
        setMetrics(liveSimulation.getTrafficMetrics());
      }
    });
  }, []);

  const handleExport = useCallback(async () => {
    if (isBackendAvailable() || getDataMode() === "backend") {
      try {
        const alerts = await getThreats();
        if (alerts.length > 0) {
          downloadAlerts(alerts, "csv", "threx-traffic");
          toast(`CSV exported (${alerts.length} alerts from backend)`);
          return;
        }
      } catch {}
    }
    // fallback to simulation alerts
    const alerts = liveSimulation.getAlerts();
    downloadAlerts(alerts, "csv", "threx-traffic");
    toast(`CSV exported (${alerts.length} alerts, simulation)`);
  }, []);

  if (loading) return <LoadingSpinner text="Loading traffic analytics..." />;

  return (
    <div className="space-y-6 page-enter">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-medium text-[var(--color-text-primary)] tracking-tight">Traffic Analytics</h1>
            <DataModeIndicator />
          </div>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">Real-time network traffic metrics and protocol analysis</p>
        </div>
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" onClick={refreshData}>
            <RefreshCw className="w-4 h-4 mr-1" />
            Refresh
          </Button>
          <Button variant="secondary" size="sm" onClick={handleExport}>
            <Download className="w-4 h-4 mr-1" />
            Export CSV
          </Button>
        </div>
      </div>

      {error && (
        <div className="px-4 py-3 rounded-[6px] bg-red-500/10 border border-red-500/20 text-sm text-red-400 font-mono">
          {error}
        </div>
      )}

      {!metrics ? (
        <EmptyState title="No traffic data" description="No traffic metrics available from backend." />
      ) : null}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          label="Packets/sec"
          value={metrics ? formatNumber(metrics.packetsPerSecond) : "—"}
          trend={2.4}
          trendLabel="vs baseline"
          icon={<Activity className="w-6 h-6 text-[var(--color-accent-cyan)]" />}
        />
        <MetricCard
          label="Flows/sec"
          value={metrics ? formatNumber(metrics.flowsPerSecond) : "—"}
          trend={1.8}
          trendLabel="vs 1h ago"
          icon={<Network className="w-6 h-6 text-[var(--color-threat-c2)]" />}
        />
        <MetricCard
          label="Bits/sec"
          value={metrics ? formatBits(metrics.bitsPerSecond) : "—"}
          trend={0.9}
          trendLabel="vs 1h ago"
          icon={<Server className="w-6 h-6 text-[var(--color-success)]" />}
        />
        <MetricCard
          label="Active Flows"
          value={metrics ? formatNumber(metrics.activeFlows) : "—"}
          trend={-0.3}
          trendLabel="vs 1h ago"
          icon={<Download className="w-6 h-6 text-[var(--color-threat-dga)]" />}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="card-inner-highlight">
          <CardHeader>
            <CardTitle>Packets & Flows per Second — Last 60 Minutes</CardTitle>
          </CardHeader>
          <CardContent>
            <TrafficAreaChart
              data={timeSeriesData}
              series={[
                { key: "pps", name: "Packets/sec", color: "var(--color-accent-cyan)" },
                { key: "fps", name: "Flows/sec", color: "var(--color-threat-c2)" },
              ]}
              height={280}
            />
            <ScanlineOverlay speed={10} opacity={0.02} />
          </CardContent>
        </Card>

        <Card className="card-inner-highlight">
          <CardHeader>
            <CardTitle>Throughput & Active Flows — Last 60 Minutes</CardTitle>
          </CardHeader>
          <CardContent>
            <TrafficAreaChart
              data={timeSeriesData}
              series={[
                { key: "bps", name: "Bits/sec", color: "var(--color-success)" },
                { key: "flows", name: "Active Flows", color: "var(--color-threat-dga)" },
              ]}
              height={280}
            />
            <ScanlineOverlay speed={10} opacity={0.02} />
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="card-inner-highlight">
          <CardHeader>
            <CardTitle>Protocol Distribution</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {metrics?.topProtocols.map((proto) => (
              <div key={proto.protocol} className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2">
                    <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: getProtocolColor(proto.protocol) }} />
                    <span className="font-mono font-medium text-[var(--color-text-primary)]">{proto.protocol}</span>
                  </div>
                  <span className="text-[var(--color-text-secondary)] font-mono tabular-nums">{proto.percentage}%</span>
                </div>
                <div className="h-2 bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${proto.percentage}%`, backgroundColor: getProtocolColor(proto.protocol) }}
                  />
                </div>
                <div className="flex justify-between text-xs text-[var(--color-text-muted)]">
                  <span>{formatNumber(proto.count)} packets</span>
                  <span>{formatBits(proto.bitsPerSecond)}</span>
                </div>
              </div>
            ))}
            {!metrics?.topProtocols.length && <EmptyState title="No protocol data" description="Protocol distribution unavailable." />}
          </CardContent>
        </Card>

        <Card className="card-inner-highlight">
          <CardHeader>
            <CardTitle>Top Source IPs</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {metrics?.topTalkers.filter(t => t.direction === "source").slice(0, 8).map((talker, i) => (
              <div key={talker.ip} className="flex items-center justify-between p-3 rounded-[6px] hover:bg-[var(--color-bg-elevated-2)] transition-colors">
                <div className="flex items-center gap-3">
                  <span className="text-xs text-[var(--color-text-muted)] font-mono tabular-nums w-6">#{i + 1}</span>
                  <div>
                    <p className="font-mono text-sm text-[var(--color-text-primary)]">{talker.ip}</p>
                    <p className="text-xs text-[var(--color-text-muted)]">{formatNumber(talker.flows)} flows</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{formatNumber(talker.packets)} pkts</p>
                  <p className="text-xs text-[var(--color-text-muted)]">{formatBytes(talker.bytes)}</p>
                </div>
              </div>
            ))}
            {!metrics?.topTalkers.length && <EmptyState title="No talkers" description="No top talkers available." />}
          </CardContent>
        </Card>

        <Card className="card-inner-highlight">
          <CardHeader>
            <CardTitle>Top Destination Ports</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {metrics?.topPorts.slice(0, 8).map((port, i) => (
              <div key={port.port} className="flex items-center justify-between p-3 rounded-[6px] hover:bg-[var(--color-bg-elevated-2)] transition-colors">
                <div className="flex items-center gap-3">
                  <span className="text-xs text-[var(--color-text-muted)] font-mono tabular-nums w-6">#{i + 1}</span>
                  <div>
                    <p className="font-mono text-sm text-[var(--color-text-primary)]">{port.port}/{port.protocol}</p>
                    <p className="text-xs text-[var(--color-text-muted)]">{getServiceName(port.port)}</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{formatNumber(port.count)}</p>
                  <p className="text-xs text-[var(--color-text-muted)]">{port.percentage}%</p>
                </div>
              </div>
            ))}
            {!metrics?.topPorts.length && <EmptyState title="No port data" description="Top destination ports unavailable." />}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function getProtocolColor(protocol: string): string {
  const colors: Record<string, string> = {
    TCP: "var(--color-accent-cyan)",
    UDP: "var(--color-threat-c2)",
    ICMP: "var(--color-threat-dga)",
    Other: "var(--color-text-muted)",
  };
  return colors[protocol] || "var(--color-accent-cyan)";
}

function getServiceName(port: number): string {
  const services: Record<number, string> = {
    53: "DNS", 80: "HTTP", 443: "HTTPS", 22: "SSH", 
    445: "SMB", 3389: "RDP", 8080: "HTTP-Alt", 500: "IPsec",
    123: "NTP", 161: "SNMP", 389: "LDAP", 636: "LDAPS",
  };
  return services[port] || "Unknown";
}
