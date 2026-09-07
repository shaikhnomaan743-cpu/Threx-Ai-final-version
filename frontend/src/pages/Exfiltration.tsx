import { useEffect, useState, useMemo, useCallback } from "react";
import { TrendingUp, Download, Upload, AlertTriangle, BarChart2, RefreshCw } from "lucide-react";
import { Button } from "../components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { DataTable } from "../components/tables/DataTable";
import { Select, SelectOption } from "../components/ui/Select";
import { Input } from "../components/ui/Input";
import { MetricCard } from "../components/charts/MetricCard";
import { TrafficAreaChart } from "../components/charts/TrafficAreaChart";
import { ScanlineOverlay } from "../components/ui/ScanlineOverlay";
import { generateExfiltrationAnomalies } from "../data/mockData";
import { downloadAlerts, toast } from "../lib/export";
import { formatNumber, formatBytes } from "../lib/utils";
import { ExfiltrationAnomaly } from "../types";
import { DataModeIndicator } from "../components/DataModeIndicator";
import { LoadingSpinner, EmptyState } from "../components/ui/LoadingStates";
import { getExfiltrationAnomalies, getThreats, getDataMode, isBackendAvailable } from "../services/apiClient";
import { liveSimulation } from "../services/liveSimulation";

const DIRECTION_OPTIONS: SelectOption[] = [
  { value: "", label: "All Directions" },
  { value: "outbound", label: "Outbound" },
  { value: "inbound", label: "Inbound" },
];

export function Exfiltration() {
  const [anomalies, setAnomalies] = useState<ExfiltrationAnomaly[]>(() => generateExfiltrationAnomalies(15));
  const [searchQuery, setSearchQuery] = useState("");
  const [directionFilter, setDirectionFilter] = useState("");
  const [sortBy, setSortBy] = useState<string>("deviation");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
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
          const apiAnoms = await getExfiltrationAnomalies();
          if (apiAnoms.length > 0) {
            setAnomalies(apiAnoms);
            setDataMode(getDataMode());
            setLoading(false);
            return;
          }
        } catch (e) {
          setError(e instanceof Error ? e.message : "Backend fetch failed");
        }
      }
      setAnomalies(generateExfiltrationAnomalies(15));
      setDataMode("simulation");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refreshData(); }, [refreshData]);

  const handleExport = useCallback(async () => {
    if (isBackendAvailable() || getDataMode() === "backend") {
      try {
        const alerts = await getThreats();
        const exfilAlerts = alerts.filter(a => a.threatClass === "Exfiltration");
        if (exfilAlerts.length > 0) {
          downloadAlerts(exfilAlerts, "csv", "threx-exfil");
          toast(`CSV exported (${exfilAlerts.length} exfil alerts from backend)`);
          return;
        }
      } catch {}
    }
    const sim = liveSimulation.getAlerts().filter(a => a.threatClass === "Exfiltration");
    downloadAlerts(sim.length ? sim : liveSimulation.getAlerts().slice(0, 10), "csv", "threx-exfil-sim");
    toast("CSV exported (simulation)");
  }, []);

  const filtered = useMemo(() => {
    return anomalies.filter(a => {
      if (searchQuery && !a.sourceIp.includes(searchQuery) && !a.destinationIp.includes(searchQuery)) return false;
      if (directionFilter && a.direction !== directionFilter) return false;
      return true;
    });
  }, [anomalies, searchQuery, directionFilter]);

  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      let aVal = (a as any)[sortBy];
      let bVal = (b as any)[sortBy];
      if (sortBy === "timestamp") {
        aVal = (aVal as Date).getTime();
        bVal = (bVal as Date).getTime();
      }
      if (aVal === bVal) return 0;
      const comparison = (aVal as number) < (bVal as number) ? -1 : 1;
      return sortOrder === "asc" ? comparison : -comparison;
    });
  }, [filtered, sortBy, sortOrder]);

  const columns = [
    { key: "timestamp", header: "Timestamp", sortable: true, width: "160px",
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{(v as Date).toLocaleString()}</span> },
    { key: "sourceIp", header: "Source IP", sortable: true, width: "140px",
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{v}</span> },
    { key: "destinationIp", header: "Destination IP", sortable: true, width: "140px",
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{v}</span> },
    { key: "direction", header: "Direction", sortable: true, width: "110px",
      render: (v: any) => <Badge variant={(v as string) === "outbound" ? "danger" : "success"} size="sm" className="uppercase">{v}</Badge> },
    { key: "byteRatio", header: "Byte Ratio", sortable: true, width: "110px", align: "right" as const,
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{(v as number).toFixed(1)}:1</span> },
    { key: "baselineRatio", header: "Baseline", sortable: true, width: "110px", align: "right" as const,
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-secondary)] tabular-nums">{(v as number).toFixed(1)}:1</span> },
    { key: "deviation", header: "Deviation (σ)", sortable: true, width: "120px", align: "right" as const,
      render: (v: any) => <Badge variant="danger" size="sm">{(v as number).toFixed(1)}σ</Badge> },
    { key: "totalBytes", header: "Total Bytes", sortable: true, width: "130px", align: "right" as const,
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{formatBytes(v as number)}</span> },
    { key: "confidence", header: "Confidence", sortable: true, width: "110px", align: "right" as const,
      render: (v: any) => <Badge variant="info" size="sm">{(v as number * 100).toFixed(1)}%</Badge> },
  ];

  const outboundCount = anomalies.filter(a => a.direction === "outbound").length;
  const inboundCount = anomalies.filter(a => a.direction === "inbound").length;
  const maxDeviation = anomalies.length ? Math.max(...anomalies.map(a => a.deviation)) : 0;
  const totalExfilBytes = anomalies.filter(a => a.direction === "outbound").reduce((sum, a) => sum + a.totalBytes, 0);

  if (loading) return <LoadingSpinner text="Loading exfiltration anomalies..." />;

  return (
    <div className="space-y-6 page-enter">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-medium text-[var(--color-text-primary)] tracking-tight">Exfiltration</h1>
            <DataModeIndicator />
          </div>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">Byte ratio anomalies · Baseline comparison · Data loss detection</p>
        </div>
        <div className="flex items-center gap-2">
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

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <MetricCard label="Outbound Anomalies" value={outboundCount} trend={23.1} trendLabel="vs 24h ago" icon={<Upload className="w-6 h-6 text-[var(--color-threat-exfil)]" />} />
        <MetricCard label="Inbound Anomalies" value={inboundCount} trend={-5.2} trendLabel="vs 24h ago" icon={<Download className="w-6 h-6 text-[var(--color-accent-cyan)]" />} />
        <MetricCard label="Max Deviation" value={maxDeviation.toFixed(1) + "σ"} trend={12.4} trendLabel="vs baseline" icon={<AlertTriangle className="w-6 h-6 text-[var(--color-danger)]" />} />
        <MetricCard label="Suspected Exfil" value={formatBytes(totalExfilBytes)} trend={8.7} trendLabel="vs 24h ago" icon={<BarChart2 className="w-6 h-6 text-[var(--color-threat-ddos)]" />} />
      </div>

      <Card className="card-inner-highlight">
        <CardContent className="p-4 pb-0">
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 mb-4">
            <Input placeholder="Search IPs…" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="sm:col-span-2" />
            <Select value={directionFilter} onChange={setDirectionFilter} options={DIRECTION_OPTIONS} placeholder="Direction" />
          </div>
          {sorted.length === 0 ? <EmptyState title="No anomalies" description="No exfiltration anomalies match filters." /> : (
            <DataTable
              data={sorted}
              columns={columns}
              keyExtractor={(row) => row.id}
              sortBy={sortBy}
              sortOrder={sortOrder}
              onSort={(key, order) => { setSortBy(key); setSortOrder(order); }}
            />
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="card-inner-highlight">
          <CardHeader>
            <CardTitle>Byte Ratio Over Time — Last 24 Hours</CardTitle>
          </CardHeader>
          <CardContent>
            <TrafficAreaChart
              data={generateRatioTimeSeries()}
              series={[
                { key: "outboundRatio", name: "Outbound Ratio", color: "var(--color-threat-exfil)" },
                { key: "inboundRatio", name: "Inbound Ratio", color: "var(--color-accent-cyan)" },
                { key: "baselineRatio", name: "Baseline", color: "var(--color-text-muted)" },
              ]}
              height={280}
            />
            <ScanlineOverlay speed={10} opacity={0.02} />
          </CardContent>
        </Card>

        <Card className="card-inner-highlight">
          <CardHeader>
            <CardTitle>Deviation from Baseline (σ)</CardTitle>
          </CardHeader>
          <CardContent>
            <TrafficAreaChart
              data={generateDeviationTimeSeries()}
              series={[
                { key: "deviation", name: "Deviation (σ)", color: "var(--color-danger)" },
                { key: "threshold", name: "Alert Threshold (3σ)", color: "var(--color-warning)" },
              ]}
              height={280}
            />
            <ScanlineOverlay speed={10} opacity={0.02} />
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="card-inner-highlight">
          <CardHeader>
            <CardTitle>Top Exfiltration Sources</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {getTopSources(anomalies).map((src, i) => (
              <div key={src.ip} className="flex items-center justify-between p-3 rounded-[6px] hover:bg-[var(--color-bg-elevated-2)] transition-colors">
                <div className="flex items-center gap-3">
                  <span className="text-xs text-[var(--color-text-muted)] font-mono tabular-nums w-6">#{i + 1}</span>
                  <div>
                    <p className="font-mono text-sm text-[var(--color-text-primary)]">{src.ip}</p>
                    <p className="text-xs text-[var(--color-text-muted)]">{src.count} anomalies · {formatBytes(src.totalBytes)}</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{src.maxRatio.toFixed(1)}:1 max ratio</p>
                  <p className="text-xs text-[var(--color-text-muted)]">{src.maxDeviation.toFixed(1)}σ max deviation</p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card className="card-inner-highlight">
          <CardHeader>
            <CardTitle>Protocol Breakdown</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {getProtocolBreakdown(anomalies).map((proto) => (
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
                  <span>{proto.count} anomalies</span>
                  <span>{formatBytes(proto.totalBytes)}</span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function generateRatioTimeSeries() {
  const data = [];
  const now = new Date();
  for (let i = 23; i >= 0; i--) {
    const time = new Date(now.getTime() - i * 60 * 60 * 1000);
    data.push({
      time: time.toLocaleTimeString([], { hour: '2-digit' }),
      outboundRatio: Math.random() * 3 + 1,
      inboundRatio: Math.random() * 2 + 0.5,
      baselineRatio: 1.2 + Math.random() * 0.5,
    });
  }
  return data;
}

function generateDeviationTimeSeries() {
  const data = [];
  const now = new Date();
  for (let i = 23; i >= 0; i--) {
    const time = new Date(now.getTime() - i * 60 * 60 * 1000);
    data.push({
      time: time.toLocaleTimeString([], { hour: '2-digit' }),
      deviation: Math.random() * 5,
      threshold: 3,
    });
  }
  return data;
}

function getTopSources(anomalies: ExfiltrationAnomaly[]) {
  const sources: Record<string, { ip: string; count: number; totalBytes: number; maxRatio: number; maxDeviation: number }> = {};
  anomalies.forEach(a => {
    if (!sources[a.sourceIp]) sources[a.sourceIp] = { ip: a.sourceIp, count: 0, totalBytes: 0, maxRatio: 0, maxDeviation: 0 };
    sources[a.sourceIp].count++;
    sources[a.sourceIp].totalBytes += a.totalBytes;
    sources[a.sourceIp].maxRatio = Math.max(sources[a.sourceIp].maxRatio, a.byteRatio);
    sources[a.sourceIp].maxDeviation = Math.max(sources[a.sourceIp].maxDeviation, a.deviation);
  });
  return Object.values(sources).sort((a, b) => b.totalBytes - a.totalBytes).slice(0, 8);
}

function getProtocolBreakdown(anomalies: ExfiltrationAnomaly[]) {
  const counts: Record<string, { count: number; totalBytes: number }> = {};
  anomalies.forEach(a => {
    if (!counts[a.protocol]) counts[a.protocol] = { count: 0, totalBytes: 0 };
    counts[a.protocol].count++;
    counts[a.protocol].totalBytes += a.totalBytes;
  });
  const total = anomalies.length;
  return Object.entries(counts)
    .map(([protocol, data]) => ({ protocol, ...data, percentage: Math.round((data.count / total) * 100) }))
    .sort((a, b) => b.count - a.count);
}

function getProtocolColor(protocol: string): string {
  const colors: Record<string, string> = {
    TCP: "var(--color-threat-exfil)",
    UDP: "var(--color-accent-cyan)",
    QUIC: "var(--color-threat-tls)",
  };
  return colors[protocol] || "var(--color-text-muted)";
}
