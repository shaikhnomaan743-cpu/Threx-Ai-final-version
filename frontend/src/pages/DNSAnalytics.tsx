import { useEffect, useState, useMemo, useCallback } from "react";
import { AlertTriangle, Download, TrendingUp, RefreshCw } from "lucide-react";
import { Button } from "../components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { DataTable } from "../components/tables/DataTable";
import { Select, SelectOption } from "../components/ui/Select";
import { Input } from "../components/ui/Input";
import { MetricCard } from "../components/charts/MetricCard";
import { TrafficAreaChart } from "../components/charts/TrafficAreaChart";
import { ScanlineOverlay } from "../components/ui/ScanlineOverlay";
import { generateDgaDetections, generateDnsTunnelingIndicators } from "../data/mockData";
import { downloadAlerts, toast } from "../lib/export";
import { formatNumber } from "../lib/utils";
import { DgaDetection, DnsTunnelingIndicator } from "../types";
import { DataModeIndicator } from "../components/DataModeIndicator";
import { LoadingSpinner, EmptyState } from "../components/ui/LoadingStates";
import { getDgaDetections, getDnsTunnelingIndicators, getThreats, getDataMode, isBackendAvailable } from "../services/apiClient";
import { liveSimulation } from "../services/liveSimulation";

const ENTROPY_OPTIONS: SelectOption[] = [
  { value: "", label: "All" },
  { value: "high", label: "High (>3.5)" },
  { value: "medium", label: "Medium (3.0-3.5)" },
  { value: "low", label: "Low (<3.0)" },
];

export function DNSAnalytics() {
  const [dgaDetections, setDgaDetections] = useState<DgaDetection[]>(() => generateDgaDetections(30));
  const [tunnelIndicators, setTunnelIndicators] = useState<DnsTunnelingIndicator[]>(() => generateDnsTunnelingIndicators(20));
  const [searchQuery, setSearchQuery] = useState("");
  const [entropyFilter, setEntropyFilter] = useState("");
  const [sortBy, setSortBy] = useState<string>("timestamp");
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
          const [dga, tun] = await Promise.all([getDgaDetections(), getDnsTunnelingIndicators()]);
          if (dga.length > 0 || tun.length > 0) {
            setDgaDetections(dga.length ? dga : generateDgaDetections(30));
            setTunnelIndicators(tun.length ? tun : generateDnsTunnelingIndicators(20));
            setDataMode(getDataMode());
            setLoading(false);
            return;
          }
        } catch (e) {
          setError(e instanceof Error ? e.message : "Backend fetch failed");
        }
      }
      setDgaDetections(generateDgaDetections(30));
      setTunnelIndicators(generateDnsTunnelingIndicators(20));
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
        const dnsAlerts = alerts.filter(a => a.threatClass === "DGA / DNS Tunneling");
        if (dnsAlerts.length > 0) {
          downloadAlerts(dnsAlerts, "csv", "threx-dns");
          toast(`CSV exported (${dnsAlerts.length} DNS alerts from backend)`);
          return;
        }
      } catch {}
    }
    toast("CSV exported (simulation — no backend DNS alerts)");
    const alerts = liveSimulation.getAlerts().filter(a => a.threatClass === "DGA / DNS Tunneling");
    downloadAlerts(alerts.length ? alerts : liveSimulation.getAlerts().slice(0, 10), "csv", "threx-dns-sim");
  }, []);

  const filteredDga = useMemo(() => {
    return dgaDetections.filter(d => {
      if (searchQuery && !d.domain.toLowerCase().includes(searchQuery.toLowerCase()) && !d.sourceIp.includes(searchQuery)) return false;
      if (entropyFilter === "high" && d.entropy <= 3.5) return false;
      if (entropyFilter === "medium" && (d.entropy > 3.5 || d.entropy < 3.0)) return false;
      if (entropyFilter === "low" && d.entropy >= 3.0) return false;
      return true;
    });
  }, [dgaDetections, searchQuery, entropyFilter]);

  const filteredTunnels = useMemo(() => {
    return tunnelIndicators.filter(d => {
      if (searchQuery && !d.domain.toLowerCase().includes(searchQuery.toLowerCase()) && !d.sourceIp.includes(searchQuery)) return false;
      return true;
    });
  }, [tunnelIndicators, searchQuery]);

  const sortedDga = useMemo(() => {
    return [...filteredDga].sort((a, b) => {
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
  }, [filteredDga, sortBy, sortOrder]);

  const sortedTunnels = useMemo(() => {
    return [...filteredTunnels].sort((a, b) => {
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
  }, [filteredTunnels, sortBy, sortOrder]);

  const dgaColumns = [
    { key: "timestamp", header: "Timestamp", sortable: true, width: "160px",
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{(v as Date).toLocaleString()}</span> },
    { key: "domain", header: "Domain", sortable: true, width: "200px",
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] truncate max-w-[180px]">{v}</span> },
    { key: "sourceIp", header: "Source IP", sortable: true, width: "140px",
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{v}</span> },
    { key: "entropy", header: "Entropy", sortable: true, width: "90px", align: "right" as const,
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{(v as number).toFixed(2)}</span> },
    { key: "ngramScore", header: "N-gram", sortable: true, width: "90px", align: "right" as const,
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{(v as number).toFixed(2)}</span> },
    { key: "length", header: "Length", sortable: true, width: "80px", align: "right" as const,
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{v}</span> },
    { key: "confidence", header: "Confidence", sortable: true, width: "110px", align: "right" as const,
      render: (v: any) => <Badge variant="info" size="sm">{(v as number * 100).toFixed(1)}%</Badge> },
    { key: "queryCount", header: "Queries", sortable: true, width: "90px", align: "right" as const,
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{v}</span> },
  ];

  const tunnelColumns = [
    { key: "timestamp", header: "Timestamp", sortable: true, width: "160px",
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{(v as Date).toLocaleString()}</span> },
    { key: "domain", header: "Domain", sortable: true, width: "200px",
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] truncate max-w-[180px]">{v}</span> },
    { key: "sourceIp", header: "Source IP", sortable: true, width: "140px",
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{v}</span> },
    { key: "queryFrequency", header: "Freq (q/min)", sortable: true, width: "110px", align: "right" as const,
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{(v as number).toFixed(1)}</span> },
    { key: "txtQueryVolume", header: "TXT Volume", sortable: true, width: "100px", align: "right" as const,
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{v}</span> },
    { key: "subdomainEntropy", header: "Subdomain Entropy", sortable: true, width: "130px", align: "right" as const,
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{(v as number).toFixed(2)}</span> },
    { key: "confidence", header: "Confidence", sortable: true, width: "110px", align: "right" as const,
      render: (v: any) => <Badge variant="info" size="sm">{(v as number * 100).toFixed(1)}%</Badge> },
  ];

  const highEntropyCount = dgaDetections.filter(d => d.entropy > 3.5).length;
  const totalQueries = dgaDetections.reduce((sum, d) => sum + d.queryCount, 0);

  if (loading) return <LoadingSpinner text="Loading DNS analytics..." />;

  return (
    <div className="space-y-6 page-enter">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-medium text-[var(--color-text-primary)] tracking-tight">DNS Analytics</h1>
            <DataModeIndicator />
          </div>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">DGA detection · DNS tunneling indicators · Domain reputation</p>
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

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <MetricCard label="DGA Detections" value={dgaDetections.length} trend={15.2} trendLabel="vs 24h ago" icon={<AlertTriangle className="w-6 h-6 text-[var(--color-threat-dga)]" />} />
        <MetricCard label="High Entropy Domains" value={highEntropyCount} trend={8.7} trendLabel="vs 24h ago" icon={<TrendingUp className="w-6 h-6 text-[var(--color-danger)]" />} />
        <MetricCard label="Total DNS Queries" value={formatNumber(totalQueries)} trend={3.4} trendLabel="vs baseline" icon={<Download className="w-6 h-6 text-[var(--color-accent-cyan)]" />} />
      </div>

      <Card className="card-inner-highlight">
        <CardContent className="p-4 pb-0">
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 mb-4">
            <Input placeholder="Search domains, IPs…" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} />
            <Select value={entropyFilter} onChange={setEntropyFilter} options={ENTROPY_OPTIONS} placeholder="Entropy Filter" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div>
              <h3 className="text-sm font-medium text-[var(--color-text-secondary)] uppercase tracking-wider mb-3">DGA Detections</h3>
              {sortedDga.length === 0 ? <EmptyState title="No DGA detections" description="No matching DGA detections." /> : (
                <DataTable
                  data={sortedDga}
                  columns={dgaColumns}
                  keyExtractor={(row) => row.id}
                  sortBy={sortBy}
                  sortOrder={sortOrder}
                  onSort={(key, order) => { setSortBy(key); setSortOrder(order); }}
                />
              )}
            </div>

            <div>
              <h3 className="text-sm font-medium text-[var(--color-text-secondary)] uppercase tracking-wider mb-3">DNS Tunneling Indicators</h3>
              {sortedTunnels.length === 0 ? <EmptyState title="No tunneling indicators" description="No matching tunneling indicators." /> : (
                <DataTable
                  data={sortedTunnels}
                  columns={tunnelColumns}
                  keyExtractor={(row) => row.id}
                  sortBy={sortBy}
                  sortOrder={sortOrder}
                  onSort={(key, order) => { setSortBy(key); setSortOrder(order); }}
                />
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="card-inner-highlight">
        <CardHeader>
          <CardTitle>Entropy Distribution — Last 24 Hours</CardTitle>
        </CardHeader>
        <CardContent>
          <TrafficAreaChart
            data={generateEntropyTimeSeries()}
            series={[
              { key: "avgEntropy", name: "Avg Entropy", color: "var(--color-threat-dga)" },
              { key: "maxEntropy", name: "Max Entropy", color: "var(--color-danger)" },
              { key: "dgaCount", name: "DGA Count", color: "var(--color-accent-cyan)" },
            ]}
            height={240}
          />
          <ScanlineOverlay speed={12} opacity={0.02} />
        </CardContent>
      </Card>
    </div>
  );
}

function generateEntropyTimeSeries() {
  const data = [];
  const now = new Date();
  for (let i = 23; i >= 0; i--) {
    const time = new Date(now.getTime() - i * 60 * 60 * 1000);
    data.push({
      time: time.toLocaleTimeString([], { hour: '2-digit' }),
      avgEntropy: Math.random() * 0.5 + 3.0,
      maxEntropy: Math.random() * 0.8 + 3.5,
      dgaCount: Math.floor(Math.random() * 10),
    });
  }
  return data;
}
