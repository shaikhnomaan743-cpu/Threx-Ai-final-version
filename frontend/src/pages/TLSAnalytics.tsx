import { useEffect, useState, useMemo, useCallback } from "react";
import { Shield, AlertTriangle, Download, BarChart2, RefreshCw } from "lucide-react";
import { Button } from "../components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { DataTable } from "../components/tables/DataTable";
import { Select, SelectOption } from "../components/ui/Select";
import { Input } from "../components/ui/Input";
import { MetricCard } from "../components/charts/MetricCard";
import { TrafficAreaChart } from "../components/charts/TrafficAreaChart";
import { ScanlineOverlay } from "../components/ui/ScanlineOverlay";
import { generateTlsFingerprints } from "../data/mockData";
import { downloadAlerts, toast } from "../lib/export";
import { formatNumber } from "../lib/utils";
import { TlsFingerprint } from "../types";
import { DataModeIndicator } from "../components/DataModeIndicator";
import { LoadingSpinner, EmptyState } from "../components/ui/LoadingStates";
import { getTlsFingerprints, getThreats, getDataMode, isBackendAvailable } from "../services/apiClient";
import { liveSimulation } from "../services/liveSimulation";

const VERSION_OPTIONS: SelectOption[] = [
  { value: "", label: "All Versions" },
  { value: "TLS 1.2", label: "TLS 1.2" },
  { value: "TLS 1.3", label: "TLS 1.3" },
  { value: "TLSv1.2", label: "TLSv1.2" },
  { value: "TLSv1.3", label: "TLSv1.3" },
];

export function TLSAnalytics() {
  const [tlsFingerprints, setTlsFingerprints] = useState<TlsFingerprint[]>(() => generateTlsFingerprints(25));
  const [searchQuery, setSearchQuery] = useState("");
  const [versionFilter, setVersionFilter] = useState("");
  const [sortBy, setSortBy] = useState<string>("count");
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
          const fps = await getTlsFingerprints();
          if (fps.length > 0) {
            setTlsFingerprints(fps);
            setDataMode(getDataMode());
            setLoading(false);
            return;
          }
        } catch (e) {
          setError(e instanceof Error ? e.message : "Backend fetch failed");
        }
      }
      setTlsFingerprints(generateTlsFingerprints(25));
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
        const tlsAlerts = alerts.filter(a => a.threatClass === "TLS/Malware");
        if (tlsAlerts.length > 0) {
          downloadAlerts(tlsAlerts, "csv", "threx-tls");
          toast(`CSV exported (${tlsAlerts.length} TLS alerts from backend)`);
          return;
        }
      } catch {}
    }
    const simAlerts = liveSimulation.getAlerts().filter(a => a.threatClass === "TLS/Malware");
    downloadAlerts(simAlerts.length ? simAlerts : liveSimulation.getAlerts().slice(0, 10), "csv", "threx-tls-sim");
    toast("CSV exported (simulation)");
  }, []);

  const filtered = useMemo(() => {
    return tlsFingerprints.filter(f => {
      if (searchQuery && !f.ja3.includes(searchQuery) && !f.ja4.includes(searchQuery) && 
          !f.sourceIps.some(ip => ip.includes(searchQuery)) && !f.destinations.some(d => d.includes(searchQuery))) return false;
      if (versionFilter && f.tlsVersion !== versionFilter && f.tlsVersion.replace("TLS ", "TLSv") !== versionFilter && f.tlsVersion !== versionFilter.replace("TLSv", "TLS ")) return false;
      return true;
    });
  }, [tlsFingerprints, searchQuery, versionFilter]);

  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      let aVal = (a as any)[sortBy];
      let bVal = (b as any)[sortBy];
      if (aVal === bVal) return 0;
      const comparison = (aVal as number) < (bVal as number) ? -1 : 1;
      return sortOrder === "asc" ? comparison : -comparison;
    });
  }, [filtered, sortBy, sortOrder]);

  const columns = [
    { key: "ja3", header: "JA3 Fingerprint", sortable: true, width: "280px",
      render: (v: any) => <span className="font-mono text-xs text-[var(--color-text-primary)] truncate max-w-[260px]">{v}</span> },
    { key: "ja4", header: "JA4", sortable: true, width: "200px",
      render: (v: any) => <span className="font-mono text-xs text-[var(--color-text-primary)] truncate max-w-[180px]">{v}</span> },
    { key: "count", header: "Connections", sortable: true, width: "110px", align: "right" as const,
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{formatNumber(v as number)}</span> },
    { key: "tlsVersion", header: "Version", sortable: true, width: "100px",
      render: (v: any) => <Badge variant="info" size="sm">{v}</Badge> },
    { key: "cipherSuite", header: "Cipher Suite", sortable: true, width: "250px",
      render: (v: any) => <span className="font-mono text-xs text-[var(--color-text-primary)] truncate max-w-[230px]">{v}</span> },
    { key: "firstSeen", header: "First Seen", sortable: true, width: "150px",
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{(v as Date).toLocaleDateString()}</span> },
    { key: "lastSeen", header: "Last Seen", sortable: true, width: "150px",
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{(v as Date).toLocaleDateString()}</span> },
  ];

  const uniqueJA3 = new Set(tlsFingerprints.map(f => f.ja3)).size;
  const uniqueJA4 = new Set(tlsFingerprints.map(f => f.ja4)).size;
  const totalConns = tlsFingerprints.reduce((sum, f) => sum + f.count, 0);

  if (loading) return <LoadingSpinner text="Loading TLS analytics..." />;

  return (
    <div className="space-y-6 page-enter">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-medium text-[var(--color-text-primary)] tracking-tight">TLS/QUIC Analytics</h1>
              <DataModeIndicator />
            </div>
            <p className="text-sm text-[var(--color-text-secondary)] mt-1">JA3/JA3S/JA4 fingerprinting · Cipher analysis · Certificate inspection</p>
          </div>
          <div className="flex items-center gap-2 px-3 py-1.5 bg-[var(--color-danger)]/15 border border-[var(--color-danger)]/30 rounded-[6px]">
            <AlertTriangle className="w-4 h-4 text-[var(--color-danger)]" />
            <span className="text-xs font-medium text-[var(--color-danger)] uppercase tracking-wider">PAYLOAD INSPECTION: DISABLED — METADATA ONLY</span>
          </div>
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
        <MetricCard label="Unique JA3" value={uniqueJA3} trend={5.2} trendLabel="new today" icon={<Shield className="w-6 h-6 text-[var(--color-threat-tls)]" />} />
        <MetricCard label="Unique JA4" value={uniqueJA4} trend={3.1} trendLabel="new today" icon={<BarChart2 className="w-6 h-6 text-[var(--color-accent-cyan)]" />} />
        <MetricCard label="Total Connections" value={formatNumber(totalConns)} trend={2.8} trendLabel="vs 1h ago" icon={<Download className="w-6 h-6 text-[var(--color-success)]" />} />
      </div>

      <Card className="card-inner-highlight">
        <CardContent className="p-4 pb-0">
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 mb-4">
            <Input placeholder="Search JA3, JA4, IPs, ciphers…" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="sm:col-span-2" />
            <Select value={versionFilter} onChange={setVersionFilter} options={VERSION_OPTIONS} placeholder="TLS Version" />
          </div>

          {sorted.length === 0 ? <EmptyState title="No fingerprints" description="No TLS fingerprints match filters." /> : (
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
            <CardTitle>Cipher Suite Distribution</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {getCipherDistribution(tlsFingerprints).map((cipher) => (
              <div key={cipher.suite} className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="font-mono text-[var(--color-text-primary)] truncate max-w-[300px]">{cipher.suite}</span>
                  <span className="text-[var(--color-text-secondary)] font-mono tabular-nums">{cipher.percentage}%</span>
                </div>
                <div className="h-2 bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${cipher.percentage}%`, backgroundColor: getCipherColor(cipher.suite) }}
                  />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card className="card-inner-highlight">
          <CardHeader>
            <CardTitle>Packet Size Timing Sequences</CardTitle>
          </CardHeader>
          <CardContent>
            <TrafficAreaChart
              data={generatePacketTimingData()}
              series={[
                { key: "pktSize", name: "Avg Packet Size", color: "var(--color-threat-tls)" },
                { key: "interArrival", name: "Inter-arrival (ms)", color: "var(--color-accent-cyan)" },
              ]}
              height={240}
            />
            <ScanlineOverlay speed={10} opacity={0.02} />
          </CardContent>
        </Card>
      </div>

      <Card className="card-inner-highlight">
        <CardHeader>
          <CardTitle>TLS Version Distribution</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {getVersionDistribution(tlsFingerprints).map((v) => (
              <div key={v.version} className="text-center p-4 rounded-[6px] bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)]">
                <p className="text-3xl font-light tabular-nums font-mono text-[var(--color-text-primary)]">{v.percentage}%</p>
                <p className="text-xs text-[var(--color-text-muted)] uppercase tracking-wider mt-1">{v.version}</p>
                <p className="text-xs text-[var(--color-text-muted)] mt-1">{formatNumber(v.count)} connections</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function getCipherDistribution(fingerprints: TlsFingerprint[]) {
  const counts: Record<string, number> = {};
  fingerprints.forEach(f => { counts[f.cipherSuite] = (counts[f.cipherSuite] || 0) + f.count; });
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  return Object.entries(counts)
    .map(([suite, count]) => ({ suite, count, percentage: Math.round((count / total) * 100) }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);
}

function getCipherColor(suite: string): string {
  if (suite.includes("CHACHA20")) return "var(--color-threat-tls)";
  if (suite.includes("AES_256")) return "var(--color-accent-cyan)";
  if (suite.includes("AES_128")) return "var(--color-threat-c2)";
  return "var(--color-text-muted)";
}

function getVersionDistribution(fingerprints: TlsFingerprint[]) {
  const counts: Record<string, number> = {};
  fingerprints.forEach(f => { counts[f.tlsVersion] = (counts[f.tlsVersion] || 0) + f.count; });
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  return Object.entries(counts)
    .map(([version, count]) => ({ version, count, percentage: Math.round((count / total) * 100) }))
    .sort((a, b) => b.count - a.count);
}

function generatePacketTimingData() {
  const data = [];
  const now = new Date();
  for (let i = 59; i >= 0; i--) {
    const time = new Date(now.getTime() - i * 60 * 1000);
    data.push({
      time: time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      pktSize: Math.random() * 200 + 1200,
      interArrival: Math.random() * 50 + 10,
    });
  }
  return data;
}
