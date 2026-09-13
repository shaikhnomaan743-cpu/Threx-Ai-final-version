import { useEffect, useState, useMemo, useCallback } from "react";
import { Target, Network, AlertTriangle, RefreshCw, Download } from "lucide-react";
import { Button } from "../components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { DataTable } from "../components/tables/DataTable";
import { Select, SelectOption } from "../components/ui/Select";
import { Input } from "../components/ui/Input";
import { MetricCard } from "../components/charts/MetricCard";
import { ScanlineOverlay } from "../components/ui/ScanlineOverlay";
import { generatePortScanDetections } from "../data/mockData";
import { downloadAlerts, toast } from "../lib/export";
import { formatNumber, formatDuration } from "../lib/utils";
import { PortScanDetection } from "../types";
import { DataModeIndicator } from "../components/DataModeIndicator";
import { LoadingSpinner, EmptyState } from "../components/ui/LoadingStates";
import { getPortScanDetections, getThreats, getDataMode, isBackendAvailable } from "../services/apiClient";
import { liveSimulation } from "../services/liveSimulation";

const SCAN_TYPE_OPTIONS: SelectOption[] = [
  { value: "", label: "All Types" },
  { value: "syn", label: "SYN Scan" },
  { value: "ack", label: "ACK Scan" },
  { value: "fin", label: "FIN Scan" },
  { value: "null", label: "NULL Scan" },
  { value: "xmas", label: "XMAS Scan" },
  { value: "udp", label: "UDP Scan" },
  { value: "connect", label: "Connect Scan" },
];

export function Reconnaissance() {
  const [scans, setScans] = useState<PortScanDetection[]>(() => generatePortScanDetections(15));
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [sortBy, setSortBy] = useState<string>("timestamp");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const [selectedScan, setSelectedScan] = useState<PortScanDetection | null>(null);
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
          const apiScans = await getPortScanDetections();
          if (apiScans.length > 0) {
            setScans(apiScans);
            setDataMode(getDataMode());
            setLoading(false);
            return;
          }
        } catch (e) {
          setError(e instanceof Error ? e.message : "Backend fetch failed");
        }
      }
      setScans(generatePortScanDetections(15));
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
        const recon = alerts.filter(a => a.threatClass === "Reconnaissance");
        if (recon.length > 0) {
          downloadAlerts(recon, "csv", "threx-recon");
          toast(`CSV exported (${recon.length} recon alerts from backend)`);
          return;
        }
      } catch {}
    }
    const sim = liveSimulation.getAlerts().filter(a => a.threatClass === "Reconnaissance");
    downloadAlerts(sim.length ? sim : liveSimulation.getAlerts().slice(0, 10), "csv", "threx-recon-sim");
    toast("CSV exported (simulation)");
  }, []);

  const filtered = useMemo(() => {
    return scans.filter(s => {
      if (searchQuery && !s.sourceIp.includes(searchQuery) && !s.targets.some(t => t.ip.includes(searchQuery))) return false;
      if (typeFilter && s.scanType !== typeFilter) return false;
      return true;
    });
  }, [scans, searchQuery, typeFilter]);

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
    { key: "scanType", header: "Scan Type", sortable: true, width: "120px",
      render: (v: any) => <Badge variant="info" size="sm" className="uppercase">{(v as string).toUpperCase()}</Badge> },
    { key: "targetCount", header: "Targets", sortable: true, width: "90px", align: "right" as const,
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{v}</span> },
    { key: "portCount", header: "Ports", sortable: true, width: "90px", align: "right" as const,
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{v}</span> },
    { key: "duration", header: "Duration", sortable: true, width: "100px", align: "right" as const,
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{formatDuration(v as number)}</span> },
    { key: "packetsPerSecond", header: "PPS", sortable: true, width: "100px", align: "right" as const,
      render: (v: any) => <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{formatNumber(v as number)}</span> },
    { key: "confidence", header: "Confidence", sortable: true, width: "110px", align: "right" as const,
      render: (v: any) => <Badge variant="info" size="sm">{(v as number * 100).toFixed(1)}%</Badge> },
  ];

  const totalScans = scans.length;
  const totalTargets = scans.reduce((sum, s) => sum + s.targetCount, 0);
  const synScans = scans.filter(s => s.scanType === "syn").length;

  if (loading) return <LoadingSpinner text="Loading reconnaissance data..." />;

  return (
    <div className="space-y-6 page-enter">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-medium text-[var(--color-text-primary)] tracking-tight">Reconnaissance</h1>
            <DataModeIndicator />
          </div>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">Port scan detection · Fan-out visualization · Source attribution</p>
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
        <MetricCard label="Scan Detections" value={totalScans} trend={12.5} trendLabel="vs 24h ago" icon={<Target className="w-6 h-6 text-[var(--color-threat-recon)]" />} />
        <MetricCard label="Unique Targets" value={totalTargets} trend={8.3} trendLabel="vs 24h ago" icon={<Network className="w-6 h-6 text-[var(--color-accent-cyan)]" />} />
        <MetricCard label="SYN Scans" value={synScans} trend={15.2} trendLabel="vs 24h ago" icon={<AlertTriangle className="w-6 h-6 text-[var(--color-danger)]" />} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2 card-inner-highlight">
          <CardHeader>
            <CardTitle>Port Scan Detections</CardTitle>
          </CardHeader>
          <CardContent className="p-4 pb-0">
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 mb-4">
              <Input placeholder="Search source IPs, targets…" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="sm:col-span-2" />
              <Select value={typeFilter} onChange={setTypeFilter} options={SCAN_TYPE_OPTIONS} placeholder="Scan Type" />
            </div>
            {sorted.length === 0 ? <EmptyState title="No scans" description="No port scan detections match filters." /> : (
              <DataTable
                data={sorted}
                columns={columns}
                keyExtractor={(row) => row.id}
                sortBy={sortBy}
                sortOrder={sortOrder}
                onSort={(key, order) => { setSortBy(key); setSortOrder(order); }}
                onRowClick={(row) => setSelectedScan(row)}
                rowClassName={(row) => row.id === selectedScan?.id ? "bg-[var(--color-accent-cyan-dim)] border-l-2 border-[var(--color-accent-cyan)]" : ""}
              />
            )}
          </CardContent>
        </Card>

        <Card className="card-inner-highlight">
          <CardHeader>
            <CardTitle>Scan Type Distribution</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {getScanTypeDistribution(scans).map((type, i) => (
              <div key={type.type} className="flex items-center justify-between p-3 rounded-[6px] hover:bg-[var(--color-bg-elevated-2)] transition-colors">
                <div className="flex items-center gap-3">
                  <span className="text-xs text-[var(--color-text-muted)] font-mono tabular-nums w-6">#{i + 1}</span>
                  <div>
                    <p className="font-mono text-sm text-[var(--color-text-primary)] uppercase">{type.type}</p>
                    <p className="text-xs text-[var(--color-text-muted)]">{type.description}</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="font-mono text-lg text-[var(--color-text-primary)] tabular-nums">{type.count}</p>
                  <p className="text-xs text-[var(--color-text-muted)]">{(type.percentage).toFixed(1)}%</p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {selectedScan && (
        <Card className="card-inner-highlight">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Fan-out Visualization — {selectedScan.sourceIp}</CardTitle>
              <Badge variant="info" size="sm" className="uppercase">{selectedScan.scanType} SCAN</Badge>
            </div>
          </CardHeader>
          <CardContent>
            <FanOutVisualization scan={selectedScan} />
            <ScanlineOverlay speed={12} opacity={0.02} />
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function getScanTypeDistribution(scans: PortScanDetection[]) {
  const counts: Record<string, number> = {};
  const descriptions: Record<string, string> = {
    syn: "Half-open connection attempts",
    ack: "Firewall rule mapping",
    fin: "Stealth FIN packets",
    null: "No flags set",
    xmas: "FIN+PSH+URG flags",
    udp: "UDP port probing",
    connect: "Full TCP connections",
  };
  scans.forEach(s => { counts[s.scanType] = (counts[s.scanType] || 0) + 1; });
  const total = scans.length;
  return Object.entries(counts)
    .map(([type, count]) => ({ type, count, percentage: (count / total) * 100, description: descriptions[type] || "" }))
    .sort((a, b) => b.count - a.count);
}

function FanOutVisualization({ scan }: { scan: PortScanDetection }) {
  const centerX = 400;
  const centerY = 200;
  const radius = 150;

  return (
    <div className="relative h-[400px]">
      <svg className="w-full h-full" viewBox="0 0 800 400" preserveAspectRatio="xMidYMid meet">
        <defs>
          <marker id="scan-arrow" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3 Z" fill="var(--color-threat-recon)" opacity="0.6" />
          </marker>
          <radialGradient id="source-glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="var(--color-threat-recon)" stopOpacity="0.3" />
            <stop offset="100%" stopColor="var(--color-threat-recon)" stopOpacity="0" />
          </radialGradient>
        </defs>

        {scan.targets.slice(0, 12).map((target, i) => {
          const angle = (i / Math.max(1, scan.targets.slice(0, 12).length)) * Math.PI * 2 - Math.PI / 2;
          const targetX = centerX + radius * Math.cos(angle);
          const targetY = centerY + radius * Math.sin(angle);
          const ctrlX = centerX + (radius * 0.6) * Math.cos(angle);
          const ctrlY = centerY + (radius * 0.6) * Math.sin(angle);

          return (
            <g key={target.ip}>
              <path
                d={`M${centerX},${centerY} Q${ctrlX},${ctrlY} ${targetX},${targetY}`}
                stroke="var(--color-threat-recon)"
                strokeWidth={1.5}
                strokeDasharray="6,4"
                fill="none"
                opacity={0.5}
                markerEnd="url(#scan-arrow)"
              />
              <circle
                cx={targetX}
                cy={targetY}
                r={target.responses > 0 ? 10 : 6}
                fill={target.responses > 0 ? "var(--color-danger)" : "var(--color-bg-elevated-2)"}
                stroke={target.responses > 0 ? "var(--color-danger)" : "var(--color-border-card)"}
                strokeWidth={1.5}
                opacity={0.8}
              />
              <text
                x={targetX}
                y={targetY + 20}
                textAnchor="middle"
                fontSize="9"
                fontFamily="var(--font-mono)"
                fill="var(--color-text-muted)"
              >
                {target.ip}
              </text>
              {target.responses > 0 && (
                <text
                  x={targetX}
                  y={targetY - 16}
                  textAnchor="middle"
                  fontSize="8"
                  fontFamily="var(--font-mono)"
                  fill="var(--color-danger)"
                  fontWeight="bold"
                >
                  {target.responses} resp
                </text>
              )}
            </g>
          );
        })}

        <circle
          cx={centerX}
          cy={centerY}
          r={24}
          fill="url(#source-glow)"
          stroke="var(--color-threat-recon)"
          strokeWidth={2}
        />
        <circle
          cx={centerX}
          cy={centerY}
          r={12}
          fill="var(--color-threat-recon)"
        />
        <text
          x={centerX}
          y={centerY + 4}
          textAnchor="middle"
          fontSize="10"
          fontFamily="var(--font-mono)"
          fill="var(--color-bg-deep)"
          fontWeight="bold"
        >
          SRC
        </text>
        <text
          x={centerX}
          y={centerY + 40}
          textAnchor="middle"
          fontSize="11"
          fontFamily="var(--font-mono)"
          fill="var(--color-text-primary)"
        >
          {scan.sourceIp}
        </text>
      </svg>

      <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
        <div>
          <p className="text-[var(--color-text-muted)]">Targets Contacted</p>
          <p className="font-mono text-xl text-[var(--color-text-primary)] tabular-nums">{scan.targetCount}</p>
        </div>
        <div>
          <p className="text-[var(--color-text-muted)]">Ports Scanned</p>
          <p className="font-mono text-xl text-[var(--color-text-primary)] tabular-nums">{scan.portCount}</p>
        </div>
        <div>
          <p className="text-[var(--color-text-muted)]">Duration</p>
          <p className="font-mono text-xl text-[var(--color-text-primary)] tabular-nums">{formatDuration(scan.duration)}</p>
        </div>
        <div>
          <p className="text-[var(--color-text-muted)]">Packets/sec</p>
          <p className="font-mono text-xl text-[var(--color-text-primary)] tabular-nums">{formatNumber(scan.packetsPerSecond)}</p>
        </div>
      </div>

      <div className="mt-4">
        <h4 className="text-sm font-medium text-[var(--color-text-secondary)] uppercase tracking-wider mb-2">Target Details</h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 max-h-48 overflow-y-auto">
          {scan.targets.slice(0, 15).map((target) => (
            <div key={target.ip} className="p-3 rounded-[6px] bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)]">
              <p className="font-mono text-sm text-[var(--color-text-primary)]">{target.ip}</p>
              <p className="text-xs text-[var(--color-text-muted)]">{target.ports.length} ports · {target.responses} responses</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
