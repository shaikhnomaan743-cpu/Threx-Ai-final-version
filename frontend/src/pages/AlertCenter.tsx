import { useState, useMemo, useCallback, useEffect } from "react";
import { Download, ExternalLink, X, Eye, RefreshCw } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { DataTable } from "../components/tables/DataTable";
import { Select, SelectOption } from "../components/ui/Select";
import { Input } from "../components/ui/Input";
import { Button } from "../components/ui/Button";
import { FlowFingerprint } from "../components/charts/FlowFingerprint";
import { ScanlineOverlay } from "../components/ui/ScanlineOverlay";
import { liveSimulation } from "../services/liveSimulation";
import { downloadAlerts, toast } from "../lib/export";
import { ThreatAlert, ThreatClass, Severity, ThreatStatus } from "../types";
import { useNavigate } from "react-router-dom";
import { DataModeIndicator } from "../components/DataModeIndicator";
import { LoadingSpinner, EmptyState } from "../components/ui/LoadingStates";
import { getThreats, getDataMode, isBackendAvailable } from "../services/apiClient";

const THREAT_CLASS_OPTIONS: SelectOption[] = [
  { value: "", label: "All Classes" },
  { value: "DDoS", label: "DDoS" },
  { value: "C2 Beaconing", label: "C2 Beaconing" },
  { value: "DGA / DNS Tunneling", label: "DGA / DNS Tunneling" },
  { value: "TLS/Malware", label: "TLS/Malware" },
  { value: "Reconnaissance", label: "Reconnaissance" },
  { value: "Exfiltration", label: "Exfiltration" },
];

const SEVERITY_OPTIONS: SelectOption[] = [
  { value: "", label: "All Severities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "info", label: "Info" },
];

const STATUS_OPTIONS: SelectOption[] = [
  { value: "", label: "All Statuses" },
  { value: "new", label: "New" },
  { value: "investigating", label: "Investigating" },
  { value: "acknowledged", label: "Acknowledged" },
  { value: "resolved", label: "Resolved" },
  { value: "false_positive", label: "False Positive" },
];

const STATUS_LABELS: Record<ThreatStatus, string> = {
  new: "NEW",
  investigating: "INVESTIGATING",
  acknowledged: "ACKNOWLEDGED",
  resolved: "RESOLVED",
  false_positive: "FALSE POSITIVE",
};

const THREAT_CLASS_BADGE: Record<ThreatClass, "ddos" | "c2" | "dga" | "tls" | "recon" | "exfil"> = {
  "DDoS": "ddos",
  "C2 Beaconing": "c2",
  "DGA / DNS Tunneling": "dga",
  "TLS/Malware": "tls",
  "Reconnaissance": "recon",
  "Exfiltration": "exfil",
};

const THREAT_CLASS_COLOR: Record<ThreatClass, string> = {
  "DDoS": "var(--color-threat-ddos)",
  "C2 Beaconing": "var(--color-threat-c2)",
  "DGA / DNS Tunneling": "var(--color-threat-dga)",
  "TLS/Malware": "var(--color-threat-tls)",
  "Reconnaissance": "var(--color-threat-recon)",
  "Exfiltration": "var(--color-threat-exfil)",
};

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "var(--color-danger)",
  high: "var(--color-warning)",
  medium: "var(--color-accent-cyan)",
  low: "var(--color-success)",
  info: "var(--color-text-muted)",
};

export function AlertCenter() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState<ThreatAlert[]>(() => liveSimulation.getAlerts());
  const [searchQuery, setSearchQuery] = useState("");
  const [threatClassFilter, setThreatClassFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [sortBy, setSortBy] = useState<string>("timestamp");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const [selectedAlerts, setSelectedAlerts] = useState<Set<string>>(new Set());
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
          const apiAlerts = await getThreats();
          if (apiAlerts.length > 0) {
            setAlerts(apiAlerts);
            setDataMode(getDataMode());
            toast(`Data refreshed (${apiAlerts.length} alerts from backend)`);
            setLoading(false);
            return;
          }
        } catch (e) {
          setError(e instanceof Error ? e.message : "Backend fetch failed");
        }
      }
      setAlerts([...liveSimulation.getAlerts()]);
      setDataMode("simulation");
      toast("Data refreshed (simulation)");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshData();
  }, [refreshData]);

  useEffect(() => {
    return liveSimulation.subscribe(() => {
      if (getDataMode() !== "backend" || !isBackendAvailable()) {
        setAlerts([...liveSimulation.getAlerts()]);
      }
    });
  }, []);

  const filteredAlerts = useMemo(() => {
    return alerts.filter(alert => {
      if (searchQuery) {
        const lower = searchQuery.toLowerCase();
        const matches = 
          alert.sourceIp.toLowerCase().includes(lower) ||
          alert.destinationIp.toLowerCase().includes(lower) ||
          alert.threatClass.toLowerCase().includes(lower) ||
          alert.metadata.flowId.toLowerCase().includes(lower) ||
          alert.id.toLowerCase().includes(lower);
        if (!matches) return false;
      }
      if (threatClassFilter && alert.threatClass !== threatClassFilter) return false;
      if (severityFilter && alert.severity !== severityFilter) return false;
      if (statusFilter && alert.status !== statusFilter) return false;
      return true;
    });
  }, [alerts, searchQuery, threatClassFilter, severityFilter, statusFilter]);

  const sortedAlerts = useMemo(() => {
    return [...filteredAlerts].sort((a, b) => {
      let aVal: unknown;
      let bVal: unknown;
      
      if (sortBy === "timestamp") {
        aVal = a.timestamp.getTime();
        bVal = b.timestamp.getTime();
      } else if (sortBy === "threatClass") {
        aVal = a.threatClass;
        bVal = b.threatClass;
      } else if (sortBy === "severity") {
        aVal = a.severity;
        bVal = b.severity;
      } else if (sortBy === "confidence") {
        aVal = a.confidence;
        bVal = b.confidence;
      } else {
        aVal = (a as any)[sortBy];
        bVal = (b as any)[sortBy];
      }
      
      if (aVal === bVal) return 0;
      const comparison = typeof aVal === "number" ? ((aVal as number) < (bVal as number) ? -1 : 1) : String(aVal).localeCompare(String(bVal));
      return sortOrder === "asc" ? comparison : -comparison;
    });
  }, [filteredAlerts, sortBy, sortOrder]);

  const handleSort = (key: string) => {
    if (sortBy === key) setSortOrder(prev => prev === "asc" ? "desc" : "asc");
    else { setSortBy(key); setSortOrder("asc"); }
  };

  const columns = [
    {
      key: "timestamp",
      header: "Timestamp",
      sortable: true,
      width: "160px",
      render: (value: any) => (
        <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">
          {(value as Date).toLocaleString()}
        </span>
      ),
    },
    {
      key: "threatClass",
      header: "Threat Class",
      sortable: true,
      width: "180px",
      render: (value: any) => {
        const tc = value as ThreatClass;
        return (
          <Badge variant={THREAT_CLASS_BADGE[tc]} size="sm" dot>
            {tc}
          </Badge>
        );
      },
    },
    {
      key: "sourceIp",
      header: "Source IP",
      sortable: true,
      width: "140px",
      render: (value: any) => (
        <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{value}</span>
      ),
    },
    {
      key: "destinationIp",
      header: "Destination",
      sortable: true,
      width: "160px",
      render: (value: any, row: ThreatAlert) => (
        <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">
          {value}:{row.destinationPort}
        </span>
      ),
    },
    {
      key: "severity",
      header: "Severity",
      sortable: true,
      width: "100px",
      render: (value: any) => {
        const sev = value as Severity;
        return <Badge variant={sev} size="sm">{sev.toUpperCase()}</Badge>;
      },
    },
    {
      key: "confidence",
      header: "Confidence",
      sortable: true,
      width: "110px",
      align: "right" as const,
      render: (value: any) => (
        <span className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">
          {(value as number * 100).toFixed(1)}%
        </span>
      ),
    },
    {
      key: "status",
      header: "Status",
      sortable: true,
      width: "140px",
      render: (value: any) => {
        const status = value as ThreatStatus;
        return (
          <Badge variant="info" size="sm">
            {STATUS_LABELS[status]}
          </Badge>
        );
      },
    },
    {
      key: "actions",
      header: "",
      width: "80px",
      render: (_value: any, row: ThreatAlert) => (
        <Button variant="ghost" size="sm" onClick={(e) => { e.stopPropagation(); navigate(`/threats/${row.id}`); }}>
          <Eye className="w-4 h-4" />
        </Button>
      ),
    },
  ];

  const handleSelectOne = (id: string, checked: boolean) => {
    setSelectedAlerts(prev => {
      const next = new Set(prev);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  };

  const generateReport = () => {
    const selected = sortedAlerts.filter(a => selectedAlerts.has(a.id));
    if (selected.length === 0) return;
    downloadAlerts(selected, "json", "threx-alert-report");
    toast(`Report generated for ${selected.length} alerts (${dataMode === "backend" ? "backend" : "simulation"})`);
  };

  const forwardToSiem = () => {
    const selected = sortedAlerts.filter(a => selectedAlerts.has(a.id));
    if (selected.length === 0) return;
    toast(`Forwarded ${selected.length} alerts to SIEM (simulated)`);
  };

  const updateStatus = (newStatus: ThreatStatus) => {
    const selectedIds = sortedAlerts.filter(a => selectedAlerts.has(a.id)).map(a => a.id);
    if (selectedIds.length === 0) return;
    selectedIds.forEach(id => liveSimulation.updateThreatStatus(id, newStatus));
    setAlerts([...liveSimulation.getAlerts()]);
    setSelectedAlerts(new Set());
    toast(`Updated ${selectedIds.length} alerts to ${STATUS_LABELS[newStatus]}`);
  };

  const getSeverityDistribution = (alertList: ThreatAlert[]) => {
    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    alertList.forEach(a => counts[a.severity]++);
    const total = alertList.length;
    return (Object.keys(counts) as Severity[]).map(severity => ({
      severity,
      count: counts[severity],
      percentage: total ? (counts[severity] / total) * 100 : 0,
    })).filter(s => s.count > 0);
  };

  if (loading) return <LoadingSpinner text="Loading alerts..." />;

  return (
    <div className="space-y-6 page-enter">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-medium text-[var(--color-text-primary)] tracking-tight">Alert Center</h1>
            <DataModeIndicator />
          </div>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">
            {filteredAlerts.length} of {alerts.length} alerts · {selectedAlerts.size} selected · Read-only actions only
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" onClick={refreshData}>
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
        <CardContent className="p-4 pb-0">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 mb-4">
            <Input
              placeholder="Search alerts, IPs, classes…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="lg:col-span-2"
            />
            <Select
              value={threatClassFilter}
              onChange={setThreatClassFilter}
              options={THREAT_CLASS_OPTIONS}
              placeholder="Threat Class"
            />
            <Select
              value={severityFilter}
              onChange={setSeverityFilter}
              options={SEVERITY_OPTIONS}
              placeholder="Severity"
            />
            <Select
              value={statusFilter}
              onChange={setStatusFilter}
              options={STATUS_OPTIONS}
              placeholder="Status"
            />
          </div>

          {sortedAlerts.length === 0 ? <EmptyState title="No alerts" description="No alerts match current filters." /> : (
            <DataTable
              data={sortedAlerts}
              columns={columns}
              keyExtractor={(row) => row.id}
              sortBy={sortBy}
              sortOrder={sortOrder}
              onSort={handleSort}
              onRowClick={(row) => navigate(`/threats/${row.id}`)}
              rowClassName={(row) => row.severity === "critical" ? "bg-[var(--color-danger)]/5" : ""}
            />
          )}
        </CardContent>
      </Card>

      {selectedAlerts.size > 0 && (
        <Card className="card-inner-highlight border-[var(--color-accent-cyan-border)]">
          <CardContent className="p-4">
            <div className="flex items-center justify-between flex-wrap gap-4">
              <div className="flex items-center gap-4">
                <span className="text-sm text-[var(--color-text-secondary)]">
                  {selectedAlerts.size} alert{selectedAlerts.size > 1 ? "s" : ""} selected
                </span>
                <Button variant="secondary" size="sm" onClick={generateReport}>
                  <Download className="w-4 h-4 mr-1" />
                  Generate Report
                </Button>
                <Button variant="secondary" size="sm" onClick={forwardToSiem}>
                  <ExternalLink className="w-4 h-4 mr-1" />
                  Forward to SIEM
                </Button>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-[var(--color-text-muted)]">Set Status:</span>
                <Button variant="ghost" size="sm" onClick={() => updateStatus("investigating")}>Investigating</Button>
                <Button variant="ghost" size="sm" onClick={() => updateStatus("acknowledged")}>Acknowledged</Button>
                <Button variant="ghost" size="sm" onClick={() => updateStatus("resolved")}>Resolved</Button>
                <Button variant="ghost" size="sm" onClick={() => updateStatus("false_positive")}>False Positive</Button>
                <Button variant="ghost" size="sm" onClick={() => setSelectedAlerts(new Set())}>
                  <X className="w-4 h-4" />
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2 card-inner-highlight">
          <CardHeader>
            <CardTitle>Alert Timeline — Last 24 Hours</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3 max-h-[400px] overflow-y-auto">
              {sortedAlerts.slice(0, 20).map((alert, i) => (
                <div
                  key={alert.id}
                  className={`flex items-center gap-3 p-3 rounded-[6px] bg-[var(--color-bg-elevated-2)]/50 border border-[var(--color-border-card)]/50 border-l-2 transition-all duration-300 animate-slide-in cursor-pointer ${
                    selectedAlerts.has(alert.id) ? "bg-[var(--color-accent-cyan-dim)] border-[var(--color-accent-cyan)]" : ""
                  }`}
                  style={{
                    animationDelay: `${i * 30}ms`,
                    borderLeftColor: THREAT_CLASS_COLOR[alert.threatClass],
                  }}
                  onClick={() => navigate(`/threats/${alert.id}`)}
                >
                  <input
                    type="checkbox"
                    checked={selectedAlerts.has(alert.id)}
                    onChange={(e) => { e.stopPropagation(); handleSelectOne(alert.id, e.target.checked); }}
                    className="w-4 h-4 accent-[var(--color-accent-cyan)]"
                  />
                  <div className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ backgroundColor: THREAT_CLASS_COLOR[alert.threatClass] }} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge variant={THREAT_CLASS_BADGE[alert.threatClass]} size="sm">{alert.threatClass}</Badge>
                      <Badge variant={alert.severity} size="sm">{alert.severity.toUpperCase()}</Badge>
                      <Badge variant="info" size="sm">{STATUS_LABELS[alert.status]}</Badge>
                      <span className="text-xs text-[var(--color-text-muted)] font-mono tabular-nums">
                        {alert.timestamp.toLocaleTimeString()}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 mt-1 text-xs">
                      <span className="font-mono text-[var(--color-text-primary)]">{alert.sourceIp}</span>
                      <span className="text-[var(--color-text-muted)]">→</span>
                      <span className="font-mono text-[var(--color-text-primary)]">{alert.destinationIp}</span>
                      <span className="text-[var(--color-text-muted)]">:</span>
                      <span className="font-mono text-[var(--color-text-primary)]">{alert.destinationPort}</span>
                      <span className="text-[var(--color-text-muted)] ml-auto">Confidence: {(alert.confidence * 100).toFixed(0)}%</span>
                    </div>
                  </div>
                  <FlowFingerprint data={alert.flowFingerprint} width={100} height={24} color={THREAT_CLASS_COLOR[alert.threatClass]} />
                </div>
              ))}
              {sortedAlerts.length === 0 && <EmptyState title="No timeline data" description="No alerts to display." />}
              <ScanlineOverlay speed={15} opacity={0.025} />
            </div>
          </CardContent>
        </Card>

        <Card className="card-inner-highlight">
          <CardHeader>
            <CardTitle>Severity Distribution</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {getSeverityDistribution(alerts).map((sev) => (
              <div key={sev.severity} className="flex items-center justify-between p-3 rounded-[6px] hover:bg-[var(--color-bg-elevated-2)] transition-colors">
                <div className="flex items-center gap-3">
                  <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: SEVERITY_COLORS[sev.severity] }} />
                  <span className="font-medium text-[var(--color-text-primary)] capitalize">{sev.severity}</span>
                </div>
                <div className="text-right">
                  <p className="font-mono text-lg text-[var(--color-text-primary)] tabular-nums">{sev.count}</p>
                  <p className="text-xs text-[var(--color-text-muted)]">{(sev.percentage).toFixed(1)}%</p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
