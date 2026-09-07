import { useParams, useNavigate } from "react-router-dom";
import { useMemo, useState, useCallback, useEffect } from "react";
import {
  ArrowLeft,
  ExternalLink,
  Copy,
  AlertTriangle,
  Download,
  FileText,
  CheckCircle,
  MessageSquare,
  Loader2,
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { FlowVisualization } from "../components/charts/FlowVisualization";
import { EvidenceBars } from "../components/charts/EvidenceBars";
import { ScanlineOverlay } from "../components/ui/ScanlineOverlay";
import { AddNoteDialog } from "../components/AddNoteDialog";
import { liveSimulation } from "../services/liveSimulation";
import { downloadAlerts, toast } from "../lib/export";
import { formatNumber, formatBytes, formatDuration } from "../lib/utils";
import { ThreatAlert, ThreatStatus } from "../types";
import { getThreatById, getDataMode } from "../services/apiClient";

const STATUS_LABELS: Record<ThreatStatus, string> = {
  new: "NEW",
  investigating: "INVESTIGATING",
  acknowledged: "ACKNOWLEDGED",
  resolved: "RESOLVED",
  false_positive: "FALSE POSITIVE",
};

export function ThreatInvestigation() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [noteDialogOpen, setNoteDialogOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [backendAlert, setBackendAlert] = useState<ThreatAlert | undefined>(undefined);
  const [, forceUpdate] = useState(0);

  useEffect(() => {
    if (!id || getDataMode() !== "backend") return;
    setLoading(true);
    getThreatById(id).then((a) => {
      if (a) setBackendAlert(a);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [id]);

  const alert = useMemo(() => {
    if (backendAlert) return backendAlert;
    if (!id) return undefined;
    return liveSimulation.getAlerts().find(a => a.id === id);
  }, [id, backendAlert]);

  const analystNotes = useMemo(() => {
    if (!id) return [];
    return liveSimulation.getNotes(id);
  }, [id]);

  const handleMarkReviewed = useCallback(() => {
    if (!id) return;
    liveSimulation.updateThreatStatus(id, "acknowledged");
    toast("Threat marked as reviewed");
    forceUpdate(n => n + 1);
  }, [id]);

  const handleExportJson = useCallback(() => {
    if (!alert) return;
    downloadAlerts([alert], "json", `threx-${alert.id}`);
    toast("JSON exported");
  }, [alert]);

  const handleExportCsv = useCallback(() => {
    if (!alert) return;
    downloadAlerts([alert], "csv", `threx-${alert.id}`);
    toast("CSV exported");
  }, [alert]);

  const handleExportPdf = useCallback(() => {
    if (!alert) return;
    downloadAlerts([alert], "pdf", `threx-${alert.id}`);
    toast("PDF report generated");
  }, [alert]);

  const handleForwardToSiem = useCallback(() => {
    if (!alert) return;
    toast(`Forwarded ${alert.id} to SIEM (simulated)`);
  }, [alert]);

  const handleSaveNote = useCallback((note: string) => {
    if (!id) return;
    liveSimulation.addNote(id, note);
    toast("Analyst note added");
    forceUpdate(n => n + 1);
  }, [id]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="w-8 h-8 text-[var(--color-accent-cyan)] animate-spin" />
          <p className="text-sm text-[var(--color-text-muted)]">Loading threat details...</p>
        </div>
      </div>
    );
  }

  if (!alert) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="text-center">
          <AlertTriangle className="w-12 h-12 text-[var(--color-text-muted)] mx-auto mb-4" />
          <h2 className="text-lg font-medium text-[var(--color-text-primary)]">Threat Not Found</h2>
          <p className="text-[var(--color-text-secondary)] mt-1">The requested threat investigation could not be found.</p>
          <Button onClick={() => navigate("/threats")} className="mt-4" variant="primary">
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Threats
          </Button>
        </div>
      </div>
    );
  }

  const metadata = alert.metadata;

  return (
    <div className="space-y-6 page-enter">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="sm" onClick={() => navigate("/threats")}>
          <ArrowLeft className="w-4 h-4 mr-1" />
          Back
        </Button>
        <div>
          <div className="flex items-center gap-2">
            <Badge variant={alert.threatClass === "DDoS" ? "ddos" : alert.threatClass === "C2 Beaconing" ? "c2" : alert.threatClass === "DGA / DNS Tunneling" ? "dga" : alert.threatClass === "TLS/Malware" ? "tls" : alert.threatClass === "Reconnaissance" ? "recon" : "exfil"} size="md" dot>
              {alert.threatClass}
            </Badge>
            <Badge variant={alert.severity} size="md">{alert.severity.toUpperCase()}</Badge>
            <Badge variant="info" size="md">{(alert.confidence * 100).toFixed(1)}% CONFIDENCE</Badge>
            <span className="text-xs text-[var(--color-text-muted)] font-mono tabular-nums">
              {alert.timestamp.toLocaleString()}
            </span>
          </div>
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">
            Flow ID: <span className="font-mono text-[var(--color-text-primary)]">{metadata.flowId}</span>
          </p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={handleMarkReviewed}>
            <CheckCircle className="w-4 h-4 mr-1" />
            Mark Reviewed
          </Button>
          <Button variant="ghost" size="sm" onClick={() => setNoteDialogOpen(true)}>
            <MessageSquare className="w-4 h-4 mr-1" />
            Add Note
          </Button>
          <Button variant="ghost" size="sm" onClick={handleForwardToSiem}>
            <ExternalLink className="w-4 h-4 mr-1" />
            Forward to SIEM
          </Button>
          <Button variant="secondary" size="sm" onClick={handleExportJson}>
            <Download className="w-4 h-4 mr-1" />
            Export JSON
          </Button>
          <Button variant="secondary" size="sm" onClick={handleExportCsv}>
            <Download className="w-4 h-4 mr-1" />
            Export CSV
          </Button>
          <Button variant="primary" size="sm" onClick={handleExportPdf}>
            <FileText className="w-4 h-4 mr-1" />
            Generate Report
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2 card-inner-highlight">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Flow Visualization</CardTitle>
              <div className="flex items-center gap-2">
                <span className="text-[10px] text-[var(--color-text-muted)] uppercase tracking-wider">ONE-WAY FLOW</span>
                <span className="text-[10px] text-[var(--color-text-muted)] uppercase tracking-wider">RETURN PATH: NONE</span>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <FlowVisualization
              sourceIp={alert.sourceIp}
              destinationIp={alert.destinationIp}
              sourcePort={metadata.sourcePort}
              destinationPort={metadata.destinationPort}
              protocol={alert.protocol}
              packets={metadata.packets}
              bytes={metadata.bytes}
              direction={metadata.direction}
            />
            <ScanlineOverlay speed={12} opacity={0.02} />
          </CardContent>
        </Card>

        <Card className="card-inner-highlight space-y-4">
          <CardHeader>
            <CardTitle>Evidence</CardTitle>
          </CardHeader>
          <CardContent>
            <EvidenceBars features={alert.evidence} />
          </CardContent>

          <CardHeader className="border-t border-[var(--color-border-card)]/50 pt-4">
            <CardTitle>Raw Flow Metadata</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <div className="grid grid-cols-2 gap-2">
              <div>
                <span className="text-[var(--color-text-muted)]">Flow ID</span>
                <p className="font-mono text-[var(--color-text-primary)] truncate">{metadata.flowId}</p>
              </div>
              <div>
                <span className="text-[var(--color-text-muted)]">Duration</span>
                <p className="font-mono text-[var(--color-text-primary)] tabular-nums">{formatDuration(metadata.duration)}</p>
              </div>
              <div>
                <span className="text-[var(--color-text-muted)]">Packets</span>
                <p className="font-mono text-[var(--color-text-primary)] tabular-nums">{formatNumber(metadata.packets)}</p>
              </div>
              <div>
                <span className="text-[var(--color-text-muted)]">Bytes</span>
                <p className="font-mono text-[var(--color-text-primary)] tabular-nums">{formatBytes(metadata.bytes)}</p>
              </div>
              <div>
                <span className="text-[var(--color-text-muted)]">Packets/sec</span>
                <p className="font-mono text-[var(--color-text-primary)] tabular-nums">{formatNumber(metadata.packetsPerSecond)}</p>
              </div>
              <div>
                <span className="text-[var(--color-text-muted)]">Bits/sec</span>
                <p className="font-mono text-[var(--color-text-primary)] tabular-nums">{formatNumber(metadata.bitsPerSecond)} bps</p>
              </div>
              <div>
                <span className="text-[var(--color-text-muted)]">TCP Flags</span>
                <p className="font-mono text-[var(--color-text-primary)]">{metadata.tcpFlags || "—"}</p>
              </div>
              <div>
                <span className="text-[var(--color-text-muted)]">Direction</span>
                <p className="font-mono text-[var(--color-text-primary)] capitalize">{metadata.direction}</p>
              </div>
              <div>
                <span className="text-[var(--color-text-muted)]">Source Port</span>
                <p className="font-mono text-[var(--color-text-primary)] tabular-nums">{metadata.sourcePort}</p>
              </div>
              <div>
                <span className="text-[var(--color-text-muted)]">Dest Port</span>
                <p className="font-mono text-[var(--color-text-primary)] tabular-nums">{metadata.destinationPort}</p>
              </div>
            </div>

            {metadata.asnSource && (
              <div className="pt-2 border-t border-[var(--color-border-card)]/50">
                <p className="text-xs text-[var(--color-text-muted)] uppercase tracking-wider mb-2">Network Context</p>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div>
                    <span className="text-[var(--color-text-muted)]">Source ASN</span>
                    <p className="font-mono text-[var(--color-text-primary)]">{metadata.asnSource}</p>
                  </div>
                  <div>
                    <span className="text-[var(--color-text-muted)]">Dest ASN</span>
                    <p className="font-mono text-[var(--color-text-primary)]">{metadata.asnDestination || "—"}</p>
                  </div>
                </div>
              </div>
            )}

            {metadata.geoSource && (
              <div className="pt-2 border-t border-[var(--color-border-card)]/50">
                <p className="text-xs text-[var(--color-text-muted)] uppercase tracking-wider mb-2">Geolocation</p>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div>
                    <span className="text-[var(--color-text-muted)]">Source</span>
                    <p className="font-mono text-[var(--color-text-primary)]">{metadata.geoSource.city}, {metadata.geoSource.country}</p>
                  </div>
                  <div>
                    <span className="text-[var(--color-text-muted)]">Destination</span>
                    <p className="font-mono text-[var(--color-text-primary)]">{metadata.geoDestination?.city}, {metadata.geoDestination?.country}</p>
                  </div>
                </div>
              </div>
            )}

            {metadata.dnsInfo && (
              <div className="pt-2 border-t border-[var(--color-border-card)]/50">
                <p className="text-xs text-[var(--color-text-muted)] uppercase tracking-wider mb-2">DNS Information</p>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-[var(--color-text-muted)]">Domain</span>
                    <span className="font-mono text-[var(--color-text-primary)] truncate max-w-[200px]">{metadata.dnsInfo.domain}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[var(--color-text-muted)]">Query Type</span>
                    <span className="font-mono text-[var(--color-text-primary)]">{metadata.dnsInfo.queryType}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[var(--color-text-muted)]">Response</span>
                    <span className="font-mono text-[var(--color-text-primary)]">{metadata.dnsInfo.responseCode}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[var(--color-text-muted)]">Entropy</span>
                    <span className="font-mono text-[var(--color-text-primary)] tabular-nums">{metadata.dnsInfo.entropy?.toFixed(2)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[var(--color-text-muted)]">N-gram Score</span>
                    <span className="font-mono text-[var(--color-text-primary)] tabular-nums">{metadata.dnsInfo.ngramScore?.toFixed(2)}</span>
                  </div>
                </div>
              </div>
            )}

            {metadata.tlsInfo && (
              <div className="pt-2 border-t border-[var(--color-border-card)]/50">
                <p className="text-xs text-[var(--color-text-muted)] uppercase tracking-wider mb-2">TLS Information</p>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-[var(--color-text-muted)]">Version</span>
                    <span className="font-mono text-[var(--color-text-primary)]">{metadata.tlsInfo.version}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[var(--color-text-muted)]">Cipher Suite</span>
                    <span className="font-mono text-[var(--color-text-primary)] truncate max-w-[200px]">{metadata.tlsInfo.cipherSuite}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[var(--color-text-muted)]">JA3</span>
                    <span className="font-mono text-[var(--color-text-primary)] truncate max-w-[200px]">{metadata.tlsInfo.ja3}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[var(--color-text-muted)]">JA3S</span>
                    <span className="font-mono text-[var(--color-text-primary)] truncate max-w-[200px]">{metadata.tlsInfo.ja3s}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[var(--color-text-muted)]">JA4</span>
                    <span className="font-mono text-[var(--color-text-primary)] truncate max-w-[200px]">{metadata.tlsInfo.ja4}</span>
                  </div>
                  {metadata.tlsInfo.sni && (
                    <div className="flex justify-between">
                      <span className="text-[var(--color-text-muted)]">SNI</span>
                      <span className="font-mono text-[var(--color-text-primary)] truncate max-w-[200px]">{metadata.tlsInfo.sni}</span>
                    </div>
                  )}
                  {metadata.tlsInfo.certInfo && (
                    <div className="pt-2 border-t border-[var(--color-border-card)]/50">
                      <p className="text-xs text-[var(--color-text-muted)] uppercase tracking-wider mb-2">Certificate</p>
                      <div className="space-y-1 text-xs">
                        <div className="flex justify-between">
                          <span className="text-[var(--color-text-muted)]">Subject</span>
                          <span className="font-mono text-[var(--color-text-primary)] truncate max-w-[200px]">{metadata.tlsInfo.certInfo.subject}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[var(--color-text-muted)]">Issuer</span>
                          <span className="font-mono text-[var(--color-text-primary)]">{metadata.tlsInfo.certInfo.issuer}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[var(--color-text-muted)]">Valid</span>
                          <span className="font-mono text-[var(--color-text-primary)]">
                            {metadata.tlsInfo.certInfo.validFrom.toLocaleDateString()} → {metadata.tlsInfo.certInfo.validTo.toLocaleDateString()}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[var(--color-text-muted)]">Self-Signed</span>
                          <Badge variant={metadata.tlsInfo.certInfo.isSelfSigned ? "danger" : "success"} size="sm">
                            {metadata.tlsInfo.certInfo.isSelfSigned ? "YES" : "NO"}
                          </Badge>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {analystNotes.length > 0 && (
        <Card className="card-inner-highlight">
          <CardHeader>
            <CardTitle>Analyst Notes</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {analystNotes.map((note, i) => (
              <div key={i} className="p-3 rounded-[6px] bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)]">
                <p className="text-sm text-[var(--color-text-primary)]">{note.note}</p>
                <p className="text-xs text-[var(--color-text-muted)] mt-1">
                  {note.analyst} · {(note.timestamp as Date).toLocaleString()}
                </p>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      <AddNoteDialog
        open={noteDialogOpen}
        onClose={() => setNoteDialogOpen(false)}
        onSave={handleSaveNote}
        threatId={alert.id}
      />
    </div>
  );
}
