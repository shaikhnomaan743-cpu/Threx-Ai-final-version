import type {
  ThreatAlert,
  ThreatClass,
  Severity,
  ThreatStatus,
  TrafficMetrics,
  DgaDetection,
  DnsTunnelingIndicator,
  TlsFingerprint,
  PortScanDetection,
  ExfiltrationAnomaly,
  ModelStatus,
  PipelineStage,
  SystemStatus,
} from "../types";

export interface SearchResult {
  type: "threat" | "alert" | "ip" | "domain" | "fingerprint";
  id: string;
  title: string;
  subtitle: string;
  href: string;
  relevance: number;
}

export interface ApiService {
  getThreats(): Promise<ThreatAlert[]>;
  getThreatById(id: string): Promise<ThreatAlert | undefined>;
  getTrafficMetrics(): Promise<TrafficMetrics>;
  getDgaDetections(): Promise<DgaDetection[]>;
  getDnsTunnelingIndicators(): Promise<DnsTunnelingIndicator[]>;
  getTlsFingerprints(): Promise<TlsFingerprint[]>;
  getPortScanDetections(): Promise<PortScanDetection[]>;
  getExfiltrationAnomalies(): Promise<ExfiltrationAnomaly[]>;
  getModelStatuses(): Promise<ModelStatus[]>;
  getPipelineStages(): Promise<PipelineStage[]>;
  getSystemStatus(): Promise<SystemStatus>;
  search(query: string): Promise<SearchResult[]>;
  updateThreatStatus(id: string, status: ThreatStatus): Promise<void>;
  addAnalystNote(id: string, note: string): Promise<void>;
  getAnalystNotes(id: string): Promise<string[]>;
  generateReport(config: unknown): Promise<Blob>;
}

export function createToast(message: string) {
  window.dispatchEvent(new CustomEvent("threx:toast", { detail: message }));
}
