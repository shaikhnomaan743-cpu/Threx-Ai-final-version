export type ThreatClass = 
  | "DDoS" 
  | "C2 Beaconing" 
  | "DGA / DNS Tunneling" 
  | "TLS/Malware" 
  | "Reconnaissance" 
  | "Exfiltration";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type ThreatStatus = "new" | "investigating" | "acknowledged" | "resolved" | "false_positive";

export interface ThreatAlert {
  id: string;
  timestamp: Date;
  threatClass: ThreatClass;
  sourceIp: string;
  destinationIp: string;
  destinationPort?: number;
  protocol: string;
  severity: Severity;
  confidence: number;
  status: ThreatStatus;
  flowFingerprint: number[];
  metadata: FlowMetadata;
  evidence: EvidenceFeature[];
}

export interface FlowMetadata {
  flowId: string;
  startTime: Date;
  endTime?: Date;
  duration: number;
  packets: number;
  bytes: number;
  packetsPerSecond: number;
  bitsPerSecond: number;
  tcpFlags?: string;
  sourcePort: number;
  destinationPort: number;
  direction: "inbound" | "outbound" | "internal";
  asnSource?: string;
  asnDestination?: string;
  geoSource?: GeoLocation;
  geoDestination?: GeoLocation;
  dnsInfo?: DnsInfo;
  tlsInfo?: TlsInfo;
}

export interface GeoLocation {
  country: string;
  countryCode: string;
  region: string;
  city: string;
  lat: number;
  lon: number;
  isp: string;
}

export interface DnsInfo {
  queryType: string;
  domain: string;
  responseCode: string;
  answers?: string[];
  entropy?: number;
  ngramScore?: number;
}

export interface TlsInfo {
  version: string;
  cipherSuite: string;
  ja3?: string;
  ja3s?: string;
  ja4?: string;
  ja4s?: string;
  sni?: string;
  certInfo?: CertInfo;
}

export interface CertInfo {
  subject: string;
  issuer: string;
  validFrom: Date;
  validTo: Date;
  serialNumber: string;
  fingerprint: string;
  isSelfSigned: boolean;
}

export interface EvidenceFeature {
  name: string;
  value: number;
  maxValue: number;
  description: string;
  weight: number;
}

export interface TrafficMetrics {
  packetsPerSecond: number;
  flowsPerSecond: number;
  bitsPerSecond: number;
  activeFlows: number;
  uniqueSourceIps: number;
  uniqueDestIps: number;
  topProtocols: ProtocolStat[];
  topTalkers: TalkerStat[];
  topPorts: PortStat[];
}

export interface ProtocolStat {
  protocol: string;
  count: number;
  percentage: number;
  bitsPerSecond: number;
  color?: string;
}

export interface TalkerStat {
  ip: string;
  packets: number;
  bytes: number;
  flows: number;
  direction: "source" | "destination";
}

export interface PortStat {
  port: number;
  protocol: string;
  count: number;
  percentage: number;
}

export interface DgaDetection {
  id: string;
  domain: string;
  entropy: number;
  ngramScore: number;
  length: number;
  confidence: number;
  timestamp: Date;
  sourceIp: string;
  queryCount: number;
}

export interface DnsTunnelingIndicator {
  id: string;
  domain: string;
  queryFrequency: number;
  txtQueryVolume: number;
  subdomainEntropy: number;
  confidence: number;
  timestamp: Date;
  sourceIp: string;
}

export interface TlsFingerprint {
  id: string;
  ja3: string;
  ja3s: string;
  ja4: string;
  count: number;
  firstSeen: Date;
  lastSeen: Date;
  sourceIps: string[];
  destinations: string[];
  cipherSuite: string;
  tlsVersion: string;
}

export interface PortScanDetection {
  id: string;
  sourceIp: string;
  targetCount: number;
  portCount: number;
  scanType: "syn" | "ack" | "fin" | "null" | "xmas" | "udp" | "connect";
  duration: number;
  packetsPerSecond: number;
  confidence: number;
  timestamp: Date;
  targets: ScanTarget[];
}

export interface ScanTarget {
  ip: string;
  ports: number[];
  responses: number;
}

export interface ExfiltrationAnomaly {
  id: string;
  sourceIp: string;
  destinationIp: string;
  direction: "outbound" | "inbound";
  byteRatio: number;
  baselineRatio: number;
  deviation: number;
  totalBytes: number;
  duration: number;
  confidence: number;
  timestamp: Date;
  protocol: string;
}

export interface ModelStatus {
  name: string;
  version: string;
  status: "active" | "training" | "degraded" | "offline";
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  inferenceLatency: number;
  throughput: number;
  lastUpdated: Date;
}

export interface PipelineStage {
  name: string;
  status: "active" | "idle" | "error";
  throughput: number;
  latency: number;
  queueDepth: number;
}

export interface SystemStatus {
  ingestHealth: "healthy" | "degraded" | "critical";
  throughput: number;
  uptime: number;
  activeAlerts: number;
  processedFlows: number;
  droppedPackets: number;
  cpuUsage: number;
  memoryUsage: number;
  diskUsage: number;
  diodeStatus: "connected" | "disconnected" | "error";
  lastFlowTimestamp: Date;
}

export interface TimeRange {
  start: Date;
  end: Date;
  preset: "1h" | "6h" | "24h" | "7d" | "30d" | "custom";
}

export interface ReportConfig {
  id: string;
  name: string;
  type: "forensic" | "executive" | "technical" | "compliance";
  format: "json" | "csv" | "pdf";
  timeRange: TimeRange;
  filters: ReportFilters;
  createdAt: Date;
  generatedAt?: Date;
  status: "pending" | "generating" | "completed" | "failed";
  downloadUrl?: string;
}

export interface ReportFilters {
  threatClasses?: ThreatClass[];
  severities?: Severity[];
  sourceIps?: string[];
  destinationIps?: string[];
  minConfidence?: number;
  statuses?: ThreatStatus[];
}