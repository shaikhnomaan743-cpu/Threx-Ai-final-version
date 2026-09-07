import {
  ThreatAlert,
  ThreatClass,
  Severity,
  ThreatStatus,
  FlowMetadata,
  EvidenceFeature,
  TrafficMetrics,
  ProtocolStat,
  TalkerStat,
  PortStat,
  DgaDetection,
  DnsTunnelingIndicator,
  TlsFingerprint,
  PortScanDetection,
  ExfiltrationAnomaly,
  ModelStatus,
  PipelineStage,
  SystemStatus,
  ScanTarget,
  GeoLocation,
  DnsInfo,
  TlsInfo,
  CertInfo,
} from "../types";
import { generateId } from "../lib/utils";

const THREAT_CLASSES: ThreatClass[] = [
  "DDoS",
  "C2 Beaconing",
  "DGA / DNS Tunneling",
  "TLS/Malware",
  "Reconnaissance",
  "Exfiltration",
];

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const STATUSES: ThreatStatus[] = ["new", "investigating", "acknowledged", "resolved", "false_positive"];

const SOURCE_IPS = [
  "192.168.1.45", "10.10.10.5", "172.16.0.12", "192.168.100.23", "10.0.5.67",
  "203.0.113.8", "198.51.100.42", "172.31.16.89", "10.20.30.11", "192.168.50.5",
  "172.18.0.100", "10.100.0.15", "192.168.200.77", "10.5.5.5", "172.20.10.200",
];

const DEST_IPS = [
  "8.8.8.8", "1.1.1.1", "208.67.222.222", "9.9.9.9", "185.228.168.9",
  "151.101.1.140", "104.16.123.96", "172.217.164.110", "13.107.42.14", "52.95.110.1",
  "18.65.128.0", "34.192.0.0", "54.239.16.0", "15.188.0.0", "35.160.0.0",
];

const DGA_DOMAINS = [
  "kqxwzpnmvbtr.com", "aeplxnvhqtwx.net", "mjrzqwxbfyhv.org", "xvzkqpmnjwlr.io",
  "qwjxznmvpyhg.biz", "kzxmvnqwprtj.info", "jvqxzmwnpryt.co", "wqzmxjvpnkry.me",
  "xqwzmjvnpkry.top", "zmqxwjvnpkry.xyz", "qxzmwjvnpkry.online", "wqxzmjvnpkry.site",
  "mzxqwjvnpkry.tech", "zqxwjmvnpkry.app", "xwqzmjvnpkry.dev",
];

const JA3_HASHES = [
  "771,4865-4866-4867-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24-25",
  "771,4865-4866-4867-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24-25-26",
  "771,4865-4866-4867-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24",
  "771,4865-4866-4867-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24-25-26-27",
  "771,4866-4867-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24-25-26",
];

const COUNTRIES: GeoLocation[] = [
  { country: "United States", countryCode: "US", region: "California", city: "San Francisco", lat: 37.7749, lon: -122.4194, isp: "Google LLC" },
  { country: "United States", countryCode: "US", region: "Virginia", city: "Ashburn", lat: 39.0438, lon: -77.4874, isp: "Amazon.com, Inc." },
  { country: "Germany", countryCode: "DE", region: "Hesse", city: "Frankfurt", lat: 50.1109, lon: 8.6821, isp: "Deutsche Telekom AG" },
  { country: "Japan", countryCode: "JP", region: "Tokyo", city: "Tokyo", lat: 35.6762, lon: 139.6503, isp: "NTT Communications" },
  { country: "Singapore", countryCode: "SG", region: "Singapore", city: "Singapore", lat: 1.3521, lon: 103.8198, isp: "SingTel" },
  { country: "United Kingdom", countryCode: "GB", region: "England", city: "London", lat: 51.5074, lon: -0.1278, isp: "BT Group" },
  { country: "Brazil", countryCode: "BR", region: "São Paulo", city: "São Paulo", lat: -23.5505, lon: -46.6333, isp: "Telefonica Brasil" },
  { country: "Australia", countryCode: "AU", region: "New South Wales", city: "Sydney", lat: -33.8688, lon: 151.2093, isp: "Telstra" },
];

function mulberry32(seed: number) {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rng = mulberry32(20260902);

function randomElement<T>(arr: T[]): T {
  return arr[Math.floor(rng() * arr.length)];
}

function randomInt(min: number, max: number): number {
  return Math.floor(rng() * (max - min + 1)) + min;
}

function randomFloat(min: number, max: number, decimals = 2): number {
  const factor = Math.pow(10, decimals);
  return Math.floor((rng() * (max - min) + min) * factor) / factor;
}

function randomDate(daysBack = 7): Date {
  const now = new Date();
  const past = new Date(now.getTime() - daysBack * 24 * 60 * 60 * 1000);
  return new Date(past.getTime() + rng() * (now.getTime() - past.getTime()));
}

function generateFlowFingerprint(): number[] {
  const length = randomInt(20, 60);
  return Array.from({ length }, () => randomFloat(0.1, 2.0, 3));
}

function generateEvidenceFeatures(threatClass: ThreatClass): EvidenceFeature[] {
  const baseFeatures: Record<ThreatClass, EvidenceFeature[]> = {
    "DDoS": [
      { name: "Packet Rate Anomaly", value: 0.96, maxValue: 1, description: "Packets/sec exceeds 99.9th percentile", weight: 0.35 },
      { name: "Flow Symmetry", value: 0.89, maxValue: 1, description: "Near-perfect request/response symmetry", weight: 0.25 },
      { name: "Source Diversity", value: 0.92, maxValue: 1, description: "Single source, many destinations", weight: 0.20 },
      { name: "Payload Uniformity", value: 0.94, maxValue: 1, description: "Identical packet sizes observed", weight: 0.20 },
    ],
    "C2 Beaconing": [
      { name: "Periodicity", value: 0.96, maxValue: 1, description: "Regular intervals detected (σ < 2%)", weight: 0.40 },
      { name: "Destination Rarity", value: 0.91, maxValue: 1, description: "Unknown destination, no reputation", weight: 0.25 },
      { name: "Payload Entropy", value: 0.87, maxValue: 1, description: "High entropy in small packets", weight: 0.20 },
      { name: "Connection Duration", value: 0.83, maxValue: 1, description: "Consistent short-lived connections", weight: 0.15 },
    ],
    "DGA / DNS Tunneling": [
      { name: "Domain Entropy", value: 0.94, maxValue: 1, description: "Shannon entropy > 3.5", weight: 0.35 },
      { name: "N-gram Anomaly", value: 0.89, maxValue: 1, description: "Low n-gram probability vs Alexa top 1M", weight: 0.30 },
      { name: "Subdomain Length", value: 0.92, maxValue: 1, description: "Avg subdomain length > 20 chars", weight: 0.20 },
      { name: "Query Frequency", value: 0.85, maxValue: 1, description: "Burst pattern, >50 q/min", weight: 0.15 },
    ],
    "TLS/Malware": [
      { name: "JA3 Fingerprint", value: 0.93, maxValue: 1, description: "Matches known malware JA3", weight: 0.35 },
      { name: "Cipher Anomaly", value: 0.88, maxValue: 1, description: "Unusual cipher suite ordering", weight: 0.25 },
      { name: "Cert Anomaly", value: 0.91, maxValue: 1, description: "Self-signed, short validity", weight: 0.25 },
      { name: "SNI Entropy", value: 0.86, maxValue: 1, description: "Random-looking SNI values", weight: 0.15 },
    ],
    "Reconnaissance": [
      { name: "Port Spread", value: 0.95, maxValue: 1, description: "Scanning >100 ports in <60s", weight: 0.35 },
      { name: "Target Diversity", value: 0.90, maxValue: 1, description: "Single source, many targets", weight: 0.30 },
      { name: "SYN Ratio", value: 0.93, maxValue: 1, description: "High SYN/ACK ratio indicates scanning", weight: 0.20 },
      { name: "Timing Regularity", value: 0.87, maxValue: 1, description: "Automated scan timing pattern", weight: 0.15 },
    ],
    "Exfiltration": [
      { name: "Byte Ratio Anomaly", value: 0.94, maxValue: 1, description: "Outbound/Inbound ratio >10:1", weight: 0.35 },
      { name: "Baseline Deviation", value: 0.91, maxValue: 1, description: "5σ above historical baseline", weight: 0.30 },
      { name: "Destination Uniqueness", value: 0.88, maxValue: 1, description: "New external destination", weight: 0.20 },
      { name: "Transfer Duration", value: 0.85, maxValue: 1, description: "Sustained high-volume transfer", weight: 0.15 },
    ],
  };
  return baseFeatures[threatClass].map(f => ({ ...f, value: randomFloat(f.value - 0.05, f.value) }));
}

export function generateMockAlerts(count = 50): ThreatAlert[] {
  const alerts: ThreatAlert[] = [];
  const classDistribution = {
    "DDoS": 8,
    "C2 Beaconing": 10,
    "DGA / DNS Tunneling": 8,
    "TLS/Malware": 8,
    "Reconnaissance": 8,
    "Exfiltration": 8,
  };

  let generated = 0;
  for (const [threatClass, classCount] of Object.entries(classDistribution)) {
    for (let i = 0; i < classCount && generated < count; i++) {
      const severity = randomElement(SEVERITIES.slice(0, 4));
      const confidence = randomFloat(0.75, 0.98);
      const timestamp = randomDate(7);
      const sourceIp = randomElement(SOURCE_IPS);
      const destinationIp = randomElement(DEST_IPS);
      const sourcePort = randomInt(1024, 65535);
      const destinationPort = randomElement([53, 80, 443, 8080, 8443, 22, 3389, 445, 135, 139]);
      
      const metadata: FlowMetadata = {
        flowId: `flow_${generateId()}`,
        startTime: timestamp,
        endTime: new Date(timestamp.getTime() + randomInt(1000, 300000)),
        duration: randomInt(1000, 300000),
        packets: randomInt(10, 10000),
        bytes: randomInt(1000, 10000000),
        packetsPerSecond: randomFloat(10, 5000),
        bitsPerSecond: randomFloat(10000, 100000000),
        tcpFlags: randomElement(["SYN", "SYN,ACK", "PSH,ACK", "FIN,ACK", "RST"]),
        sourcePort,
        destinationPort,
        direction: randomElement(["inbound", "outbound", "internal"]),
        asnSource: `AS${randomInt(10000, 99999)}`,
        asnDestination: `AS${randomInt(10000, 99999)}`,
        geoSource: randomElement(COUNTRIES),
        geoDestination: randomElement(COUNTRIES),
        dnsInfo: threatClass === "DGA / DNS Tunneling" ? {
          queryType: randomElement(["A", "AAAA", "TXT", "MX", "CNAME"]),
          domain: randomElement(DGA_DOMAINS),
          responseCode: randomElement(["NOERROR", "NXDOMAIN", "SERVFAIL"]),
          entropy: randomFloat(3.0, 4.5),
          ngramScore: randomFloat(0.1, 0.8),
        } : undefined,
        tlsInfo: threatClass === "TLS/Malware" ? {
          version: randomElement(["TLS 1.2", "TLS 1.3"]),
          cipherSuite: randomElement([
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
          ]),
          ja3: randomElement(JA3_HASHES),
          ja3s: randomElement(JA3_HASHES),
          ja4: `t13d_${randomElement(JA3_HASHES).substring(0, 32)}`,
          sni: randomElement(DGA_DOMAINS),
          certInfo: {
            subject: `CN=${randomElement(DGA_DOMAINS)}`,
            issuer: "Self-Signed",
            validFrom: new Date(Date.now() - randomInt(0, 30) * 24 * 60 * 60 * 1000),
            validTo: new Date(Date.now() + randomInt(1, 365) * 24 * 60 * 60 * 1000),
            serialNumber: generateId(),
            fingerprint: `SHA256:${generateId()}`,
            isSelfSigned: true,
          },
        } : undefined,
      };

      alerts.push({
        id: `alert_${generateId()}`,
        timestamp,
        threatClass: threatClass as ThreatClass,
        sourceIp,
        destinationIp,
        destinationPort,
        protocol: destinationPort === 53 ? "UDP" : "TCP",
        severity,
        confidence,
        status: randomElement(STATUSES),
        flowFingerprint: generateFlowFingerprint(),
        metadata,
        evidence: generateEvidenceFeatures(threatClass as ThreatClass),
      });
      generated++;
    }
  }

  return alerts.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
}

let cachedAlerts: ThreatAlert[] | null = null;

export function getCachedAlerts(count = 50): ThreatAlert[] {
  if (!cachedAlerts) cachedAlerts = generateMockAlerts(count);
  return cachedAlerts;
}

export function getAlertById(id: string): ThreatAlert | undefined {
  return getCachedAlerts().find((a) => a.id === id);
}

export function generateTrafficMetrics(): TrafficMetrics {
  return {
    packetsPerSecond: randomFloat(1.5e6, 3.5e6),
    flowsPerSecond: randomFloat(45000, 85000),
    bitsPerSecond: randomFloat(4e9, 8e9),
    activeFlows: randomInt(800, 1200),
    uniqueSourceIps: randomInt(2000, 5000),
    uniqueDestIps: randomInt(1500, 4000),
    topProtocols: [
      { protocol: "TCP", count: randomInt(1200000, 2000000), percentage: 65, bitsPerSecond: randomFloat(3e9, 5e9), color: "var(--color-accent-cyan)" },
      { protocol: "UDP", count: randomInt(400000, 800000), percentage: 25, bitsPerSecond: randomFloat(1e9, 2e9), color: "var(--color-threat-c2)" },
      { protocol: "ICMP", count: randomInt(50000, 150000), percentage: 5, bitsPerSecond: randomFloat(1e8, 5e8), color: "var(--color-threat-dga)" },
      { protocol: "Other", count: randomInt(20000, 80000), percentage: 5, bitsPerSecond: randomFloat(5e7, 2e8), color: "var(--color-text-muted)" },
    ],
    topTalkers: [
      { ip: "192.168.1.45", packets: randomInt(500000, 800000), bytes: randomInt(5e9, 1e10), flows: randomInt(500, 1200), direction: "source" },
      { ip: "10.10.10.5", packets: randomInt(300000, 600000), bytes: randomInt(3e9, 8e9), flows: randomInt(300, 900), direction: "source" },
      { ip: "203.0.113.8", packets: randomInt(200000, 500000), bytes: randomInt(2e9, 6e9), flows: randomInt(200, 700), direction: "destination" },
      { ip: "172.16.0.12", packets: randomInt(150000, 400000), bytes: randomInt(1e9, 4e9), flows: randomInt(150, 500), direction: "source" },
      { ip: "192.168.100.23", packets: randomInt(100000, 300000), bytes: randomInt(8e8, 3e9), flows: randomInt(100, 400), direction: "destination" },
    ],
    topPorts: [
      { port: 443, protocol: "TCP", count: randomInt(800000, 1500000), percentage: 42 },
      { port: 80, protocol: "TCP", count: randomInt(300000, 600000), percentage: 18 },
      { port: 53, protocol: "UDP", count: randomInt(200000, 500000), percentage: 15 },
      { port: 8080, protocol: "TCP", count: randomInt(100000, 300000), percentage: 8 },
      { port: 22, protocol: "TCP", count: randomInt(50000, 150000), percentage: 5 },
      { port: 445, protocol: "TCP", count: randomInt(30000, 100000), percentage: 3 },
      { port: 3389, protocol: "TCP", count: randomInt(20000, 80000), percentage: 2 },
      { port: 500, protocol: "UDP", count: randomInt(15000, 50000), percentage: 2 },
    ],
  };
}

export function generateDgaDetections(count = 25): DgaDetection[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `dga_${generateId()}`,
    domain: randomElement(DGA_DOMAINS),
    entropy: randomFloat(3.0, 4.5),
    ngramScore: randomFloat(0.05, 0.6),
    length: randomInt(12, 28),
    confidence: randomFloat(0.75, 0.99),
    timestamp: randomDate(7),
    sourceIp: randomElement(SOURCE_IPS),
    queryCount: randomInt(10, 500),
  }));
}

export function generateDnsTunnelingIndicators(count = 15): DnsTunnelingIndicator[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `tunnel_${generateId()}`,
    domain: randomElement(DGA_DOMAINS),
    queryFrequency: randomFloat(50, 500),
    txtQueryVolume: randomInt(100, 5000),
    subdomainEntropy: randomFloat(3.5, 4.8),
    confidence: randomFloat(0.70, 0.95),
    timestamp: randomDate(7),
    sourceIp: randomElement(SOURCE_IPS),
  }));
}

export function generateTlsFingerprints(count = 20): TlsFingerprint[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `tls_${generateId()}`,
    ja3: randomElement(JA3_HASHES),
    ja3s: randomElement(JA3_HASHES),
    ja4: `t13d_${randomElement(JA3_HASHES).substring(0, 32)}`,
    count: randomInt(100, 10000),
    firstSeen: randomDate(30),
    lastSeen: randomDate(1),
    sourceIps: Array.from({ length: randomInt(1, 5) }, () => randomElement(SOURCE_IPS)),
    destinations: Array.from({ length: randomInt(1, 3) }, () => randomElement(DEST_IPS)),
    cipherSuite: randomElement([
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    ]),
    tlsVersion: randomElement(["TLS 1.2", "TLS 1.3"]),
  }));
}

export function generatePortScanDetections(count = 12): PortScanDetection[] {
  const scanTypes = ["syn", "ack", "fin", "null", "xmas", "udp", "connect"] as const satisfies ("syn" | "ack" | "fin" | "null" | "xmas" | "udp" | "connect")[];
  return Array.from({ length: count }, (_, i) => {
    const targetCount = randomInt(50, 500);
    const portCount = randomInt(100, 65535);
    return {
      id: `scan_${generateId()}`,
      sourceIp: randomElement(SOURCE_IPS),
      targetCount,
      portCount,
      scanType: randomElement(scanTypes),
      duration: randomInt(10000, 300000),
      packetsPerSecond: randomFloat(100, 10000),
      confidence: randomFloat(0.80, 0.99),
      timestamp: randomDate(7),
      targets: Array.from({ length: Math.min(targetCount, 10) }, () => ({
        ip: randomElement(DEST_IPS),
        ports: Array.from({ length: randomInt(10, 100) }, () => randomInt(1, 65535)),
        responses: randomInt(0, 50),
      })),
    };
  });
}

export function generateExfiltrationAnomalies(count = 10): ExfiltrationAnomaly[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `exfil_${generateId()}`,
    sourceIp: randomElement(SOURCE_IPS),
    destinationIp: randomElement(DEST_IPS),
    direction: randomElement(["outbound", "inbound"] as const),
    byteRatio: randomFloat(10, 500),
    baselineRatio: randomFloat(0.5, 3),
    deviation: randomFloat(3, 10),
    totalBytes: randomInt(1e8, 1e11),
    duration: randomInt(300000, 3600000),
    confidence: randomFloat(0.75, 0.97),
    timestamp: randomDate(7),
    protocol: randomElement(["TCP", "UDP", "QUIC"]),
  }));
}

export function generateModelStatuses(): ModelStatus[] {
  return [
    {
      name: "ThreatClassifer-v3.2",
      version: "3.2.1",
      status: "active",
      accuracy: 0.973,
      precision: 0.968,
      recall: 0.971,
      f1Score: 0.969,
      inferenceLatency: 2.3,
      throughput: 125000,
      lastUpdated: new Date(Date.now() - 2 * 60 * 60 * 1000),
    },
    {
      name: "AnomalyDetector-v2.1",
      version: "2.1.4",
      status: "active",
      accuracy: 0.942,
      precision: 0.935,
      recall: 0.948,
      f1Score: 0.941,
      inferenceLatency: 1.8,
      throughput: 180000,
      lastUpdated: new Date(Date.now() - 4 * 60 * 60 * 1000),
    },
    {
      name: "DGA-Classifier-v1.5",
      version: "1.5.0",
      status: "active",
      accuracy: 0.987,
      precision: 0.982,
      recall: 0.985,
      f1Score: 0.983,
      inferenceLatency: 0.9,
      throughput: 250000,
      lastUpdated: new Date(Date.now() - 1 * 60 * 60 * 1000),
    },
    {
      name: "TLS-Fingerprinter-v4.0",
      version: "4.0.2",
      status: "active",
      accuracy: 0.956,
      precision: 0.951,
      recall: 0.959,
      f1Score: 0.955,
      inferenceLatency: 1.2,
      throughput: 200000,
      lastUpdated: new Date(Date.now() - 30 * 60 * 1000),
    },
    {
      name: "Exfil-Detector-v1.8",
      version: "1.8.3",
      status: "training",
      accuracy: 0.934,
      precision: 0.928,
      recall: 0.939,
      f1Score: 0.933,
      inferenceLatency: 3.1,
      throughput: 95000,
      lastUpdated: new Date(Date.now() - 6 * 60 * 60 * 1000),
    },
  ];
}

export function generatePipelineStages(): PipelineStage[] {
  return [
    { name: "Ingest", status: "active", throughput: 2350000, latency: 0.4, queueDepth: 12 },
    { name: "Feature Extraction", status: "active", throughput: 2340000, latency: 1.2, queueDepth: 8 },
    { name: "ML Models", status: "active", throughput: 2335000, latency: 2.8, queueDepth: 15 },
    { name: "Classification", status: "active", throughput: 2330000, latency: 0.6, queueDepth: 3 },
    { name: "Alerts", status: "active", throughput: 847, latency: 0.1, queueDepth: 0 },
  ];
}

export function generateSystemStatus(): SystemStatus {
  return {
    ingestHealth: "healthy",
    throughput: 2350000,
    uptime: 99.997,
    activeAlerts: 847,
    processedFlows: 2847593421,
    droppedPackets: 1247,
    cpuUsage: 34,
    memoryUsage: 58,
    diskUsage: 42,
    diodeStatus: "connected",
    lastFlowTimestamp: new Date(),
  };
}

export function getThreatClassColor(threatClass: ThreatClass): string {
  const colors: Record<ThreatClass, string> = {
    "DDoS": "var(--color-threat-ddos)",
    "C2 Beaconing": "var(--color-threat-c2)",
    "DGA / DNS Tunneling": "var(--color-threat-dga)",
    "TLS/Malware": "var(--color-threat-tls)",
    "Reconnaissance": "var(--color-threat-recon)",
    "Exfiltration": "var(--color-threat-exfil)",
  };
  return colors[threatClass];
}

export function getSeverityColor(severity: Severity): string {
  const colors: Record<Severity, string> = {
    critical: "var(--color-danger)",
    high: "var(--color-warning)",
    medium: "var(--color-accent-cyan)",
    low: "var(--color-success)",
    info: "var(--color-text-muted)",
  };
  return colors[severity];
}

export function getStatusColor(status: ThreatStatus): string {
  const colors: Record<ThreatStatus, string> = {
    new: "var(--color-danger)",
    investigating: "var(--color-warning)",
    acknowledged: "var(--color-accent-cyan)",
    resolved: "var(--color-success)",
    false_positive: "var(--color-text-muted)",
  };
  return colors[status];
}