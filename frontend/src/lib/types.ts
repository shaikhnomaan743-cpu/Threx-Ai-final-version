export type Severity = 'critical' | 'high' | 'medium';
export type ThreatClass = 'DDoS' | 'C2 Beaconing' | 'DGA' | 'TLS Malware' | 'Recon' | 'Exfiltration';
export type SystemStatus = 'SIMULATION' | 'BACKEND_SEEDED' | 'PCAP_REPLAY' | 'LIVE_INGEST' | 'LAB_TRAFFIC';

export interface Evidence { label: string; value: string | number; contribution?: number; }

export interface Alert {
  id: string; timestamp: string; severity: Severity; threat_class: ThreatClass;
  flow_id: string; source_ip: string; source_port: number;
  destination_ip: string; destination_port: number;
  confidence: number; protocol: string;
  block_height?: number; block_hash?: string;
  evidence: Evidence[]; bytes?: number; duration?: number;
  status?: 'new' | 'reviewed' | 'escalated';
}

export interface Metric {
  flows_per_second: number; throughput_mbps: number; detection_latency_ms: number;
  active_threats: number; total_detections: number; chain_height: number; uptime_seconds: number;
}

export interface ModelCard {
  name: string; detector: string; model_type: string;
  auc: number; accuracy: number; precision?: number; recall?: number; f1?: number;
  features: string[]; threats_caught: number; description: string;
  dataset: string; train_test_split: string;
}

export interface ThroughputBenchmark {
  sustained_peak: number; p50_ms: number; p95_ms: number; p99_ms: number;
  zero_drops: boolean; return_path: string; total_flows: number;
}
