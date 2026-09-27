import type { Alert, Severity, ThreatClass, Metric } from './types';

/**
 * Backend data layer.
 *
 * Rules this file follows, deliberately:
 *
 *  1. No Math.random(), anywhere. Every value rendered by the dashboard comes
 *     from the backend. This file previously exported generateAlert(),
 *     seedAlerts() and rI/rF/rH/rP helpers, and every fetcher below ended in a
 *     `catch { return <randomised object> }`. That meant a backend outage
 *     produced a dashboard that looked perfectly healthy and full of traffic —
 *     the single most misleading failure mode a SOC tool can have.
 *
 *  2. Failures propagate. Fetchers throw ApiError; pages render an error state.
 *     "I could not reach the detector" and "the detector found nothing" are
 *     different answers and must look different.
 *
 *  3. No hardcoded headline numbers. TOP_TALKERS and DETECTION_MIX used to be
 *     literal arrays, so Overview always showed the same six counts and five
 *     IPs regardless of what the engine actually detected.
 */

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export class ApiError extends Error {
  status: number;
  constructor(message: string, status = 0) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function getJSON<T>(path: string, timeoutMs = 8000): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API}${path}`, { signal: AbortSignal.timeout(timeoutMs) });
  } catch (e) {
    throw new ApiError(
      `Cannot reach backend at ${API}${path} — ${(e as Error).message}`, 0,
    );
  }
  if (!res.ok) {
    let detail = '';
    try {
      const body = await res.json();
      detail = typeof body?.detail === 'string'
        ? body.detail
        : body?.detail?.message || body?.detail?.cause || '';
    } catch { /* non-JSON error body */ }
    throw new ApiError(`${path} returned ${res.status}${detail ? `: ${detail}` : ''}`, res.status);
  }
  return res.json() as Promise<T>;
}

// ── Shapes returned by the backend ────────────────────────────────────
type BackendAlert = {
  alert_id: string; timestamp: string; flow_id: string;
  threat_class: string; severity: string; confidence: number;
  source_ip: string; source_port: number | null;
  destination_ip: string; destination_port: number | null;
  protocol: string; bytes_transferred: number;
  packet_count: number; duration_seconds: number;
  evidence: { feature_name: string; value: number; contribution?: number; description: string }[];
  raw_features?: Record<string, number>;
};

export type ThroughputTelemetry = {
  flows_per_sec: number; peak_flows_per_sec: number;
  packets_per_sec: number; bytes_per_sec: number;
  total_flows: number; total_packets: number; total_bytes: number;
  latency: {
    samples: number; total_inferences: number;
    p50_ms: number; p95_ms: number; p99_ms: number;
    min_ms: number; max_ms: number; mean_ms: number;
  };
  queue: { depth: number; dropped_flows: number };
  alerts_generated: number;
  resources: {
    available: boolean; reason?: string;
    cpu_percent?: number; memory_rss_mb?: number; memory_percent?: number;
    system_memory_percent?: number; num_threads?: number;
  };
  detection_active: boolean;
  degraded_reason: string | null;
  data_source: string | null;
  return_path: string;
  uptime_seconds: number;
  timestamp: string;
  pipeline?: {
    mode: 'single_process' | 'multi_core';
    latency_basis: string;
    workers?: number; dst_aggregators?: number; records_received?: number;
    loss?: { exporter_seq_gap_records: number; queue_drops_messages: number;
             unknown_template_sets: number; malformed_datagrams: number };
    alerts?: { alerts_in?: number; alerts_new?: number; alerts_merged?: number;
               pushed?: number; push_suppressed?: number };
  };
};

export type TimeSeriesBucket = { offset_s: number; flows: number; packets: number; bytes: number };

const ev = (a: BackendAlert, name: string, dflt = 0): number => {
  const hit = a.evidence?.find(e => e.feature_name === name);
  if (hit && Number.isFinite(hit.value)) return hit.value;
  const raw = a.raw_features?.[name];
  return Number.isFinite(raw as number) ? (raw as number) : dflt;
};

const pct = (n: number) => Math.round(n * 100);
const uniq = <T,>(xs: T[]) => Array.from(new Set(xs));
const avg = (xs: number[]) => (xs.length ? xs.reduce((s, x) => s + x, 0) / xs.length : 0);

const CLASS_MAP: Record<string, ThreatClass> = {
  ddos: 'DDoS', c2_beacon: 'C2 Beaconing', dga: 'DGA',
  dns_tunnel: 'DNS Tunnel', tls_malware: 'TLS Malware',
  port_scan: 'Recon', exfiltration: 'Exfiltration',
};

const SEV_MAP: Record<string, Severity> = {
  critical: 'critical', high: 'high', medium: 'medium', low: 'low',
};

export const CLASS_COLOR: Record<string, string> = {
  'DDoS': '#f04050', 'C2 Beaconing': '#e8a020', 'DGA': '#8060f0',
  'DNS Tunnel': '#4080f0', 'TLS Malware': '#10d4e8',
  'Recon': '#6a7a8c', 'Exfiltration': '#20c070',
};

const clockTime = (iso: string): string => {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return [d.getHours(), d.getMinutes(), d.getSeconds()]
    .map(n => String(n).padStart(2, '0')).join(':');
};

function toAlert(a: BackendAlert): Alert {
  return {
    id: a.alert_id,
    timestamp: clockTime(a.timestamp),
    severity: SEV_MAP[String(a.severity).toLowerCase()] || 'medium',
    threat_class: CLASS_MAP[a.threat_class] || (a.threat_class as ThreatClass),
    flow_id: a.flow_id,
    source_ip: a.source_ip,
    source_port: a.source_port ?? 0,
    destination_ip: a.destination_ip,
    destination_port: a.destination_port ?? 0,
    confidence: Math.round((a.confidence ?? 0) * 100),
    protocol: String(a.protocol || '').toUpperCase(),
    evidence: (a.evidence || []).map(e => ({
      label: e.feature_name,
      value: e.value,
      contribution: Math.round((e.contribution ?? 0) * 100),
    })),
    bytes: a.bytes_transferred,
    duration: a.duration_seconds,
    status: 'new',
  };
}

// ── Health ────────────────────────────────────────────────────────────
export type Health = {
  ok: boolean;
  status?: string;
  detection_active?: boolean;
  degraded_reason?: string;
  version?: string;
  error?: string;
};

export async function fetchHealth(): Promise<Health> {
  try {
    const d = await getJSON<Record<string, unknown>>('/health', 3000);
    return {
      ok: true,
      status: d.status as string,
      detection_active: d.detection_active as boolean,
      degraded_reason: d.degraded_reason as string | undefined,
      version: d.version as string,
    };
  } catch (e) {
    // The only place a failure becomes a value rather than a throw: "is the
    // backend up" is a yes/no question and false is a real answer to it.
    return { ok: false, error: (e as Error).message };
  }
}

// ── Threats ───────────────────────────────────────────────────────────
export async function fetchThreats(n = 50): Promise<Alert[]> {
  const raw = await getJSON<BackendAlert[]>(`/threats/?limit=${n}`);
  if (!Array.isArray(raw)) throw new ApiError('unexpected /threats shape');
  return raw.map(toAlert);
}

export async function fetchThreatById(id: string): Promise<Alert | null> {
  try {
    return toAlert(await getJSON<BackendAlert>(`/threats/${id}`));
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return null;
    throw e;
  }
}

// ── Live telemetry ────────────────────────────────────────────────────
export const fetchTelemetry = () =>
  getJSON<ThroughputTelemetry>('/api/v1/metrics/throughput');

export async function fetchTimeSeries(buckets = 60, bucketSeconds = 1) {
  return getJSON<{
    buckets: number; bucket_seconds: number; series: TimeSeriesBucket[];
    protocol_distribution: Record<string, number>;
    observed_flows_in_window: number; window_empty: boolean;
  }>(`/api/v1/analytics/time-series?buckets=${buckets}&bucket_seconds=${bucketSeconds}`);
}

export const fetchModelMetrics = () =>
  getJSON<Record<string, unknown>>('/api/v1/models');

// ── Detection mix / top talkers (computed from real alerts) ───────────
export async function fetchDetectionMix(): Promise<{ cls: string; count: number; color: string }[]> {
  const raw = await getJSON<BackendAlert[]>('/threats/?limit=1000');
  const counts = new Map<string, number>();
  for (const a of raw) {
    const label = CLASS_MAP[a.threat_class] || a.threat_class;
    counts.set(label, (counts.get(label) || 0) + 1);
  }
  return Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([cls, count]) => ({ cls, count, color: CLASS_COLOR[cls] || '#6a7a8c' }));
}

export async function fetchTopTalkers(limit = 10) {
  const [talkers, alerts] = await Promise.all([
    getJSON<{ ip: string; bytes: number }[]>(`/traffic/top-talkers?limit=${limit}`),
    getJSON<BackendAlert[]>('/threats/?limit=1000').catch(() => [] as BackendAlert[]),
  ]);
  // Annotate each talker with what was actually detected from it, instead of
  // the fixed editorial strings ("C2 suspect · 60s beacon") this used to ship.
  const bySource = new Map<string, BackendAlert[]>();
  for (const a of alerts) {
    const list = bySource.get(a.source_ip) || [];
    list.push(a);
    bySource.set(a.source_ip, list);
  }
  return talkers.map(t => {
    const hits = bySource.get(t.ip) || [];
    const classes = uniq(hits.map(h => CLASS_MAP[h.threat_class] || h.threat_class));
    const worst = hits.some(h => ['critical', 'high'].includes(String(h.severity).toLowerCase()));
    return {
      ip: t.ip,
      bytes: t.bytes,
      pkts: hits.reduce((s, h) => s + (h.packet_count || 0), 0),
      flows: hits.length,
      note: classes.length ? classes.join(', ') : 'No detections',
      flagged: worst,
    };
  });
}

// ── Per-class analytics ───────────────────────────────────────────────
export async function fetchDNS() {
  const d = await getJSON<{
    detection_active: boolean; dga_detections: number; tunnel_detections: number;
    total: number; mean_domain_entropy: number | null; entropy_samples: number;
    top_sources: { source_ip: string; detections: number }[];
    samples: {
      alert_id: string; source_ip: string; destination_ip: string;
      domain_entropy: number; bigram_likelihood: number;
      confidence: number; severity: string;
    }[];
  }>('/api/v1/analytics/dns');
  return {
    total: d.total,
    dga: d.dga_detections,
    tunnel: d.tunnel_detections,
    entropy: d.mean_domain_entropy,
    entropySamples: d.entropy_samples,
    families: d.top_sources.map(s => ({ name: s.source_ip, count: s.detections })),
    samples: d.samples.map(s => ({
      domain: s.destination_ip,
      entropy: s.domain_entropy ? s.domain_entropy.toFixed(2) : '—',
      family: s.severity.toUpperCase(),
      confidence: pct(s.confidence),
    })),
  };
}

export async function fetchTLS() {
  const d = await getJSON<{
    detection_active: boolean; ja3s_available: boolean; ja3s_reason: string;
    sessions_flagged: number; malware_verdicts: number;
    fingerprints: {
      alert_id: string; flow_id: string; source_ip: string;
      destination_ip: string; extensions_count: number; ciphers_count: number;
      confidence: number; severity: string;
    }[];
  }>('/api/v1/analytics/tls');
  return {
    sessions: d.sessions_flagged,
    malware: d.malware_verdicts,
    ja3: uniq(d.fingerprints.map(f => f.flow_id)).length,
    ja3sAvailable: d.ja3s_available,
    ja3sReason: d.ja3s_reason,
    prints: d.fingerprints.map(f => ({
      hash: f.flow_id,
      ext: f.extensions_count,
      ciphers: f.ciphers_count,
      verdict: ['critical', 'high'].includes(String(f.severity).toLowerCase()) ? 'Malware' : 'Suspicious',
      conf: pct(f.confidence),
    })),
  };
}

export async function fetchRecon() {
  const list = await getJSON<BackendAlert[]>('/recon/scans');
  if (!Array.isArray(list)) throw new ApiError('unexpected /recon/scans shape');
  return {
    total: list.length,
    active: uniq(list.map(a => a.source_ip)).length,
    scans: list.slice(0, 25).map(a => ({
      src: a.source_ip,
      ports: Math.round(ev(a, 'unique_dst_ports')),
      hosts: Math.round(ev(a, 'unique_dst_hosts')),
      dur: Math.round(a.duration_seconds),
      tech: `${(a.protocol || 'tcp').toUpperCase()} scan`,
    })),
  };
}

export async function fetchExfil() {
  const list = await getJSON<BackendAlert[]>('/exfil/anomalies');
  if (!Array.isArray(list)) throw new ApiError('unexpected /exfil/anomalies shape');
  const out = (a: BackendAlert) => a.bytes_transferred || ev(a, 'total_bytes_transferred');
  return {
    total: list.length,
    bytes: list.reduce((s, a) => s + out(a), 0),
    items: list.slice(0, 25).map(a => ({
      src: a.source_ip,
      dst: a.destination_ip,
      out: out(a),
      ratio: (() => {
        const r = ev(a, 'outbound_inbound_ratio');
        return r >= 1000 ? '>1000' : r.toFixed(1);
      })(),
      conf: pct(a.confidence),
    })),
  };
}

export async function fetchTraffic() {
  const [stats, ts] = await Promise.all([
    getJSON<Record<string, number>>('/traffic/stats'),
    fetchTimeSeries(60, 1).catch(() => null),
  ]);
  if (!stats || typeof stats.total_flows !== 'number') {
    throw new ApiError('unexpected /traffic/stats shape');
  }
  let avgDur = 0;
  try {
    const alerts = await getJSON<BackendAlert[]>('/threats/?limit=500');
    avgDur = avg(alerts.map(a => a.duration_seconds).filter(Number.isFinite));
  } catch { /* average duration is supplementary */ }

  return {
    flows: stats.total_flows,
    bytes: stats.total_bytes ?? 0,
    packets: stats.total_packets ?? 0,
    avg_dur: avgDur,
    protocols: ts?.protocol_distribution ?? {},
    series: ts?.series ?? [],
    seriesEmpty: ts?.window_empty ?? true,
  };
}

// ── Reports ───────────────────────────────────────────────────────────
const REPORT_CLASS: Record<string, string | undefined> = {
  'All': undefined, 'DDoS': 'ddos', 'C2 Beaconing': 'c2_beacon', 'DGA': 'dga',
  'DNS Tunnel': 'dns_tunnel', 'TLS Malware': 'tls_malware',
  'Recon': 'port_scan', 'Exfiltration': 'exfiltration',
};

export async function generateReport(opts: {
  format: string; cls: string; sev: string; limit: number;
}): Promise<{ blob: Blob; filename: string; count: number }> {
  const fmt = opts.format.toLowerCase() === 'csv' ? 'csv' : 'json';
  const params = new URLSearchParams({ format: fmt, limit: String(opts.limit) });
  const cls = REPORT_CLASS[opts.cls];
  if (cls) params.set('threat_class', cls);
  if (opts.sev && opts.sev !== 'All') params.set('severity', opts.sev.toLowerCase());

  const res = await fetch(`${API}/reports/generate?${params}`);
  if (!res.ok) throw new ApiError(`Backend returned ${res.status} — is it running on ${API}?`, res.status);

  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  const filename = `threx-report-${stamp}.${fmt}`;

  if (fmt === 'csv') {
    const text = await res.text();
    const count = Math.max(0, text.trim().split('\n').length - 1);
    return { blob: new Blob([text], { type: 'text/csv' }), filename, count };
  }
  const json = await res.json();
  const rows = Array.isArray(json) ? json : (json.data ?? []);
  return {
    blob: new Blob([JSON.stringify(json, null, 2)], { type: 'application/json' }),
    filename,
    count: Array.isArray(rows) ? rows.length : 0,
  };
}

// ── Headline metrics ──────────────────────────────────────────────────
export async function fetchMetrics(telemetry?: ThroughputTelemetry): Promise<Partial<Metric>> {
  // Pass the telemetry you already fetched to avoid a second identical request.
  const [t, alerts] = await Promise.all([
    telemetry ? Promise.resolve(telemetry) : fetchTelemetry(),
    getJSON<BackendAlert[]>('/threats/?limit=1000').catch(() => [] as BackendAlert[]),
  ]);
  const active = alerts.filter(a =>
    ['critical', 'high'].includes(String(a.severity).toLowerCase()));
  return {
    uptime_seconds: t.uptime_seconds,
    total_detections: alerts.length,
    active_threats: active.length,
    flows_per_second: t.flows_per_sec,
    detection_latency_ms: t.latency.p50_ms,
    throughput_mbps: +((t.bytes_per_sec * 8) / 1e6).toFixed(2),
  };
}
