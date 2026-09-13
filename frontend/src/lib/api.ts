import type { Alert, Severity, ThreatClass, Evidence, Metric } from './types';
import { CLASS_EVIDENCE } from './utils';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const HEX = '0123456789abcdef';
const rH = (n: number) => Array.from({length:n},()=>HEX[(Math.random()*16)|0]).join('');
const rP = <T>(a: T[]): T => a[(Math.random()*a.length)|0];
const rI = (a: number, b: number) => Math.round(a+Math.random()*(b-a));
const rF = (a: number, b: number) => +(a+Math.random()*(b-a)).toFixed(3);
const pad = (n: number) => n<10?'0'+n:''+n;
const now = () => { const d=new Date(); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };

const CLASSES: {c:ThreatClass;s:Severity;conf:[number,number]}[] = [
  {c:'DDoS',s:'critical',conf:[70,92]},{c:'C2 Beaconing',s:'critical',conf:[68,85]},
  {c:'DGA',s:'high',conf:[61,80]},{c:'TLS Malware',s:'high',conf:[58,78]},
  {c:'Recon',s:'medium',conf:[44,66]},{c:'Exfiltration',s:'critical',conf:[75,95]},
];
const SRC=['192.0.2.44','198.51.100.10','192.0.2.98','172.16.0.22','10.0.0.50','192.0.2.157','192.0.2.183','192.0.2.10'];
const DST=['198.51.100.100','203.0.113.50','8.8.8.8','203.0.113.60','104.26.10.5','198.51.100.50'];
const PORTS=[443,80,8080,53,8443,22,3389,445,1433,993];
const PROTO=['TCP','UDP','DNS','TLS','QUIC'];

function genEvidence(cls: ThreatClass): Evidence[] {
  const specs = CLASS_EVIDENCE[cls] || [];
  return specs.map(s => {
    let val: string|number;
    switch(s.key) {
      case 'packet_rate': val=rI(5000,50000); break;
      case 'syn_ack_ratio': val=rF(5,15); break;
      case 'source_entropy': val=rF(0.1,0.5); break;
      case 'amplification_ratio': val=rF(2,30); break;
      case 'periodicity_score': val=rF(0.2,0.95); break;
      case 'dominant_period': val=rF(55,65); break;
      case 'inter_arrival_cv': val=rF(0.01,0.09); break;
      case 'jitter': val=rF(100,3000); break;
      case 'domain_entropy': val=rF(3.5,4.8); break;
      case 'bigram_likelihood': val=rF(-12,-6); break;
      case 'digit_ratio': val=rF(15,60); break;
      case 'consonant_vowel_ratio': val=rF(1.5,4); break;
      case 'extensions_count': val=rI(0,3); break;
      case 'ciphers_count': val=rI(1,5); break;
      case 'min_pkt_size': val=rI(40,200); break;
      case 'median_pkt_size': val=rI(100,800); break;
      case 'unique_dst_ports': val=rI(50,2000); break;
      case 'unique_dst_hosts': val=rI(1,20); break;
      case 'scan_duration': val=rI(10,300); break;
      case 'byte_ratio_outbound': val=rF(3.5,25); break;
      case 'total_bytes': val=rI(500000,50000000); break;
      case 'avg_pkt_size': val=rI(200,1400); break;
      case 'flow_duration': val=rI(30,600); break;
      default: val=rF(0,1);
    }
    return { label: s.key, value: val, contribution: rI(10,40) };
  });
}

let ctr = 0;
export function generateAlert(): Alert {
  const k = rP(CLASSES);
  const sp = rP(PORTS), dp = rP(PORTS);
  const si = rP(SRC), di = rP(DST);
  ctr++;
  return {
    id: `alert-${ctr}-${rH(4)}`, timestamp: now(), severity: k.s, threat_class: k.c,
    flow_id: `${si}:${sp} → ${di}:${dp}`,
    source_ip: si, source_port: sp, destination_ip: di, destination_port: dp,
    confidence: rI(k.conf[0], k.conf[1]), protocol: rP(PROTO),
    block_height: 3680 + ctr, block_hash: `${rH(8)}`,
    evidence: genEvidence(k.c),
    bytes: rI(1000, 500000), duration: rI(1, 300),
    status: 'new',
  };
}

export const seedAlerts = (n: number) => Array.from({length:n}, generateAlert);

export const TOP_TALKERS = [
  {ip:'198.51.100.20',bytes:48200000,pkts:31200,flows:42,note:'C2 suspect · 60s beacon',flagged:true},
  {ip:'192.0.2.98',bytes:34100000,pkts:22800,flows:18,note:'SYN flood source · 14k pps',flagged:true},
  {ip:'10.0.0.50',bytes:22700000,pkts:15100,flows:89,note:'High DNS query rate',flagged:false},
  {ip:'172.16.0.22',bytes:18400000,pkts:12200,flows:156,note:'Normal profile',flagged:false},
  {ip:'203.0.113.60',bytes:8900000,pkts:5900,flows:7,note:'Outbound 8.4 MB',flagged:true},
];

export const DETECTION_MIX = [
  {cls:'DDoS',count:87,color:'#f04050'},{cls:'C2 Beaconing',count:64,color:'#e8a020'},
  {cls:'DGA',count:112,color:'#8060f0'},{cls:'TLS Malware',count:53,color:'#10d4e8'},
  {cls:'Recon',count:134,color:'#6a7a8c'},{cls:'Exfiltration',count:50,color:'#20c070'},
];

// ── Backend adapters ──────────────────────────────────────────────
// The detection endpoints all return a flat array of alert records. The pages
// below were written against summary objects, so each fetcher normalises the
// array into the shape its page renders. Without this the pages receive
// `undefined` where they expect an array and crash to a blank screen.

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

/** Pull a named evidence/raw_feature value off an alert, with a default. */
const ev = (a: BackendAlert, name: string, dflt = 0): number => {
  const hit = a.evidence?.find(e => e.feature_name === name);
  if (hit && Number.isFinite(hit.value)) return hit.value;
  const raw = a.raw_features?.[name];
  return Number.isFinite(raw as number) ? (raw as number) : dflt;
};

const pct = (n: number) => Math.round(n * 100);
const uniq = <T,>(xs: T[]) => Array.from(new Set(xs));
const avg = (xs: number[]) => (xs.length ? xs.reduce((s, x) => s + x, 0) / xs.length : 0);

async function getJSON<T>(path: string): Promise<T> {
  const r = await fetch(`${API}${path}`);
  if (!r.ok) throw new Error(`${path} -> ${r.status}`);
  return r.json();
}

export async function fetchHealth(): Promise<{ok:boolean;status?:string}> {
  try { const r=await fetch(`${API}/health`,{signal:AbortSignal.timeout(3000)}); const d=await r.json(); return {ok:r.ok,status:d.status}; }
  catch { return {ok:false}; }
}
// Backend threat_class values -> the labels the UI filters and colours on.
const CLASS_MAP: Record<string, ThreatClass> = {
  ddos: 'DDoS', c2_beacon: 'C2 Beaconing', dga: 'DGA',
  dns_tunnel: 'DNS Tunnel', tls_malware: 'TLS Malware',
  port_scan: 'Recon', exfiltration: 'Exfiltration',
};

const SEV_MAP: Record<string, Severity> = {
  critical: 'critical', high: 'high', medium: 'medium', low: 'low',
};

/** ISO timestamp -> HH:MM:SS, matching the live-feed format. */
const clockTime = (iso: string): string => {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return [d.getHours(), d.getMinutes(), d.getSeconds()]
    .map(n => String(n).padStart(2, '0')).join(':');
};

/**
 * Normalise a backend alert into the `Alert` shape the pages render.
 * The backend sends confidence as 0-1, snake_case threat classes and ISO
 * timestamps; the UI expects 0-100, display labels and a clock time. Without
 * this the confidence column shows "0.085410768...%" and the class filters
 * never match.
 */
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

export async function fetchThreats(n=50): Promise<Alert[]> {
  try {
    const raw = await getJSON<BackendAlert[]>(`/threats?limit=${n}`);
    if (!Array.isArray(raw)) throw new Error('unexpected /threats shape');
    return raw.map(toAlert);
  }
  catch { return seedAlerts(n); }
}
export async function fetchThreatById(id: string): Promise<Alert|null> {
  try { return toAlert(await getJSON<BackendAlert>(`/threats/${id}`)); }
  catch { return null; }
}

export async function fetchDNS() {
  try {
    const [dga, tunnel] = await Promise.all([
      getJSON<BackendAlert[]>('/dns/dga'),
      getJSON<BackendAlert[]>('/dns/tunneling').catch(() => [] as BackendAlert[]),
    ]);
    if (!Array.isArray(dga)) throw new Error('unexpected /dns/dga shape');

    // Group DGA hits by source so the panel shows real attribution. The backend
    // does not emit the queried name itself, so we report the resolver target.
    const bySource = new Map<string, number>();
    for (const a of dga) bySource.set(a.source_ip, (bySource.get(a.source_ip) || 0) + 1);

    return {
      total: dga.length + tunnel.length,
      dga: dga.length,
      tunnel: tunnel.length,
      entropy: avg(dga.map(a => ev(a, 'domain_entropy'))),
      families: Array.from(bySource.entries())
        .sort((a, b) => b[1] - a[1]).slice(0, 6)
        .map(([ip, n]) => ({ name: ip, count: n })),
      samples: dga.slice(0, 12).map(a => ({
        domain: a.destination_ip,
        entropy: ev(a, 'domain_entropy').toFixed(2),
        family: a.severity.toUpperCase(),
        confidence: pct(a.confidence),
      })),
    };
  }
  catch {
    return { total:rI(8000,15000), dga:rI(40,120), tunnel:rI(5,20), entropy:rF(3.2,4.1),
      families:['Nymaim','Matsnu','Suppobox','Gozi','CryptoLocker'].map(n=>({name:n,count:rI(5,35)})),
      samples:Array.from({length:8},()=>({domain:`${rH(rI(8,16))}.com`,entropy:rF(3.5,4.8).toFixed(2),family:rP(['Nymaim','Matsnu','Suppobox','Gozi','CryptoLocker']),confidence:rI(65,98)}))
    };
  }
}

export async function fetchTLS() {
  try {
    const list = await getJSON<BackendAlert[]>('/tls/fingerprints');
    if (!Array.isArray(list)) throw new Error('unexpected /tls/fingerprints shape');
    return {
      sessions: list.length,
      malware: list.filter(a => a.severity === 'high' || a.severity === 'critical').length,
      ja3: uniq(list.map(a => a.flow_id)).length,
      prints: list.slice(0, 12).map(a => ({
        hash: a.flow_id,
        ext: ev(a, 'extensions_count'),
        ciphers: ev(a, 'ciphers_count'),
        verdict: a.severity === 'critical' ? 'Malware'
               : a.severity === 'high' ? 'Malware' : 'Suspicious',
        conf: pct(a.confidence),
      })),
    };
  }
  catch {
    return { sessions:rI(200,500), malware:rI(10,55), ja3:rI(12,30),
      prints:Array.from({length:6},()=>({hash:rH(32),ext:rI(0,3),ciphers:rI(1,5),verdict:rP(['Malware','Suspicious','Unknown C2']),conf:rI(60,95)}))
    };
  }
}

export async function fetchRecon() {
  try {
    const list = await getJSON<BackendAlert[]>('/recon/scans');
    if (!Array.isArray(list)) throw new Error('unexpected /recon/scans shape');
    const SCAN_TYPES = ['SYN scan','TCP connect','UDP scan','FIN scan'];
    return {
      total: list.length,
      active: uniq(list.map(a => a.source_ip)).length,
      scans: list.slice(0, 15).map(a => {
        const t = ev(a, 'scan_type', -1);
        return {
          src: a.source_ip,
          ports: Math.round(ev(a, 'unique_dst_ports')),
          hosts: Math.round(ev(a, 'unique_dst_hosts')),
          dur: Math.round(a.duration_seconds),
          tech: t >= 0 && t < SCAN_TYPES.length ? SCAN_TYPES[t] : (a.protocol || 'tcp').toUpperCase() + ' scan',
        };
      }),
    };
  }
  catch {
    return { total:rI(20,60), active:rI(3,8),
      scans:Array.from({length:6},()=>({src:rP(SRC),ports:rI(50,2000),hosts:rI(1,20),dur:rI(10,300),tech:rP(['SYN scan','TCP connect','UDP scan','FIN scan'])}))
    };
  }
}

export async function fetchExfil() {
  try {
    const list = await getJSON<BackendAlert[]>('/exfil/anomalies');
    if (!Array.isArray(list)) throw new Error('unexpected /exfil/anomalies shape');
    const out = (a: BackendAlert) => a.bytes_transferred || ev(a, 'total_bytes_transferred');
    return {
      total: list.length,
      bytes: list.reduce((s, a) => s + out(a), 0),
      items: list.slice(0, 12).map(a => ({
        src: a.source_ip,
        dst: a.destination_ip,
        out: out(a),
        // ratio = outbound / max(inbound,1); with no inbound observed it
        // degenerates into the raw byte count, so cap it rather than print it.
        ratio: (() => { const r = ev(a, 'outbound_inbound_ratio');
          return r >= 1000 ? '>1000' : r.toFixed(1); })(),
        conf: pct(a.confidence),
      })),
    };
  }
  catch {
    return { total:rI(8,30), bytes:rI(5e7,5e8),
      items:Array.from({length:5},()=>({src:rP(SRC),dst:rP(DST),out:rI(5e5,5e7),ratio:rF(3.5,25).toFixed(1),conf:rI(70,96)}))
    };
  }
}

export async function fetchTraffic() {
  try {
    const stats = await getJSON<Record<string, number>>('/traffic/stats');
    if (!stats || typeof stats.total_flows !== 'number') throw new Error('unexpected /traffic/stats shape');

    // /traffic/stats has no protocol breakdown, so derive it from the alert feed.
    let protocols: Record<string, number> = { TCP: 100 };
    let avgDur = 0;
    try {
      const alerts = await getJSON<BackendAlert[]>('/threats?limit=500');
      if (Array.isArray(alerts) && alerts.length) {
        const counts: Record<string, number> = {};
        for (const a of alerts) {
          const p = (a.protocol || 'other').toUpperCase();
          counts[p] = (counts[p] || 0) + 1;
        }
        protocols = Object.fromEntries(
          Object.entries(counts).map(([p, c]) => [p, Math.round((c / alerts.length) * 100)])
        );
        avgDur = avg(alerts.map(a => a.duration_seconds).filter(Number.isFinite));
      }
    } catch { /* protocol mix is best-effort; the metric cards still render */ }

    return {
      flows: stats.total_flows,
      bytes: stats.total_bytes ?? 0,
      packets: stats.total_packets ?? 0,
      avg_dur: avgDur,
      protocols,
    };
  }
  catch { return {flows:rI(140,220),bytes:rI(8e8,2e9),packets:rI(1e5,9e5),protocols:{TCP:62,UDP:24,DNS:8,TLS:4,QUIC:2},avg_dur:rF(8,45)}; }
}

// ── Report generation ─────────────────────────────────────────────
// UI labels -> the backend's threat_class / severity vocabulary.
const REPORT_CLASS: Record<string, string|undefined> = {
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
  if (!res.ok) throw new Error(`Backend returned ${res.status} — is it running on ${API}?`);

  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  const filename = `threx-report-${stamp}.${fmt}`;

  if (fmt === 'csv') {
    const text = await res.text();
    const count = Math.max(0, text.trim().split('\n').length - 1); // minus header
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

/**
 * Real metrics for the Command Center, assembled from the backend.
 * Previously these headline numbers were generated with Math.random(), which is
 * why "Total Detections" read 1 while the threat distribution summed to 500.
 */
export async function fetchMetrics(): Promise<Partial<Metric> | null> {
  try {
    const [health, stats, alerts] = await Promise.all([
      getJSON<Record<string, unknown>>('/health'),
      getJSON<Record<string, number>>('/traffic/stats').catch(() => ({} as Record<string, number>)),
      getJSON<BackendAlert[]>('/threats?limit=1000').catch(() => [] as BackendAlert[]),
    ]);
    const list = Array.isArray(alerts) ? alerts : [];
    const active = list.filter(a => ['critical', 'high'].includes(String(a.severity).toLowerCase()));
    return {
      uptime_seconds: Number(health.uptime_seconds) || 0,
      total_detections: list.length,
      active_threats: active.length,
      throughput_mbps: stats.total_bytes ? +((stats.total_bytes * 8) / 1e6 / 60).toFixed(2) : undefined,
    };
  } catch { return null; }
}
