import type { Alert, Severity, ThreatClass, Evidence } from './types';
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

/* ══════════════════════════════════════════════════════
   BACKEND → FRONTEND DATA MAPPER
   Transforms raw backend Alert schema to frontend Alert type
   ══════════════════════════════════════════════════════ */

const CLASS_MAP: Record<string, ThreatClass> = {
  'ddos': 'DDoS', 'DDoS': 'DDoS',
  'c2_beacon': 'C2 Beaconing', 'C2 Beaconing': 'C2 Beaconing',
  'dga': 'DGA', 'DGA': 'DGA',
  'dns_tunnel': 'DGA', // DNS tunnelling grouped under DGA
  'tls_malware': 'TLS Malware', 'TLS Malware': 'TLS Malware',
  'port_scan': 'Recon', 'Recon': 'Recon',
  'exfiltration': 'Exfiltration', 'Exfiltration': 'Exfiltration',
};

const SEV_MAP: Record<string, Severity> = {
  'low': 'medium', 'medium': 'medium', 'high': 'high', 'critical': 'critical',
};

function mapAlert(raw: any): Alert {
  if (!raw) return generateAlert(); // safety fallback

  const srcIp = raw.source_ip || raw.sourceIp || '';
  const dstIp = raw.destination_ip || raw.destinationIp || '';
  const srcPort = raw.source_port || raw.sourcePort || 0;
  const dstPort = raw.destination_port || raw.destinationPort || 0;

  // Confidence: backend sends 0.0-1.0, frontend uses 0-100
  let conf = raw.confidence ?? 0;
  if (conf <= 1 && conf > 0) conf = Math.round(conf * 100);

  // Timestamp: backend sends ISO string, frontend wants HH:MM:SS
  let ts = '';
  try {
    if (raw.timestamp) {
      const d = new Date(raw.timestamp);
      if (!isNaN(d.getTime())) {
        ts = d.toLocaleTimeString('en-GB');
      } else {
        ts = String(raw.timestamp);
      }
    } else {
      ts = now();
    }
  } catch { ts = now(); }

  // Evidence: backend uses {feature_name, value, contribution, description}
  // frontend uses {label, value, contribution}
  let evidence: Evidence[] = [];
  try {
    if (Array.isArray(raw.evidence) && raw.evidence.length > 0) {
      evidence = raw.evidence.map((e: any) => ({
        label: e.feature_name || e.label || e.name || 'unknown',
        value: e.value ?? 0,
        contribution: typeof e.contribution === 'number'
          ? (e.contribution <= 1 ? Math.round(e.contribution * 100) : Math.round(e.contribution))
          : undefined,
      }));
    } else {
      // Generate synthetic evidence based on threat class
      const cls = CLASS_MAP[raw.threat_class] || 'DGA';
      evidence = genEvidence(cls);
    }
  } catch { evidence = []; }

  // Flow ID
  let flowId = '';
  if (srcIp && dstIp) {
    flowId = `${srcIp}:${srcPort} → ${dstIp}:${dstPort}`;
  } else {
    flowId = raw.flow_id || raw.flowId || `flow-${rH(8)}`;
  }

  return {
    id: raw.alert_id || raw.id || `alert-${++ctr}-${rH(4)}`,
    timestamp: ts,
    severity: SEV_MAP[raw.severity] || (raw.severity as Severity) || 'medium',
    threat_class: CLASS_MAP[raw.threat_class] || CLASS_MAP[raw.threatClass] || raw.threat_class || 'DGA',
    flow_id: flowId,
    source_ip: srcIp,
    source_port: srcPort,
    destination_ip: dstIp,
    destination_port: dstPort,
    confidence: conf,
    protocol: (raw.protocol || 'tcp').toUpperCase(),
    block_height: raw.block_height || undefined,
    block_hash: raw.block_hash || undefined,
    evidence: evidence,
    bytes: raw.bytes_transferred || raw.bytes || 0,
    duration: raw.duration_seconds || raw.duration || 0,
    status: raw.status || 'new',
  };
}

/* ══════════════════════════════════════════════════════
   MOCK DATA GENERATORS (fallback when backend is offline)
   ══════════════════════════════════════════════════════ */

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

/* ══════════════════════════════════════════════════════
   API FETCH FUNCTIONS — all with mappers and safe fallbacks
   ══════════════════════════════════════════════════════ */

export async function fetchHealth(): Promise<{ok:boolean;status?:string}> {
  try {
    const r = await fetch(`${API}/health`, {signal: AbortSignal.timeout(3000)});
    const d = await r.json();
    return {ok: r.ok, status: d.status};
  } catch { return {ok: false}; }
}

export async function fetchThreats(n=50): Promise<Alert[]> {
  try {
    const r = await fetch(`${API}/threats?limit=${n}`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    // Backend may return array directly or {threats: [...]} or {items: [...]}
    const arr = Array.isArray(data) ? data : (data.threats || data.items || data.results || []);
    if (!Array.isArray(arr) || arr.length === 0) return seedAlerts(n);
    return arr.map(mapAlert);
  } catch {
    return seedAlerts(n);
  }
}

export async function fetchThreatById(id: string): Promise<Alert|null> {
  try {
    const r = await fetch(`${API}/threats/${id}`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    return mapAlert(data);
  } catch {
    // Fallback: generate one and give it the requested ID
    const a = generateAlert();
    a.id = id;
    return a;
  }
}

export async function fetchDNS() {
  try {
    const r = await fetch(`${API}/dns/dga`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    // Normalize backend response
    return {
      total: data.total_queries ?? data.total ?? rI(8000,15000),
      dga: data.dga_detected ?? data.dga ?? rI(40,120),
      tunnel: data.tunneling_detected ?? data.tunnel ?? rI(5,20),
      entropy: data.avg_entropy ?? data.entropy ?? rF(3.2,4.1),
      families: data.families || ['Nymaim','Matsnu','Suppobox','Gozi','CryptoLocker'],
      samples: Array.isArray(data.samples) ? data.samples.map((s: any) => ({
        domain: s.domain || s.query || `${rH(12)}.com`,
        entropy: s.entropy ?? rF(3.5,4.8).toFixed(2),
        family: s.family || s.dga_family || rP(['Nymaim','Matsnu','Suppobox','Gozi','CryptoLocker']),
        confidence: s.confidence ? (s.confidence <= 1 ? Math.round(s.confidence*100) : Math.round(s.confidence)) : rI(65,98),
      })) : Array.from({length:8},()=>({domain:`${rH(rI(8,16))}.com`,entropy:rF(3.5,4.8).toFixed(2),family:rP(['Nymaim','Matsnu','Suppobox','Gozi','CryptoLocker']),confidence:rI(65,98)})),
    };
  } catch {
    return { total:rI(8000,15000), dga:rI(40,120), tunnel:rI(5,20), entropy:rF(3.2,4.1),
      families:['Nymaim','Matsnu','Suppobox','Gozi','CryptoLocker'],
      samples:Array.from({length:8},()=>({domain:`${rH(rI(8,16))}.com`,entropy:rF(3.5,4.8).toFixed(2),family:rP(['Nymaim','Matsnu','Suppobox','Gozi','CryptoLocker']),confidence:rI(65,98)}))
    };
  }
}

export async function fetchTLS() {
  try {
    const r = await fetch(`${API}/tls/fingerprints`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    return {
      sessions: data.total_sessions ?? data.sessions ?? rI(200,500),
      malware: data.malware_detected ?? data.malware ?? rI(10,55),
      ja3: data.unique_ja3 ?? data.ja3 ?? rI(12,30),
      prints: Array.isArray(data.fingerprints || data.prints || data.suspicious_fingerprints)
        ? (data.fingerprints || data.prints || data.suspicious_fingerprints).map((f: any) => ({
          hash: f.ja3_hash || f.ja3 || f.hash || rH(32),
          ext: f.extensions_count ?? f.extensions ?? f.ext ?? rI(0,3),
          ciphers: f.ciphers_count ?? f.ciphers ?? rI(1,5),
          verdict: f.verdict || f.classification || rP(['Malware','Suspicious','Unknown C2']),
          conf: f.confidence ? (f.confidence <= 1 ? Math.round(f.confidence*100) : Math.round(f.confidence)) : rI(60,95),
        }))
        : Array.from({length:6},()=>({hash:rH(32),ext:rI(0,3),ciphers:rI(1,5),verdict:rP(['Malware','Suspicious','Unknown C2']),conf:rI(60,95)})),
    };
  } catch {
    return { sessions:rI(200,500), malware:rI(10,55), ja3:rI(12,30),
      prints:Array.from({length:6},()=>({hash:rH(32),ext:rI(0,3),ciphers:rI(1,5),verdict:rP(['Malware','Suspicious','Unknown C2']),conf:rI(60,95)}))
    };
  }
}

export async function fetchRecon() {
  try {
    const r = await fetch(`${API}/recon/scans`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    return {
      total: data.total_scans ?? data.total ?? rI(20,60),
      active: data.active_scanners ?? data.active ?? rI(3,8),
      scans: Array.isArray(data.scans)
        ? data.scans.map((s: any) => ({
          src: s.source_ip || s.source || s.src || rP(SRC),
          ports: s.unique_ports ?? s.ports ?? rI(50,2000),
          hosts: s.unique_hosts ?? s.hosts ?? rI(1,20),
          dur: s.duration ?? s.dur ?? rI(10,300),
          tech: s.technique ?? s.tech ?? rP(['SYN scan','TCP connect','UDP scan','FIN scan']),
        }))
        : Array.from({length:6},()=>({src:rP(SRC),ports:rI(50,2000),hosts:rI(1,20),dur:rI(10,300),tech:rP(['SYN scan','TCP connect','UDP scan','FIN scan'])})),
    };
  } catch {
    return { total:rI(20,60), active:rI(3,8),
      scans:Array.from({length:6},()=>({src:rP(SRC),ports:rI(50,2000),hosts:rI(1,20),dur:rI(10,300),tech:rP(['SYN scan','TCP connect','UDP scan','FIN scan'])}))
    };
  }
}

export async function fetchExfil() {
  try {
    const r = await fetch(`${API}/exfil/anomalies`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    return {
      total: data.total_anomalies ?? data.total ?? rI(8,30),
      bytes: data.total_bytes_exfil ?? data.bytes ?? rI(5e7,5e8),
      items: Array.isArray(data.anomalies || data.items)
        ? (data.anomalies || data.items).map((a: any) => ({
          src: a.source_ip || a.source || a.src || rP(SRC),
          dst: a.destination_ip || a.destination || a.dst || rP(DST),
          out: a.bytes_out || a.bytes_transferred || a.out || rI(5e5,5e7),
          ratio: a.byte_ratio || a.ratio || rF(3.5,25).toFixed(1),
          dur: a.duration || a.dur || rI(30,600),
          conf: a.confidence ? (a.confidence <= 1 ? Math.round(a.confidence*100) : Math.round(a.confidence)) : rI(70,96),
        }))
        : Array.from({length:5},()=>({src:rP(SRC),dst:rP(DST),out:rI(5e5,5e7),ratio:rF(3.5,25).toFixed(1),dur:rI(30,600),conf:rI(70,96)})),
    };
  } catch {
    return { total:rI(8,30), bytes:rI(5e7,5e8),
      items:Array.from({length:5},()=>({src:rP(SRC),dst:rP(DST),out:rI(5e5,5e7),ratio:rF(3.5,25).toFixed(1),dur:rI(30,600),conf:rI(70,96)}))
    };
  }
}

export async function fetchTraffic() {
  try {
    const r = await fetch(`${API}/traffic/stats`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    return {
      flows: data.total_flows ?? data.flows ?? rI(140,220),
      bytes: data.total_bytes ?? data.bytes ?? rI(8e8,2e9),
      protocols: data.protocols || data.protocol_distribution || {TCP:62,UDP:24,DNS:8,TLS:4,QUIC:2},
      avg_dur: data.avg_flow_duration ?? data.avg_dur ?? rF(8,45),
    };
  } catch {
    return {flows:rI(140,220),bytes:rI(8e8,2e9),protocols:{TCP:62,UDP:24,DNS:8,TLS:4,QUIC:2},avg_dur:rF(8,45)};
  }
}
