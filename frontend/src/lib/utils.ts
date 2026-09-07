export const formatUptime = (s: number) => {
  const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sec=s%60;
  return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(sec).padStart(2,'0')}`;
};
export const formatBytes = (b: number) => b>=1e9?(b/1e9).toFixed(1)+' GB':b>=1e6?(b/1e6).toFixed(1)+' MB':b>=1e3?(b/1e3).toFixed(0)+' KB':b+' B';

export const CLASS_COLORS: Record<string,string> = {
  'DDoS':'#f04050','C2 Beaconing':'#e8a020','DGA':'#8060f0',
  'TLS Malware':'#10d4e8','Recon':'#6a7a8c','Exfiltration':'#20c070',
};

// evidence features per threat class — what the ML models actually output
export const CLASS_EVIDENCE: Record<string, {key:string;unit:string}[]> = {
  'DDoS': [{key:'packet_rate',unit:'pps'},{key:'syn_ack_ratio',unit:''},{key:'source_entropy',unit:''},{key:'amplification_ratio',unit:'x'}],
  'C2 Beaconing': [{key:'periodicity_score',unit:''},{key:'dominant_period',unit:'s'},{key:'inter_arrival_cv',unit:''},{key:'jitter',unit:'ms'}],
  'DGA': [{key:'domain_entropy',unit:'bits'},{key:'bigram_likelihood',unit:''},{key:'digit_ratio',unit:'%'},{key:'consonant_vowel_ratio',unit:''}],
  'TLS Malware': [{key:'extensions_count',unit:''},{key:'ciphers_count',unit:''},{key:'min_pkt_size',unit:'B'},{key:'median_pkt_size',unit:'B'}],
  'Recon': [{key:'unique_dst_ports',unit:''},{key:'unique_dst_hosts',unit:''},{key:'syn_ack_ratio',unit:''},{key:'scan_duration',unit:'s'}],
  'Exfiltration': [{key:'byte_ratio_outbound',unit:':1'},{key:'total_bytes',unit:'B'},{key:'avg_pkt_size',unit:'B'},{key:'flow_duration',unit:'s'}],
};

export const BENCHMARK = {
  sustained_peak: 88.6, p50_ms: 12.93, p95_ms: 12.93, p99_ms: 13.95,
  zero_drops: true, return_path: 'NONE', total_flows: 180,
};

export const MODELS = [
  { name:'DGA', detector:'LightGBM', type:'Gradient Boosting', auc:.9991, testAuc:1.0, acc:.999, dataset:'1000 Tranco benign + 5000 DGArchive malicious', split:'80/20 stratified, seed 42', features:['domain_entropy','bigram_likelihood','digit_ratio','consonant_vowel_ratio'], caught:112, desc:'Classifies DGA domains vs legitimate via entropy and n-gram analysis.' },
  { name:'TLS Malware', detector:'RandomForest', type:'Classification', auc:1.0, testAuc:1.0, acc:1.0, dataset:'200 benign + 200 malware JA3/packet-size synthetic', split:'80/20, seed 42', features:['extensions_count','ciphers_count','curves_count','min_size','median_size'], caught:53, desc:'Detects malware-controlled TLS from JA3 fingerprints — zero payload decryption.' },
  { name:'DDoS', detector:'IsolationForest', type:'Anomaly Detection', auc:.9967, testAuc:.9967, acc:.99, dataset:'300 benign + 300 attack flow rates', split:'80/20, seed 42', features:['packet_rate','byte_rate','syn_ack_ratio','amplification_ratio'], caught:87, desc:'Isolates volumetric anomalies — SYN floods, UDP amplification, spoofed-source floods.' },
  { name:'Exfiltration', detector:'IsolationForest', type:'Anomaly Detection', auc:.9933, testAuc:.9933, acc:.99, dataset:'Asymmetric flow-volume profiles', split:'80/20, seed 42', features:['byte_ratio_outbound','total_bytes','avg_pkt_size'], caught:50, desc:'Catches asymmetric outbound volume anomalies exceeding baselines.' },
  { name:'C2 Beaconing', detector:'FFT + CV Analysis', type:'Signal Processing', auc:1.0, testAuc:1.0, acc:1.0, dataset:'Synthetic beacon flows with 60s interval, 5% jitter', split:'Threshold-based (cv<0.1)', features:['periodicity_score','dominant_period','inter_arrival_cv','jitter'], caught:64, desc:'FFT extracts dominant periodicities, CV measures timing consistency.' },
  { name:'Recon', detector:'Rule-based Fan-out', type:'Statistical', auc:1.0, testAuc:1.0, acc:1.0, dataset:'Port scan patterns: 200-2000 unique ports', split:'Threshold-based (ports>20 or hosts>15)', features:['unique_dst_ports','unique_dst_hosts','syn_ack_ratio'], caught:134, desc:'Fan-out analysis flags sources scanning > 20 ports or > 15 hosts.' },
];
