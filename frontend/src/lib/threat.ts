import type { ThreatClass } from "../types";

export const THREAT_BADGE_VARIANT: Record<ThreatClass, "ddos" | "c2" | "dga" | "tls" | "recon" | "exfil"> = {
  DDoS: "ddos",
  "C2 Beaconing": "c2",
  "DGA / DNS Tunneling": "dga",
  "TLS/Malware": "tls",
  Reconnaissance: "recon",
  Exfiltration: "exfil",
};

export function threatBadgeVariant(threatClass: ThreatClass) {
  return THREAT_BADGE_VARIANT[threatClass];
}
