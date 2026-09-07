import type { ThreatAlert, ThreatClass, Severity, ThreatStatus } from "../types";
import type { SearchResult } from "./api";

const THREAT_CLASSES: ThreatClass[] = [
  "DDoS", "C2 Beaconing", "DGA / DNS Tunneling", "TLS/Malware", "Reconnaissance", "Exfiltration",
];

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const STATUSES: ThreatStatus[] = ["new", "investigating", "acknowledged", "resolved", "false_positive"];

export class SearchIndex {
  private alerts: ThreatAlert[] = [];
  private domains: Map<string, string> = new Map();
  private ips: Map<string, Set<string>> = new Map();
  private fingerprints: Map<string, string> = new Map();

  build(alerts: ThreatAlert[]) {
    this.alerts = alerts;
    this.domains.clear();
    this.ips.clear();
    this.fingerprints.clear();

    for (const alert of alerts) {
      this.ips.get(alert.sourceIp)?.add(alert.id) || this.ips.set(alert.sourceIp, new Set([alert.id]));
      this.ips.get(alert.destinationIp)?.add(alert.id) || this.ips.set(alert.destinationIp, new Set([alert.id]));

      if (alert.metadata.dnsInfo?.domain) {
        this.domains.set(alert.metadata.dnsInfo.domain, alert.id);
      }
      if (alert.metadata.tlsInfo?.ja3) {
        this.fingerprints.set(alert.metadata.tlsInfo.ja3, alert.id);
      }
      if (alert.metadata.tlsInfo?.ja4) {
        this.fingerprints.set(alert.metadata.tlsInfo.ja4, alert.id);
      }
    }
  }

  search(query: string): SearchResult[] {
    if (!query.trim()) return [];
    const q = query.toLowerCase().trim();
    const results: SearchResult[] = [];
    const seen = new Set<string>();

    // Search by threat ID (THR-XXXX)
    const thrMatch = q.match(/^thr[-\s]?(\d+)$/i);
    if (thrMatch) {
      const alert = this.alerts.find(a => a.id.includes(thrMatch[1]) || a.id.endsWith(thrMatch[1]));
      if (alert && !seen.has(alert.id)) {
        seen.add(alert.id);
        results.push({
          type: "threat",
          id: alert.id,
          title: `Threat ${alert.id}`,
          subtitle: `${alert.threatClass} — ${alert.severity.toUpperCase()} — ${(alert.confidence * 100).toFixed(0)}%`,
          href: `/threats/${alert.id}`,
          relevance: 100,
        });
      }
    }

    // Search by IP
    if (this.ips.has(q)) {
      const alertIds = this.ips.get(q)!;
      for (const id of alertIds) {
        if (!seen.has(id)) {
          seen.add(id);
          const alert = this.alerts.find(a => a.id === id);
          if (alert) {
            results.push({
              type: "ip",
              id: alert.id,
              title: q,
              subtitle: `${alert.threatClass} — ${alert.sourceIp} → ${alert.destinationIp}`,
              href: `/threats/${alert.id}`,
              relevance: 90,
            });
          }
        }
      }
    }

    // Search by domain
    if (this.domains.has(q)) {
      const alertId = this.domains.get(q)!;
      if (!seen.has(alertId)) {
        seen.add(alertId);
        const alert = this.alerts.find(a => a.id === alertId);
        if (alert) {
          results.push({
            type: "domain",
            id: alert.id,
            title: q,
            subtitle: `${alert.threatClass} — ${alert.sourceIp}`,
            href: `/threats/${alert.id}`,
            relevance: 85,
          });
        }
      }
    }

    // Search by fingerprint (JA3/JA4)
    if (this.fingerprints.has(q)) {
      const alertId = this.fingerprints.get(q)!;
      if (!seen.has(alertId)) {
        seen.add(alertId);
        const alert = this.alerts.find(a => a.id === alertId);
        if (alert) {
          results.push({
            type: "fingerprint",
            id: alert.id,
            title: q.substring(0, 40) + (q.length > 40 ? "..." : ""),
            subtitle: `${alert.threatClass} — ${alert.sourceIp} → ${alert.destinationIp}`,
            href: `/threats/${alert.id}`,
            relevance: 80,
          });
        }
      }
    }

    // Search by threat class
    for (const tc of THREAT_CLASSES) {
      if (tc.toLowerCase().includes(q)) {
        const matchingAlerts = this.alerts.filter(a => a.threatClass === tc && !seen.has(a.id)).slice(0, 3);
        for (const alert of matchingAlerts) {
          seen.add(alert.id);
          results.push({
            type: "threat",
            id: alert.id,
            title: alert.threatClass,
            subtitle: `${alert.sourceIp} → ${alert.destinationIp} — ${(alert.confidence * 100).toFixed(0)}% confidence`,
            href: `/threats/${alert.id}`,
            relevance: 70,
          });
        }
      }
    }

    // Search by severity
    for (const sev of SEVERITIES) {
      if (sev.includes(q)) {
        const matchingAlerts = this.alerts.filter(a => a.severity === sev && !seen.has(a.id)).slice(0, 2);
        for (const alert of matchingAlerts) {
          seen.add(alert.id);
          results.push({
            type: "threat",
            id: alert.id,
            title: `${sev.toUpperCase()} severity`,
            subtitle: `${alert.threatClass} — ${alert.sourceIp} → ${alert.destinationIp}`,
            href: `/threats/${alert.id}`,
            relevance: 60,
          });
        }
      }
    }

    // Search by status
    for (const status of STATUSES) {
      if (status.includes(q) || status.replace("_", " ").includes(q)) {
        const matchingAlerts = this.alerts.filter(a => a.status === status && !seen.has(a.id)).slice(0, 2);
        for (const alert of matchingAlerts) {
          seen.add(alert.id);
          results.push({
            type: "threat",
            id: alert.id,
            title: `Status: ${status.replace("_", " ")}`,
            subtitle: `${alert.threatClass} — ${alert.sourceIp} → ${alert.destinationIp}`,
            href: `/threats/${alert.id}`,
            relevance: 55,
          });
        }
      }
    }

    // Generic text search across all fields
    if (results.length < 5) {
      for (const alert of this.alerts) {
        if (seen.has(alert.id)) continue;
        const searchable = [
          alert.id, alert.sourceIp, alert.destinationIp, alert.threatClass,
          alert.severity, alert.status, alert.protocol,
          alert.metadata.flowId, alert.metadata.dnsInfo?.domain,
          alert.metadata.tlsInfo?.ja3, alert.metadata.tlsInfo?.ja4,
          alert.metadata.tlsInfo?.sni,
        ].filter(Boolean).join(" ").toLowerCase();

        if (searchable.includes(q)) {
          seen.add(alert.id);
          results.push({
            type: "alert",
            id: alert.id,
            title: `${alert.threatClass} — ${alert.id}`,
            subtitle: `${alert.sourceIp} → ${alert.destinationIp} — ${(alert.confidence * 100).toFixed(0)}%`,
            href: `/threats/${alert.id}`,
            relevance: 50,
          });
          if (results.length >= 20) break;
        }
      }
    }

    return results.sort((a, b) => b.relevance - a.relevance).slice(0, 15);
  }
}

export const searchIndex = new SearchIndex();
