import { useEffect, useRef, useCallback } from "react";
import type { ThreatAlert } from "../types";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
function wsBase(): string {
  try {
    const u = new URL(API_BASE);
    return `${u.protocol === "https:" ? "wss:" : "ws:"}//${u.host}`;
  } catch {
    return API_BASE.replace(/^http/, "ws");
  }
}

export function useAlertWebSocket(onAlert: (a: ThreatAlert) => void, enabled: boolean) {
  const wsRef = useRef<WebSocket | null>(null);
  useEffect(() => {
    if (!enabled) return;
    const url = `${wsBase()}/ws/alerts`;
    let ws: WebSocket | null = null;
    let closed = false;
    function connect() {
      ws = new WebSocket(url);
      wsRef.current = ws;
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data);
          if (msg.type === "alert" && msg.data) {
            const raw = msg.data;
            // raw is backend Alert JSON; map similarly to apiClient
            const mapped: ThreatAlert = {
              id: raw.alert_id,
              timestamp: new Date(raw.timestamp),
              threatClass: (() => {
                const m: Record<string, any> = { ddos: "DDoS", c2_beacon: "C2 Beaconing", dga: "DGA / DNS Tunneling", dns_tunnel: "DGA / DNS Tunneling", tls_malware: "TLS/Malware", port_scan: "Reconnaissance", exfiltration: "Exfiltration" };
                return m[raw.threat_class] || "DDoS";
              })(),
              sourceIp: raw.source_ip,
              destinationIp: raw.destination_ip,
              destinationPort: raw.destination_port,
              protocol: raw.protocol,
              severity: raw.severity,
              confidence: raw.confidence,
              status: "new",
              flowFingerprint: [],
              metadata: {
                flowId: raw.flow_id || "",
                startTime: new Date(raw.timestamp),
                duration: raw.duration_seconds || 0,
                packets: raw.packet_count || 0,
                bytes: raw.bytes_transferred || 0,
                packetsPerSecond: (raw.packet_count || 0) / Math.max(raw.duration_seconds || 1, 1),
                bitsPerSecond: ((raw.bytes_transferred || 0) * 8) / Math.max(raw.duration_seconds || 1, 1),
                sourcePort: raw.source_port || 0,
                destinationPort: raw.destination_port || 0,
                direction: "inbound",
              } as any,
              evidence: (raw.evidence || []).map((e: any) => ({
                name: e.feature_name || e.name || "unknown",
                value: e.value || 0,
                maxValue: 1.0,
                description: e.description || "",
                weight: e.contribution || e.weight || 0,
              })),
            };
            onAlert(mapped);
          }
        } catch {}
      };
      ws.onclose = () => {
        if (!closed) setTimeout(connect, 3000);
      };
      ws.onerror = () => {
        try { ws?.close(); } catch {}
      };
    }
    connect();
    return () => {
      closed = true;
      try { ws?.close(); } catch {}
      wsRef.current = null;
    };
  }, [enabled, onAlert]);
}

export function useMetricsWebSocket(onMetrics: (m: any) => void, enabled: boolean) {
  const wsRef = useRef<WebSocket | null>(null);
  useEffect(() => {
    if (!enabled) return;
    const url = `${wsBase()}/ws/metrics`;
    let ws: WebSocket | null = null;
    let closed = false;
    function connect() {
      ws = new WebSocket(url);
      wsRef.current = ws;
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data);
          if (msg.type === "metrics") onMetrics(msg);
        } catch {}
      };
      ws.onclose = () => { if (!closed) setTimeout(connect, 3000); };
      ws.onerror = () => { try { ws?.close(); } catch {} };
    }
    connect();
    return () => { closed = true; try { ws?.close(); } catch {} };
  }, [enabled, onMetrics]);
}
