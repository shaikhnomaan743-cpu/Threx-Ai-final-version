from __future__ import annotations

from typing import Any, Optional

from app.alerts.schema import Evidence
from app.utils.entropy import shannon_entropy


class DnsTunnelDetector:
    """Statistical DNS-tunnel detector (passive metadata only).

    Signals from the problem statement: query-name entropy/n-grams,
    query length, and record-type anomalies (TXT), plus volume.
    """

    def detect(self, flow: Any) -> Optional[dict]:
        try:
            dst_port = getattr(flow, "dst_port", None)
            dns_query = (getattr(flow, "dns_query", "") or "").strip(".")
            qtype = int(getattr(flow, "dns_qtype", 0) or 0)
            raw = getattr(flow, "raw_features", {}) or {}
            if not isinstance(raw, dict):
                raw = {}

            is_dns = dst_port == 53 or bool(dns_query) or "subdomain_entropy" in raw or "txt_query_volume" in raw
            if not is_dns:
                return None

            labels = [p for p in dns_query.split(".") if p]
            longest_label = max((len(p) for p in labels), default=0)
            query_len = len(dns_query)

            first = labels[0] if labels else ""
            entropy = float(raw.get("subdomain_entropy") or 0.0)
            if entropy <= 0 and first:
                entropy = shannon_entropy(first.encode("utf-8"))

            pkt_count = int(getattr(flow, "packet_count", 0) or 0)
            dur = getattr(flow, "duration_seconds", 0.0)
            if callable(dur):
                try:
                    dur = float(dur())
                except Exception:
                    dur = 0.0
            dur = float(dur or 0.0)
            qps = float(raw.get("query_frequency") or (pkt_count / max(dur, 1.0)))
            bytes_xfer = int(getattr(flow, "bytes_transferred", 0) or 0)
            txt_volume = float(raw.get("txt_query_volume") or 0.0)
            is_txt = qtype == 16 or txt_volume > 0

            score = 0.0
            evidence: list[Evidence] = []

            if longest_label >= 24 or query_len >= 40:
                contrib = 0.3
                score += contrib
                evidence.append(Evidence(
                    feature_name="dns_query_length",
                    value=float(query_len),
                    contribution=contrib,
                    description=f"Long DNS name ({query_len} chars, longest label {longest_label})",
                ))
            if entropy >= 3.5:
                contrib = 0.3
                score += contrib
                evidence.append(Evidence(
                    feature_name="subdomain_entropy",
                    value=round(entropy, 3),
                    contribution=contrib,
                    description=f"High subdomain entropy {entropy:.3f} (tunnel-like encoding)",
                ))
            if is_txt:
                contrib = 0.2
                score += contrib
                evidence.append(Evidence(
                    feature_name="dns_qtype_txt",
                    value=float(qtype or 16),
                    contribution=contrib,
                    description="TXT record type / TXT volume (typical of iodine/dnscat2)",
                ))
            if qps >= 2.0 and dst_port == 53:
                contrib = 0.15
                score += contrib
                evidence.append(Evidence(
                    feature_name="query_frequency",
                    value=round(qps, 2),
                    contribution=contrib,
                    description=f"High DNS query rate {qps:.1f}/s",
                ))
            if bytes_xfer >= 40_000 and dst_port == 53:
                contrib = 0.15
                score += min(0.15, contrib)
                evidence.append(Evidence(
                    feature_name="dns_byte_volume",
                    value=float(bytes_xfer),
                    contribution=0.15,
                    description=f"Elevated DNS byte volume {bytes_xfer} B",
                ))

            if score < 0.5 or not evidence:
                return None

            return {
                "threat_class": "dns_tunnel",
                "severity": "high" if score >= 0.7 else "medium",
                "confidence": round(min(1.0, score), 4),
                "evidence": evidence[:6],
                "model_version": "stat_dns_tunnel_v1",
            }
        except Exception:
            return None
