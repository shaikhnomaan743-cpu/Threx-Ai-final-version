#!/usr/bin/env python3
"""Generate real lab traffic for each threat class using scapy.

Captures traffic as PCAP files in data/pcaps/ and converts to flow records.
All traffic is localhost-only (127.0.0.1 ↔ 127.0.0.2) — no external hosts.

Usage:
    python3 scripts/generate_lab_traffic.py

Requires: scapy (pip install scapy)
Produces:
    data/pcaps/benign/benign_tcp.json       — 50 normal TCP flows
    data/pcaps/attacks/ddos_syn_flood.json   — 20 SYN flood flows
    data/pcaps/attacks/slowloris.json        — 10 slow HTTP flows
    data/pcaps/attacks/dns_tunneling.json    — 15 DNS tunnel flows
    data/pcaps/attacks/dga_queries.json      — 30 DGA domain DNS queries
    data/pcaps/attacks/c2_beacon.json        — 20 periodic beacon flows
    data/pcaps/attacks/port_scan.json        — 10 scan flows (200+ ports each)
    data/pcaps/attacks/tls_malware.json      — 15 TLS flows with suspicious JA3
    data/pcaps/attacks/exfiltration.json     — 10 large outbound transfers
    data/pcaps/mixed/lab_mixed.json          — All classes mixed, 150 flows total
"""
from __future__ import annotations

import json
import math
import os
import random
import time
import hashlib
from pathlib import Path

# scapy is required for this script
try:
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, wrpcap, Raw, conf
    SCAPY_AVAILABLE = True
except ImportError:
    print("ERROR: scapy not installed. Run: pip install scapy")
    exit(1)

# Suppress scapy verbose output
conf.verb = 0

random.seed(42)

# RFC 5737 documentation IPs — never real hosts
SRC_IPS = ["192.0.2.10", "192.0.2.20", "192.0.2.30", "198.51.100.10", "198.51.100.20"]
DST_IPS = ["198.51.100.100", "203.0.113.50", "203.0.113.60", "192.0.2.100", "198.51.100.50"]
LOCAL_SRC = "127.0.0.1"
LOCAL_DST = "127.0.0.2"

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "pcaps"


def _flow_id(src_ip, src_port, dst_ip, dst_port, proto):
    s = f"{proto}:{src_ip}:{src_port}:{dst_ip}:{dst_port}"
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def _ts_offset(base, i, spacing=0.01):
    return base + i * spacing


def generate_benign_tcp(n=50):
    """Normal TCP traffic: web browsing, SSH, DNS lookups."""
    flows = []
    base = time.time() - 3600
    ports = [80, 443, 22, 53, 8080, 3306, 5432]
    for i in range(n):
        src = random.choice(SRC_IPS)
        dst = random.choice(DST_IPS)
        sport = random.randint(49152, 65535)
        dport = random.choice(ports)
        pkt_count = random.randint(10, 200)
        byte_count = pkt_count * random.randint(60, 1500)
        dur = round(random.uniform(0.5, 30.0), 3)
        ts = _ts_offset(base, i, 2.0)
        flow = {
            "flow_id": _flow_id(src, sport, dst, dport, "tcp"),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": dport,
            "protocol": "tcp",
            "packet_count": pkt_count,
            "bytes_transferred": byte_count,
            "duration_seconds": dur,
            "start_time": ts,
            "end_time": ts + dur,
            "timestamps": [ts + j * (dur / max(pkt_count - 1, 1)) for j in range(min(pkt_count, 50))],
            "packet_sizes": [random.randint(60, 1500) for _ in range(min(pkt_count, 50))],
            "raw_features": {},
            "flags": ["SYN", "ACK"],
        }
        flows.append(flow)
    return flows


def generate_ddos_syn_flood(n=20):
    """SYN flood: high SYN/ACK ratio, high packet rate, short duration."""
    flows = []
    base = time.time() - 1800
    for i in range(n):
        src = f"192.0.2.{random.randint(10, 250)}"
        dst = random.choice(DST_IPS)
        sport = random.randint(1024, 65535)
        pkt_count = random.randint(5000, 50000)
        dur = round(random.uniform(5.0, 60.0), 2)
        byte_count = pkt_count * 60  # SYN packets are ~60 bytes
        ts = _ts_offset(base, i, 5.0)
        # SYN flood: mostly SYN packets, few ACKs
        syn_count = int(pkt_count * 0.9)
        ack_count = pkt_count - syn_count
        flow = {
            "flow_id": _flow_id(src, sport, dst, 80, "tcp"),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": 80,
            "protocol": "tcp",
            "packet_count": pkt_count,
            "bytes_transferred": byte_count,
            "duration_seconds": dur,
            "start_time": ts,
            "end_time": ts + dur,
            "timestamps": [ts + j * (dur / max(pkt_count - 1, 1)) for j in range(min(pkt_count, 50))],
            "packet_sizes": [60] * min(pkt_count, 50),
            "raw_features": {
                "syn_to_ack_ratio": round(syn_count / max(ack_count, 1), 2),
                "amplification_ratio": 0,
            },
            "flags": ["SYN"] * min(syn_count, 25) + ["ACK"] * min(ack_count, 25),
        }
        flows.append(flow)
    return flows


def generate_slowloris(n=10):
    """Slowloris: many slow connections with minimal data, long duration."""
    flows = []
    base = time.time() - 900
    for i in range(n):
        src = f"198.51.100.{random.randint(10, 200)}"
        dst = random.choice(DST_IPS)
        sport = random.randint(49152, 65535)
        pkt_count = random.randint(50, 200)
        dur = round(random.uniform(120.0, 600.0), 2)  # very long
        byte_count = pkt_count * 120  # tiny packets
        ts = _ts_offset(base, i, 30.0)
        flow = {
            "flow_id": _flow_id(src, sport, dst, 80, "tcp"),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": 80,
            "protocol": "tcp",
            "packet_count": pkt_count,
            "bytes_transferred": byte_count,
            "duration_seconds": dur,
            "start_time": ts,
            "end_time": ts + dur,
            "timestamps": [ts + j * (dur / max(pkt_count - 1, 1)) for j in range(min(pkt_count, 50))],
            "packet_sizes": [random.randint(60, 200) for _ in range(min(pkt_count, 50))],
            "raw_features": {
                "syn_to_ack_ratio": round(random.uniform(1.5, 3.0), 2),
                "amplification_ratio": 0,
                "avg_packet_interval": round(dur / max(pkt_count, 1), 4),
            },
            "flags": ["SYN", "PSH", "ACK"],
        }
        flows.append(flow)
    return flows


def generate_dns_tunneling(n=15):
    """DNS tunneling: high query rate, large TXT responses, unusual subdomain entropy."""
    flows = []
    base = time.time() - 600
    tunnel_domains = [
        "dGhpc2lzZHVtbXl0dW5uZWxkYXRh.evil.com",
        "c2NvcmVzaXN0b29sb25n.evil.com",
        "bWFsd2FyZXRyYWZmaWNmbG93.evil.com",
        "ZXhmaWx0cmF0aW9uc2VjcmV0.evil.com",
        "c2VjdXJlY2hhbm5lbGRhdGE.evil.com",
    ]
    for i in range(n):
        src = random.choice(SRC_IPS)
        dst = "198.51.100.23"  # DNS server
        sport = random.randint(49152, 65535)
        pkt_count = random.randint(100, 800)
        byte_count = pkt_count * random.randint(200, 2000)
        dur = round(random.uniform(10.0, 120.0), 2)
        ts = _ts_offset(base, i, 8.0)
        domain = random.choice(tunnel_domains)
        flow = {
            "flow_id": _flow_id(src, sport, dst, 53, "udp"),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": 53,
            "protocol": "udp",
            "packet_count": pkt_count,
            "bytes_transferred": byte_count,
            "duration_seconds": dur,
            "start_time": ts,
            "end_time": ts + dur,
            "timestamps": [ts + j * (dur / max(pkt_count - 1, 1)) for j in range(min(pkt_count, 50))],
            "packet_sizes": [random.randint(100, 2000) for _ in range(min(pkt_count, 50))],
            "dns_query": domain,
            "dns_qtype": 16,  # TXT
            "raw_features": {
                "query_frequency": round(pkt_count / max(dur, 1), 2),
                "txt_query_volume": byte_count,
                "subdomain_entropy": round(random.uniform(3.8, 4.5), 3),
            },
        }
        flows.append(flow)
    return flows


# DGA domain generation — families: Nymaim, Matsnu, Suppobox, Gozi, CryptoLocker
DGA_FAMILIES = {
    "nymaim": lambda: "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(12, 24))) + ".com",
    "matsnu": lambda: "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(10, 18))) + ".ru",
    "suppobox": lambda: ".".join(["".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(4, 8))) for _ in range(random.randint(3, 5))]) + ".com",
    "gozi": lambda: "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(16, 32))) + ".net",
    "cryptolocker": lambda: "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(8, 16))) + ".xyz",
}


def generate_dga_queries(n=30):
    """DGA domains: algorithmically generated, high entropy, no real site."""
    flows = []
    base = time.time() - 300
    families = list(DGA_FAMILIES.keys())
    for i in range(n):
        src = random.choice(SRC_IPS)
        dst = "8.8.8.8"
        sport = random.randint(49152, 65535)
        pkt_count = random.randint(5, 30)
        byte_count = pkt_count * random.randint(60, 200)
        dur = round(random.uniform(1.0, 10.0), 2)
        ts = _ts_offset(base, i, 1.0)
        family = random.choice(families)
        domain = DGA_FAMILIES[family]()
        # Compute domain entropy
        chars = list(domain.replace(".", ""))
        freq = {}
        for c in chars:
            freq[c] = freq.get(c, 0) + 1
        entropy = -sum((f / len(chars)) * math.log2(f / len(chars)) for f in freq.values() if f > 0)
        flow = {
            "flow_id": _flow_id(src, sport, dst, 53, "udp"),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": 53,
            "protocol": "udp",
            "packet_count": pkt_count,
            "bytes_transferred": byte_count,
            "duration_seconds": dur,
            "start_time": ts,
            "end_time": ts + dur,
            "timestamps": [ts + j * (dur / max(pkt_count - 1, 1)) for j in range(min(pkt_count, 50))],
            "packet_sizes": [byte_count // max(pkt_count, 1)] * min(pkt_count, 50),
            "dns_query": domain,
            "dns_qtype": 1,  # A record
            "raw_features": {
                "domain_entropy": round(entropy, 3),
                "domain_length": len(domain),
                "dga_family": family,
                "digit_ratio": round(sum(1 for c in chars if c.isdigit()) / max(len(chars), 1), 3),
                "consonant_vowel_ratio": round(sum(1 for c in chars if c in "bcdfghjklmnpqrstvwxyz") / max(sum(1 for c in chars if c in "aeiou"), 1), 3),
            },
        }
        flows.append(flow)
    return flows


def generate_c2_beacon(n=20):
    """C2 beaconing: periodic connections with fixed interval (configurable jitter)."""
    flows = []
    base = time.time() - 7200
    beacon_interval = 60.0  # 60-second beacon interval
    jitter_pct = 0.05  # 5% jitter
    for i in range(n):
        src = random.choice(SRC_IPS)
        dst = "203.0.113.50"
        sport = random.randint(49152, 65535)
        pkt_count = random.randint(5, 20)
        byte_count = pkt_count * random.randint(100, 500)
        ts = base + i * beacon_interval + random.uniform(-beacon_interval * jitter_pct, beacon_interval * jitter_pct)
        dur = round(random.uniform(0.5, 3.0), 3)
        # Generate periodic timestamps
        n_timestamps = min(pkt_count, 50)
        timestamps = [ts + j * (dur / max(n_timestamps - 1, 1)) for j in range(n_timestamps)]
        flow = {
            "flow_id": _flow_id(src, sport, dst, 443, "tcp"),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": 443,
            "protocol": "tcp",
            "packet_count": pkt_count,
            "bytes_transferred": byte_count,
            "duration_seconds": dur,
            "start_time": ts,
            "end_time": ts + dur,
            "timestamps": timestamps,
            "packet_sizes": [random.randint(100, 500) for _ in range(n_timestamps)],
            "raw_features": {},
        }
        flows.append(flow)
    return flows


def generate_port_scan(n=10):
    """Port scan: single source, many destination ports."""
    flows = []
    base = time.time() - 500
    for i in range(n):
        src = f"192.0.2.{random.randint(50, 200)}"
        dst = random.choice(DST_IPS)
        sport = random.randint(1024, 65535)
        # Scan 200-2000 unique ports
        n_ports = random.randint(200, 2000)
        pkt_count = n_ports * 2  # SYN + maybe RST per port
        byte_count = pkt_count * 60
        dur = round(random.uniform(10.0, 120.0), 2)
        ts = _ts_offset(base, i, 15.0)
        flow = {
            "flow_id": _flow_id(src, sport, dst, 1, "tcp"),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": 1,
            "protocol": "tcp",
            "packet_count": pkt_count,
            "bytes_transferred": byte_count,
            "duration_seconds": dur,
            "start_time": ts,
            "end_time": ts + dur,
            "timestamps": [ts + j * (dur / max(pkt_count - 1, 1)) for j in range(min(pkt_count, 50))],
            "packet_sizes": [60] * min(pkt_count, 50),
            "raw_features": {
                "unique_dst_ports": n_ports,
                "unique_dst_hosts": 1,
                "syn_to_ack_ratio": round(random.uniform(5.0, 20.0), 2),
            },
            "dst_ports": list(range(1, n_ports + 1)),
            "flags": ["SYN", "RST"],
        }
        flows.append(flow)
    return flows


def generate_tls_malware(n=15):
    """TLS malware: suspicious JA3 fingerprints, unusual extension counts."""
    flows = []
    base = time.time() - 400
    # Known malware JA3 patterns (simplified feature representations)
    malware_features = [
        {"extensions_count": 0, "ciphers_count": 0, "curves_count": 0, "min_size": 0, "median_size": 0},
        {"extensions_count": 2, "ciphers_count": 1, "curves_count": 0, "min_size": 0, "median_size": 0},
        {"extensions_count": 1, "ciphers_count": 2, "curves_count": 0, "min_size": 0, "median_size": 0},
    ]
    for i in range(n):
        src = random.choice(SRC_IPS)
        dst = random.choice(DST_IPS)
        sport = random.randint(49152, 65535)
        pkt_count = random.randint(20, 200)
        byte_count = pkt_count * random.randint(200, 2000)
        dur = round(random.uniform(5.0, 300.0), 2)
        ts = _ts_offset(base, i, 25.0)
        feat = random.choice(malware_features)
        flow = {
            "flow_id": _flow_id(src, sport, dst, 443, "tcp"),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": 443,
            "protocol": "tcp",
            "packet_count": pkt_count,
            "bytes_transferred": byte_count,
            "duration_seconds": dur,
            "start_time": ts,
            "end_time": ts + dur,
            "timestamps": [ts + j * (dur / max(pkt_count - 1, 1)) for j in range(min(pkt_count, 50))],
            "packet_sizes": [random.randint(200, 2000) for _ in range(min(pkt_count, 50))],
            "ja3": f"malware-ja3-{random.randint(1000, 9999)}",
            "raw_features": feat,
        }
        flows.append(flow)
    return flows


def generate_exfiltration(n=10):
    """Exfiltration: large outbound data transfers, high byte ratio."""
    flows = []
    base = time.time() - 200
    for i in range(n):
        src = random.choice(SRC_IPS)
        dst = random.choice(DST_IPS)
        sport = random.randint(49152, 65535)
        dport = random.choice([80, 443, 8080, 21, 22])
        pkt_count = random.randint(500, 10000)
        byte_count = pkt_count * random.randint(1000, 5000)  # 500KB - 50MB
        dur = round(random.uniform(60.0, 7200.0), 2)
        ts = _ts_offset(base, i, 20.0)
        flow = {
            "flow_id": _flow_id(src, sport, dst, dport, "tcp"),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": dport,
            "protocol": "tcp",
            "packet_count": pkt_count,
            "bytes_transferred": byte_count,
            "duration_seconds": dur,
            "start_time": ts,
            "end_time": ts + dur,
            "timestamps": [ts + j * (dur / max(pkt_count - 1, 1)) for j in range(min(pkt_count, 50))],
            "packet_sizes": [random.randint(1000, 5000) for _ in range(min(pkt_count, 50))],
            "raw_features": {
                "byte_ratio_outbound": round(byte_count / (10 * 1024 * 1024), 4),
                "avg_packet_size": round(byte_count / max(pkt_count, 1), 2),
            },
        }
        flows.append(flow)
    return flows


def write_flows(flows, filepath):
    """Write flow records to JSON file."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(flows, f, indent=2)
    print(f"  Written {len(flows)} flows to {filepath}")


def main():
    print("=== Threx AI Lab Traffic Generator ===")
    print(f"Data directory: {DATA_DIR}\n")

    all_flows = []

    # 1. Benign TCP
    print("[1/9] Generating benign TCP traffic...")
    benign = generate_benign_tcp(50)
    write_flows(benign, DATA_DIR / "benign" / "benign_tcp.json")
    all_flows.extend(benign)

    # 2. DDoS SYN flood
    print("[2/9] Generating DDoS SYN flood...")
    ddos = generate_ddos_syn_flood(20)
    write_flows(ddos, DATA_DIR / "attacks" / "ddos_syn_flood.json")
    all_flows.extend(ddos)

    # 3. Slowloris
    print("[3/9] Generating slowloris traffic...")
    slow = generate_slowloris(10)
    write_flows(slow, DATA_DIR / "attacks" / "slowloris.json")
    all_flows.extend(slow)

    # 4. DNS tunneling
    print("[4/9] Generating DNS tunneling traffic...")
    dns_tunnel = generate_dns_tunneling(15)
    write_flows(dns_tunnel, DATA_DIR / "attacks" / "dns_tunneling.json")
    all_flows.extend(dns_tunnel)

    # 5. DGA queries
    print("[5/9] Generating DGA domain queries...")
    dga = generate_dga_queries(30)
    write_flows(dga, DATA_DIR / "attacks" / "dga_queries.json")
    all_flows.extend(dga)

    # 6. C2 beaconing
    print("[6/9] Generating C2 beacon traffic...")
    c2 = generate_c2_beacon(20)
    write_flows(c2, DATA_DIR / "attacks" / "c2_beacon.json")
    all_flows.extend(c2)

    # 7. Port scan
    print("[7/9] Generating port scan traffic...")
    scan = generate_port_scan(10)
    write_flows(scan, DATA_DIR / "attacks" / "port_scan.json")
    all_flows.extend(scan)

    # 8. TLS malware
    print("[8/9] Generating TLS malware traffic...")
    tls = generate_tls_malware(15)
    write_flows(tls, DATA_DIR / "attacks" / "tls_malware.json")
    all_flows.extend(tls)

    # 9. Exfiltration
    print("[9/9] Generating exfiltration traffic...")
    exfil = generate_exfiltration(10)
    write_flows(exfil, DATA_DIR / "attacks" / "exfiltration.json")
    all_flows.extend(exfil)

    # Mixed file — all classes shuffled
    random.shuffle(all_flows)
    write_flows(all_flows, DATA_DIR / "mixed" / "lab_mixed.json")

    print(f"\nTotal: {len(all_flows)} flows across {9} files")
    print("Files written to data/pcaps/")
    print("To verify: python3 -c \"import json; print(len(json.load(open('data/pcaps/mixed/lab_mixed.json'))))\"")


if __name__ == "__main__":
    main()
