"""Fast PCAP parser: header fields match scapy; DNS over UDP and real JA3 are
extracted (the old scapy path missed both)."""
import hashlib
import struct

import pytest

scapy = pytest.importorskip("scapy.all")
from scapy.all import IP, IPv6, TCP, UDP, DNS, DNSQR, Ether, Dot1Q, Raw, wrpcap  # noqa: E402

from app.ingest.fast_pcap import iter_pcap, parse_client_hello  # noqa: E402


def client_hello(version=0x0303, ciphers=(0x0a0a, 0x1301, 0xc02f), exts=None):
    exts = exts or [(0x0a0a, b""), (0, b"\x00\x00"), (10, struct.pack(">HHH", 4, 0x1a1a, 29)),
                    (11, b"\x01\x00"), (13, b"\x00\x02\x04\x03")]
    body = struct.pack(">H", version) + b"\x11" * 32 + b"\x00"
    body += struct.pack(">H", 2 * len(ciphers)) + struct.pack(f">{len(ciphers)}H", *ciphers) + b"\x01\x00"
    ext_bytes = b"".join(struct.pack(">HH", t, len(d)) + d for t, d in exts)
    body += struct.pack(">H", len(ext_bytes)) + ext_bytes
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def test_ja3_matches_spec_and_drops_grease():
    ja3, counts = parse_client_hello(client_hello())
    # GREASE (0x0a0a, 0x1a1a) removed from ciphers, extensions and curves
    expected = "771,4865-49199,0-10-11-13,29,0"
    assert ja3 == hashlib.md5(expected.encode()).hexdigest()
    assert counts == (2, 4, 1, 1)


@pytest.fixture
def pcap(tmp_path):
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S"),
        Ether() / Dot1Q(vlan=7) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="FA"),
        Ether() / IP(src="10.0.0.3", dst="8.8.8.8") / UDP(sport=5555, dport=53) /
        DNS(rd=1, qd=DNSQR(qname="kq3v9zzx1.example.ru", qtype="TXT")),
        Ether() / IP(src="10.0.0.4", dst="203.0.113.5") / TCP(sport=4444, dport=443, flags="PA") / Raw(client_hello()),
        Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=9, dport=9),
    ]
    for i, p in enumerate(pkts):
        p.time = 1_790_000_000 + i * 0.5
    path = tmp_path / "t.pcap"
    wrpcap(str(path), pkts)
    return str(path), pkts


def test_headers_match_scapy(pcap):
    path, pkts = pcap
    got = list(iter_pcap(path))
    assert len(got) == len(pkts)
    for g, p in zip(got, pkts):
        l3 = p[IP] if p.haslayer(IP) else p[IPv6]
        assert (g.src_ip, g.dst_ip) == (l3.src, l3.dst)
        assert abs(g.timestamp - float(p.time)) < 1e-6 and g.packet_size == len(p)
    assert got[0].flags == "S" and got[1].flags == "FA" and got[1].dst_port == 80   # VLAN-tagged
    assert got[4].protocol == "udp" and got[4].src_ip == "2001:db8::1"


def test_dns_over_udp_and_ja3_extracted(pcap):
    path, _ = pcap
    got = list(iter_pcap(path))
    assert (got[2].dns_query, got[2].dns_qtype) == ("kq3v9zzx1.example.ru", 16)
    assert len(got[3].ja3) == 32 and got[3].tls_counts == (2, 4, 1, 1)


def test_pcapng(tmp_path, pcap):
    from scapy.all import wrpcapng
    _, pkts = pcap
    path = tmp_path / "t.pcapng"
    wrpcapng(str(path), pkts)
    got = list(iter_pcap(str(path)))
    assert [g.src_ip for g in got] == [(p[IP] if p.haslayer(IP) else p[IPv6]).src for p in pkts]
    assert got[2].dns_query == "kq3v9zzx1.example.ru"
