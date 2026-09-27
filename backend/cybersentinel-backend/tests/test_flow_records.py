"""NetFlow v5 / v9 / IPFIX codec tests (app/ingest/flow_records.py)."""
import socket
import struct
import time

from app.ingest.flow_records import (FlowRecordDecoder, IPFIXEncoder, encode_netflow_v5,
                                     flags_to_names, names_to_flags)

BASE = dict(src_ip="10.0.0.5", dst_ip="203.0.113.9", src_port=51000, dst_port=443, protocol="tcp",
            packet_count=12, bytes_transferred=3400, start_time=1_790_000_000.25,
            end_time=1_790_000_004.75, duration_seconds=4.5, flags=["SYN", "ACK", "FIN"])


def test_ipfix_roundtrip_all_threx_fields():
    rec = dict(BASE, dns_query="a1b2c3.example.com", dns_qtype=16, ja3="e7d705a3286e19ea42f587b344ee6865",
               timestamps=[1_790_000_000.25, 1_790_000_001.0, 1_790_000_004.75],
               packet_sizes=[517, 1400, 90], dst_ports=[22, 80, 443],
               raw_features={"ciphers_count": 3, "extensions_count": 2, "curves_count": 1,
                             "point_formats_count": 1, "unique_dst_ports": 900, "unique_dst_hosts": 40})
    dec = FlowRecordDecoder()
    [out] = [r for m in IPFIXEncoder().encode([rec]) for r in dec.decode(m, "exp")]
    for k in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packet_count",
              "bytes_transferred", "dns_query", "dns_qtype", "ja3", "packet_sizes", "dst_ports"):
        assert out[k] == rec[k], k
    assert abs(out["start_time"] - rec["start_time"]) < 1e-3 and abs(out["end_time"] - rec["end_time"]) < 1e-3
    assert [round(t, 3) for t in out["timestamps"]] == [round(t, 3) for t in rec["timestamps"]]
    assert set(out["flags"]) == {"SYN", "ACK", "FIN"}
    for k, v in rec["raw_features"].items():
        assert out["raw_features"][k] == v, k


def test_ipfix_sequence_gap_is_counted():
    enc, dec = IPFIXEncoder(template_every=1), FlowRecordDecoder()
    msgs = [m for i in range(5) for m in enc.encode([dict(BASE, src_port=1000 + i)] * 3)]
    for i, m in enumerate(msgs):
        if i != 2:                       # drop one datagram (3 records) in transit
            dec.decode(m, "exp")
    assert dec.stats["records"] == 12 and dec.stats["seq_gap_records"] == 3


def test_data_before_template_is_reported_not_crashed():
    enc = IPFIXEncoder(template_every=1000)
    first, second = enc.encode([BASE]), enc.encode([BASE])
    dec = FlowRecordDecoder()
    assert dec.decode(second[0], "exp") == [] and dec.stats["unknown_template_sets"] == 1
    assert len(dec.decode(first[0], "exp")) == 1


def test_netflow_v5():
    boot = BASE["start_time"] - 100.0
    recs = FlowRecordDecoder().decode(encode_netflow_v5([BASE, dict(BASE, protocol="udp", dst_port=53)], boot), "r")
    assert [r["protocol"] for r in recs] == ["tcp", "udp"]
    assert recs[0]["packet_count"] == 12 and recs[0]["bytes_transferred"] == 3400
    assert abs(recs[0]["duration_seconds"] - 4.5) < 0.01


def test_netflow_v9_template_and_data():
    # template 300: src v4, dst v4, sport, dport, proto, pkts(4), bytes(4), first, last
    fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (2, 4), (1, 4), (22, 4), (21, 4)]
    tpl = struct.pack(">HH", 300, len(fields)) + b"".join(struct.pack(">HH", *f) for f in fields)
    tset = struct.pack(">HH", 0, 4 + len(tpl)) + tpl
    row = struct.pack(">4s4sHHBIIII", socket.inet_aton("10.1.1.1"), socket.inet_aton("10.2.2.2"),
                      40000, 22, 6, 7, 900, 5_000, 9_000)
    dset = struct.pack(">HH", 300, 4 + len(row) + 3) + row + b"\0\0\0"   # padded
    now = int(time.time())
    pkt = struct.pack(">HHIIII", 9, 2, 60_000, now, 1, 42) + tset + dset
    [r] = FlowRecordDecoder().decode(pkt, "r")
    assert (r["src_ip"], r["dst_ip"], r["dst_port"], r["packet_count"]) == ("10.1.1.1", "10.2.2.2", 22, 7)
    assert abs(r["duration_seconds"] - 4.0) < 1e-6


def test_garbage_is_counted_as_malformed():
    dec = FlowRecordDecoder()
    for junk in (b"", b"\x00", b"\x00\x0a\x00", b"\xff" * 40):
        assert dec.decode(junk, "x") == []
    assert dec.stats["malformed"] == 4


def test_flag_mapping():
    assert set(flags_to_names(names_to_flags(["SYN", "ACK"]))) == {"SYN", "ACK"}
    assert names_to_flags("R") == 0x04
