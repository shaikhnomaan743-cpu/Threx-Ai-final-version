"""Receiver-side record splitting must be lossless and source-consistent."""
import json
import random
import sys
import time
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "scripts"))


def _pool(n_each=60):
    import generate_lab_traffic as G
    random.seed(3)
    pool = []
    for fn in (G.generate_benign_tcp, G.generate_dga_queries, G.generate_tls_malware,
               G.generate_port_scan, G.generate_dns_tunneling, G.generate_c2_beacon):
        pool += fn(n=n_each)
    return pool


def _canon(r):
    return json.dumps(r, sort_keys=True)


def test_ipfix_split_is_lossless_and_source_consistent():
    from app.ingest.flow_records import IPFIXEncoder, FlowRecordDecoder
    from app.ingest.parallel import RecordSplitter, shard_of
    msgs = IPFIXEncoder(mtu=1400, template_every=8).encode(_pool())
    d0 = FlowRecordDecoder()
    direct = [r for m in msgs for r in d0.decode(m, "e")]

    sp = RecordSplitter(4)
    decs = [FlowRecordDecoder() for _ in range(4)]
    got, owner = [], {}
    for m in msgs:
        bcast, parts = sp.split(m, "e")
        for b in bcast:
            for d in decs:
                assert d.decode(b, "e") == []        # templates only
        for w, part in parts:
            for r in decs[w].decode(part, "e"):
                got.append(r)
                assert owner.setdefault(r["src_ip"], w) == w          # stable shard
                assert w == shard_of(r["src_ip"], 4)                  # same routing everywhere
    assert Counter(map(_canon, got)) == Counter(map(_canon, direct))
    assert sp.stats["records"] == len(direct) and sp.stats["seq_gap_records"] == 0
    assert all(d.stats["seq_gap_records"] == 0 for d in decs)
    assert len(set(owner.values())) > 1                               # actually spread


def test_receiver_counts_exporter_side_loss():
    from app.ingest.flow_records import IPFIXEncoder
    from app.ingest.parallel import RecordSplitter
    msgs = IPFIXEncoder(mtu=1400, template_every=1).encode(_pool(30))
    sp = RecordSplitter(2)
    for i, m in enumerate(msgs):
        if i % 5 == 3:                        # drop every 5th datagram "on the wire"
            continue
        sp.split(m, "e")
    # every dropped datagram shows up as a sequence gap (except a trailing one)
    assert sp.stats["seq_gap_records"] > 0


def test_netflow_v5_split_is_lossless():
    from app.ingest.flow_records import encode_netflow_v5, FlowRecordDecoder
    from app.ingest.parallel import RecordSplitter
    boot = time.time() - 3600
    recs = [{"src_ip": f"10.0.{i % 7}.{i}", "dst_ip": "10.9.9.9", "src_port": 1000 + i, "dst_port": 80,
             "protocol": "tcp", "packet_count": 5, "bytes_transferred": 500,
             "start_time": boot + 10, "end_time": boot + 11, "flags": ["SYN"]} for i in range(30)]
    msg = encode_netflow_v5(recs, boot, seq=0)
    direct = FlowRecordDecoder().decode(msg, "e")
    sp = RecordSplitter(3)
    got = []
    for w, part in sp.split(msg, "e")[1]:
        got += FlowRecordDecoder().decode(part, "e")
    assert Counter(map(_canon, got)) == Counter(map(_canon, direct)) and len(got) == 30
