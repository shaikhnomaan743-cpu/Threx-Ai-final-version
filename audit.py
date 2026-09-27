from pptx import Presentation
DECK = r"C:\Users\shaik\Downloads\THREX_SIH26145_work.pptx"
prs = Presentation(DECK)
slide_text = []
def walk(shapes, buf):
    for sh in shapes:
        if sh.shape_type == 6: walk(sh.shapes, buf); continue
        if sh.has_text_frame: buf.append(sh.text_frame.text)
        if sh.has_table:
            for r in sh.table.rows: buf.append(" ".join(c.text for c in r.cells))
for s in prs.slides:
    b=[]; walk(s.shapes,b); slide_text.append("\n".join(b))
ALL = "\n".join(slide_text)
low = ALL.lower()
reqs = [
 ("R1a 3 real bugs framed", all(k in low for k in ["three correctness bugs", "all fixed"])),
 ("R1a alert persistence+WAL+20k", all(k in low for k in ["alerts not reliably persisted", "wal", "batched writes", "20k alerts/sec"])),
 ("R1a live re-enqueue bug", all(k in low for k in ["re-enqueued every active flow on every packet", "fin/rst"])),
 ("R1a 'NetFlow-style export' wording", "netflow-style export" in low),
 ("R1a DNS-over-UDP bug", all(k in low for k in ["dns-over-udp never parsed", "pcap uploads could not trigger dga", "ja3 was a placeholder"])),
 ("R1b 7x / 2800 -> 13394", all(k in low for k in ["~7\u00d7", "2,800", "13,394 "])),
 ("R1b batched LGBM/fan-out/bounded", all(k in low for k in ["batched lightgbm", "incremental fan-out", "bounded state"])),
 ("R1b regression gate = baseline all classes", all(k in low for k in ["regression gate", "identical to baseline on every class"])),
 ("R1c multicore receiver/workers/aggregators", all(k in low for k in ["receiver", "workers", "aggregators"])),
 ("R1c C2 sharding regression 0%", all(k in low for k in ["source-ip sharding", "c2", "0%", "destination"])),
 ("R1d 120k labelled target/unproven", ("120,000 flows/sec is a target" in low) and ("120k/s target, unproven" in low)),
 ("R1e NO 1,978.6/162.7", ("1,978.6" not in ALL) and ("162.7" not in ALL)),
 ("R2 NetFlow v5/v9/IPFIX ingest", "netflow v5/v9/ipfix" in low),
 ("R2 replay == live same schema", any(k in low for k in ["replay \u2261 live", "matching lab json", "lab json schema"])),
 ("R2 dep-free PCAP 5300->270000 ~50x", all(k in low for k in ["270,000", "5,300", "50\u00d7", "dep-free pcap"])),
 ("R3a JA4/QUIC roadmap only", ("ja4 fingerprints, quic" in low) and ("roadmap only" in low)),
 ("R3a NO JA4/QUIC 'implemented'", not any(k in low for k in ["ja4 implemented", "quic support", "supports quic", "ja4 support"])),
 ("R3b static labels disclosed", "static, not live checks" in low),
 ("R3c DDoS/exfil/TLS synthetic qualified", "ddos, exfiltration and tls-malware models are trained on synthetic data" in low),
 ("R4 tone: risk/weakness boxes exist", all(k in low for k in ["risk 2. c2 beacon precision is 0.30", "weaknesses we found ourselves"])),
]
print("DECK:", DECK, "| slides:", len(prs.slides))
for name, ok in reqs:
    print(("PASS  " if ok else "*FAIL*"), name, "" if ok else "")
print()
print("total PASS:", sum(1 for _,o in reqs if o), "/", len(reqs))
