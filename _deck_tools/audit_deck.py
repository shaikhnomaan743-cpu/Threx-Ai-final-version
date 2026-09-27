"""Compliance audit of the SIH26145 deck against the requested update spec.

Every requirement (and every explicit prohibition) from the engineering-progress
brief is checked against the deck's real text. Run after any edit.
"""
import sys

from pptx import Presentation

DECK = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\shaik\Downloads\THREX_SIH26145_work.pptx"


def all_text(prs):
    per_slide = []
    for slide in prs.slides:
        buf = []

        def walk(shapes):
            for sh in shapes:
                if sh.shape_type == 6:
                    walk(sh.shapes)
                    continue
                if sh.has_text_frame:
                    buf.append(sh.text_frame.text)
                if sh.has_table:
                    for row in sh.table.rows:
                        buf.append(" ".join(c.text for c in row.cells))

        walk(slide.shapes)
        per_slide.append("\n".join(buf))
    return per_slide


prs = Presentation(DECK)
slides = all_text(prs)
ALL = "\n".join(slides)
low = ALL.lower()

CHECKS = [
    # --- requirement 1: Feasibility / hardening content
    ("R1  three real bugs, found + fixed", "three real correctness bugs" in low),
    ("R1  alert persistence bug + WAL fix", all(k in low for k in
        ["alerts not reliably persisted under load", "wal", "batched writes", "20k alerts/sec"])),
    ("R1  live-capture re-enqueue bug", "live capture re-enqueued every active flow on every packet" in low),
    ("R1  NetFlow-style export on FIN/RST", all(k in low for k in
        ["netflow-style export", "fin/rst"])),
    ("R1  DNS-over-UDP parse bug + JA3", all(k in low for k in
        ["dns-over-udp was never parsed", "pcap uploads could never trigger dga or dns-tunnel",
         "ja3 was a placeholder, now computed"])),
    ("R1  7x, 2,800 -> 13,394 flows/sec", all(k in low for k in ["~7\u00d7", "2,800", "13,394"])),
    ("R1  exactness-preserving optimisation", "exactness-preserving" in low),
    ("R1  batched LGBM / fan-out / bounded state", all(k in low for k in
        ["batched lightgbm", "incremental fan-out", "bounded state"])),
    ("R1  regression gate = baseline, all classes", all(k in low for k in
        ["regression gate", "identical to baseline on every class"])),
    ("R1  multi-core receiver/workers/aggregators", all(k in low for k in
        ["receiver/splitter", "n workers", "destination aggregators"])),
    ("R1  self-caught C2 sharding regression", all(k in low for k in
        ["source-ip sharding", "c2", "0%", "destination-side aggregation"])),
    ("R1  120k labelled target, not measured", all(k in low for k in
        ["120,000 flows/sec is a target", "120k/s target, unproven", "not measured"])),
    ("R1  no unbacked 1,978.6 / 162.7", ("1,978.6" not in ALL) and ("162.7" not in ALL)),
    # --- requirement 2: ingest / parser line
    ("R2  NetFlow v5/v9/IPFIX ingest", "netflow v5/v9/ipfix" in low),
    ("R2  replay == live same schema", any(k in low for k in
        ["replay \u2261 live", "matching lab json", "lab json schema"])),
    ("R2  dep-free PCAP ~50x (5,300 -> 270,000)", all(k in low for k in
        ["270,000", "5,300", "50\u00d7", "dep-free pcap"])),
    # --- requirement 3: prohibitions
    ("R3  JA4/QUIC roadmap-only (never built)", all(k in low for k in
        ["ja4 fingerprints, quic", "roadmap only"])),
    ("R3  no 'JA4/QUIC implemented' claim", not any(k in low for k in
        ["ja4 implemented", "ja4 support", "quic support", "supports quic"])),
    ("R3  static status labels disclosed", "static, not live checks" in low),
    ("R3  DDoS/exfil/TLS qualified as synthetic", all(k in low for k in
        ["ddos, exfiltration and tls-malware models are trained on synthetic data",
         "trained on synthetic data, not captured attacks"])),
    # --- requirement 4: honest tone
    ("R4  weaknesses + risk boxes retained", all(k in low for k in
        ["risk 2. c2 beacon precision is 0.30", "weaknesses we found ourselves"])),
]

print("DECK:", DECK)
print("slides:", len(prs.slides))
print()
fails = 0
for name, ok in CHECKS:
    if not ok:
        fails += 1
    print(("  PASS  " if ok else "  *FAIL*") + "  " + name)
print()
print(f"{len(CHECKS) - fails}/{len(CHECKS)} checks pass")
sys.exit(1 if fails else 0)
