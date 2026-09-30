"""Assess panel freeform paths + pre-test candidate replacement strings."""
import sys, os
from pptx import Presentation
from pptx.util import Emu

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wrapmeasure import wrapped_lines, text_width

A = "http://schemas.openxmlformats.org/drawingml/2006/main"
EMU_PT = 12700.0
DECK = r"C:\Users\shaik\Downloads\THREX_SIH26145_work.pptx"
prs = Presentation(DECK)
slide = prs.slides[3]

print("### freeform path command audit (panel groups 26 / 32)")
for sh in slide.shapes:
    if sh.shape_type != 6 or sh.shape_id not in (26, 32):
        continue
    for c in sh.shapes:
        path = c._element.find(f".//{{{A}}}path")
        cmds = list(path) if path is not None else []
        kinds = {}
        for cmd in cmds:
            tag = cmd.tag.split('}')[-1]
            kinds[tag] = kinds.get(tag, 0) + 1
        print(f"  group {sh.shape_id} child {c.shape_id}: cmds={len(cmds)} {kinds}")
        # bounding of path in path space
        for cmd in cmds:
            pts = [(k, v) for k, v in cmd.attrib.items()]
            print(f"      {cmd.tag.split('}')[-1]} {pts}")

print()
print("### candidate wraps: obj 37 row (d)  @11pt, box w=198.65pt (bold '(d) ' prefix)")
full = "Measured 13,394/s, 1 core \u2014 120k/s target, unproven"
print("  current width:", round(text_width("(d) ", 11, True) + text_width(full, 11), 1))
for cand in [
    "Measured 13,394/s, 1 core \u2014 120k/s target, unproven",
    "Measured 13,394/s, 1 core \u2014 120k/s is a target",
    "Measured 13,394/s, 1 core",
    "13,394 flows/s, 1 core",
]:
    tw = text_width("(d) ", 11, True) + text_width(cand, 11, False)
    print(f"  w={tw:6.1f}  lines@198.65={len(wrapped_lines('(d) '+cand, 11, 198.65))}"
          f"  lines@300={len(wrapped_lines('(d) '+cand, 11, 300))}  | {cand}")

print()
print("### candidate wraps: obj 25 P1 (3-bug list) @8pt, box w=449.05pt")
cur25 = ("Three correctness bugs, all fixed: alerts not reliably persisted under load "
         "(single WAL connection, batched writes, 20k alerts/sec+); live capture "
         "re-enqueued every active flow on every packet (now FIN/RST or timeout); "
         "DNS-over-UDP never parsed, so PCAP uploads could not trigger DGA or DNS-tunnel "
         "\u2014 JA3 was a placeholder, now computed.")
print("  CURRENT lines:", len(wrapped_lines(cur25, 8, 449.05)), "chars:", len(cur25))
cands25 = {
 "v1": ("Three real correctness bugs, all fixed during hardening: alerts not reliably "
        "persisted under load (fixed: single WAL connection, batched writes, 20k alerts/sec+); "
        "live capture re-enqueued every active flow on every packet (fixed: NetFlow-style export "
        "on FIN/RST or timeout); DNS-over-UDP was never parsed by the original capture path, "
        "so PCAP uploads could never trigger DGA or DNS-tunnel detection \u2014 JA3 was a "
        "placeholder, now computed."),
 "v2": ("Three real correctness bugs, all fixed during hardening: alerts not reliably persisted "
        "under load (fixed: one WAL connection, batched writes, 20k alerts/sec+); live capture "
        "re-enqueued every active flow on every packet (fixed: NetFlow-style export on FIN/RST or "
        "timeout); DNS-over-UDP was never parsed by the capture path, so PCAP uploads could never "
        "trigger DGA or DNS-tunnel detection \u2014 JA3 was a placeholder, now computed."),
 "v3": ("Three real correctness bugs, all fixed: alerts not reliably persisted under load "
        "(fixed: single WAL connection, batched writes, 20k alerts/sec+); live capture re-enqueued "
        "every active flow on every packet (fixed: NetFlow-style export on FIN/RST or timeout); "
        "DNS-over-UDP was never parsed, so PCAP uploads could never trigger DGA or DNS-tunnel "
        "detection \u2014 JA3 was a placeholder, now computed."),
}
for k, v in cands25.items():
    print(f"  {k}: lines={len(wrapped_lines(v, 8, 449.05))} chars={len(v)}")

print()
print("### candidate wraps: obj 31 (feasibility body) @9/8.5pt, box w=289.50pt")
p0 = ("Prototype deployed: live SOC dashboard, WebSocket feed, report generator. "
      "Software-only on commodity servers; modular detectors.")
p1 = ("Detection 2,800 \u2192 13,394 flows/sec on one core (~7\u00d7; batched LightGBM, "
      "incremental fan-out, bounded state). Regression gate: identical to baseline on every class.")
p2 = ("Multi-core pipeline built (receiver \u2192 N workers \u2192 dst aggregators). "
      "120,000 flows/sec is a target, hardware validation in progress \u2014 not measured.")
print("  P0 current lines:", len(wrapped_lines(p0, 9.0, 289.5)))
p1b = ("Detection 2,800 \u2192 13,394 flows/sec on one core (~7\u00d7, exactness-preserving; "
       "batched LightGBM, incremental fan-out, bounded state). Regression gate: identical to "
       "baseline on every class.")
print("  P1 current lines:", len(wrapped_lines(p1, 8.5, 289.5)), "chars:", len(p1))
print("  P1 +exactness lines:", len(wrapped_lines(p1b, 8.5, 289.5)), "chars:", len(p1b))
print("  P2 current lines:", len(wrapped_lines(p2, 8.5, 289.5)), "chars:", len(p2))
p2b = ("Multi-core pipeline built for horizontal scale-out (receiver/splitter \u2192 N detection "
       "workers \u2192 destination aggregators). 120,000 flows/sec is a target, hardware validation "
       "in progress \u2014 not measured.")
print("  P2 richer lines:", len(wrapped_lines(p2b, 8.5, 289.5)), "chars:", len(p2b))
