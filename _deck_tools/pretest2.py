"""Inspect panel path XML + find richest text variants within line budgets."""
import sys, os
from pptx import Presentation
from pptx.util import Emu
from lxml import etree

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wrapmeasure import wrapped_lines, text_width

A = "http://schemas.openxmlformats.org/drawingml/2006/main"
EMU_PT = 12700.0
DECK = r"C:\Users\shaik\Downloads\THREX_SIH26145_work.pptx"
prs = Presentation(DECK)
slide = prs.slides[3]

print("### obj 26 child 27 path XML (first 1200 chars)")
for sh in slide.shapes:
    if sh.shape_type == 6 and sh.shape_id == 26:
        for c in sh.shapes:
            if c.shape_id == 27:
                xml = etree.tostring(c._element, pretty_print=True).decode()
                i = xml.find("<a:path ")
                print(xml[i:i + 1400])
                break
        break

print()
print("### obj 25 P1 CURRENT wrapped lines (8pt, w=449.05)")
cur = ("Three correctness bugs, all fixed: alerts not reliably persisted under load (single WAL "
       "connection, batched writes, 20k alerts/sec+); live capture re-enqueued every active flow on "
       "every packet (now FIN/RST or timeout); DNS-over-UDP never parsed, so PCAP uploads could not "
       "trigger DGA or DNS-tunnel \u2014 JA3 was a placeholder, now computed.")
for i, ln in enumerate(wrapped_lines(cur, 8, 449.05), 1):
    print(f"  L{i} used {text_width(ln, 8):6.1f} / 449.05  slack {449.05 - text_width(ln, 8):6.1f}")

print()
print("### obj 25 P1 variants (must stay <= 3 lines)")
BUDGET = 3
variants = {
 "A minimal": ("Three correctness bugs, all fixed: alerts not reliably persisted under load (single WAL "
               "connection, batched writes, 20k alerts/sec+); live capture re-enqueued every active flow "
               "on every packet (NetFlow-style export on FIN/RST or timeout); DNS-over-UDP never parsed, "
               "so PCAP uploads could not trigger DGA or DNS-tunnel \u2014 JA3 was a placeholder, now computed."),
 "B real+hardening": ("Three real correctness bugs, all fixed during hardening: alerts not reliably persisted "
               "under load (single WAL connection, batched writes, 20k alerts/sec+); live capture re-enqueued "
               "every active flow on every packet (NetFlow-style export on FIN/RST or timeout); DNS-over-UDP "
               "never parsed, so PCAP uploads could not trigger DGA or DNS-tunnel \u2014 JA3 was a placeholder, "
               "now computed."),
 "C tightened": ("Three real correctness bugs, all fixed during hardening: alerts not reliably persisted under "
               "load (single WAL connection, batched writes, 20k alerts/sec+); live capture re-enqueued every "
               "active flow on every packet (fixed: NetFlow-style export on FIN/RST or timeout); DNS-over-UDP "
               "was never parsed, so PCAP uploads could never trigger DGA or DNS-tunnel \u2014 JA3 was a "
               "placeholder, now computed."),
}
for k, v in variants.items():
    n = len(wrapped_lines(v, 8, 449.05))
    flag = "OK " if n <= BUDGET else "OVER"
    print(f"  {flag} {k}: lines={n} chars={len(v)}")
    if n > BUDGET:
        for i, ln in enumerate(wrapped_lines(v, 8, 449.05), 1):
            print(f"        L{i} used {text_width(ln, 8):6.1f}")

print()
print("### obj 31 P2 variants (must stay <= 2 lines @8.5pt / 289.50)")
p2v = {
 "current": ("Multi-core pipeline built (receiver \u2192 N workers \u2192 dst aggregators). 120,000 flows/sec "
             "is a target, hardware validation in progress \u2014 not measured."),
 "splitter/destination": ("Multi-core pipeline built: receiver/splitter \u2192 N workers \u2192 destination "
             "aggregators. 120,000 flows/sec is a target, hardware validation in progress."),
 "splitter/dest+scale-out": ("Multi-core pipeline built for horizontal scale-out: receiver/splitter \u2192 N "
             "workers \u2192 destination aggregators. 120,000 flows/sec: target, hardware validation in progress."),
}
for k, v in p2v.items():
    n = len(wrapped_lines(v, 8.5, 289.5))
    print(f"  {'OK ' if n <= 2 else 'OVER'} {k}: lines={n} chars={len(v)}")
    if n > 2:
        for i, ln in enumerate(wrapped_lines(v, 8.5, 289.5), 1):
            print(f"        L{i} used {text_width(ln, 8.5):6.1f}")

print()
print("### obj 31 P1 + exactness-preserving (must stay <= 3 lines)")
p1 = ("Detection 2,800 \u2192 13,394 flows/sec on one core (~7\u00d7, exactness-preserving; batched LightGBM, "
      "incremental fan-out, bounded state). Regression gate: identical to baseline on every class.")
n = len(wrapped_lines(p1, 8.5, 289.5))
print(f"  {'OK ' if n <= 3 else 'OVER'} lines={n} chars={len(p1)}")
