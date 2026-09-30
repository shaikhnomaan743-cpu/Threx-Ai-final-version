"""Apply the SIH26145 engineering-progress update to the existing deck, in place.

Design rules enforced here:
  * only slide 4 (Feasibility and Viability) is touched -- every other slide must
    stay byte-identical;
  * existing typography (Cambria headings / Calibri body, colours, sizes) is kept;
  * no existing sentence is deleted -- text is only extended, and every extended
    paragraph keeps its current rendered line count (verified with real Calibri
    metrics + PowerPoint COM bounds);
  * the two pre-existing text-overflow collisions on slide 4 are repaired
    geometrically (grow the Feasibility panel, push the lower-right block down,
    widen the constraints list so row (d) stops wrapping into row (e)).
"""
from __future__ import annotations

import os
import shutil
import sys

from pptx import Presentation
from pptx.util import Emu

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wrapmeasure import wrapped_lines

A = "http://schemas.openxmlformats.org/drawingml/2006/main"
EMU_PT = 12700.0

SRC = r"C:\Users\shaik\Downloads\THREX_SIH26145_work.pptx"
OUT = sys.argv[1] if len(sys.argv) > 1 else SRC
BACKUP = r"C:\Users\shaik\OneDrive\Desktop\threx-AI\_deck_tools\deck_backup_before_update.pptx"

# ---------------------------------------------------------------- new wording
P25_P1 = (
    "Three real correctness bugs, all fixed during hardening: alerts not reliably "
    "persisted under load (single WAL connection, batched writes, 20k alerts/sec+); "
    "live capture re-enqueued every active flow on every packet (fixed: NetFlow-style "
    "export on FIN/RST or timeout); DNS-over-UDP was never parsed, so PCAP uploads "
    "could never trigger DGA or DNS-tunnel \u2014 JA3 was a placeholder, now computed."
)
P31_P1 = (
    "Detection 2,800 \u2192 13,394 flows/sec on one core (~7\u00d7, exactness-preserving; "
    "batched LightGBM, incremental fan-out, bounded state). Regression gate: identical "
    "to baseline on every class."
)
P31_P2 = (
    "Multi-core pipeline built: receiver/splitter \u2192 N workers \u2192 destination "
    "aggregators. 120,000 flows/sec is a target, hardware validation in progress "
    "\u2014 not measured."
)

# ------------------------------------------------------------------ geometry
SHIFT_IDS = [32, 35, 36, 37, 38, 39, 40, 41, 42]   # lower-right block
PANEL26_ID = 26                                     # Feasibility panel group
GROW_PT = 26.41                                     # panel grows to hold its text
ROW37_W_PT = 300.0                                  # stops "(d)" wrapping into "(e)"



def shift_down(shapes, delta_emu):
    for sh in shapes:
        if sh.shape_id in SHIFT_IDS:
            sh.top = Emu(int(sh.top + delta_emu))
            print(f"  shifted id={sh.shape_id} -> top={sh.top/EMU_PT:.2f}pt")


def find(shapes, shape_id):
    for sh in shapes:
        if sh.shape_id == shape_id:
            return sh
    raise KeyError(shape_id)


def grow_panel(group, delta_emu):
    """Grow a panel group downward without stretching it.

    Path space is 1:1 with shape space here, so adding the same delta to the
    group ext, the group child-ext, each child ext and each child's path height
    extends the bottom edge while the corner chamfers stay bit-identical.
    """
    grpSpPr = group._element.grpSpPr
    xfrm = grpSpPr.find(f"{{{A}}}xfrm")
    ext = xfrm.find(f"{{{A}}}ext")
    chExt = xfrm.find(f"{{{A}}}chExt")
    old_ext = int(ext.get("cy"))
    old_chext = int(chExt.get("cy"))
    assert old_ext == old_chext, f"non-1:1 group scale ({old_ext} vs {old_chext})"
    ext.set("cy", str(old_ext + delta_emu))
    chExt.set("cy", str(old_chext + delta_emu))
    print(f"  panel id={group.shape_id}: ext.cy {old_ext} -> {old_ext + delta_emu}")
    for child in group.shapes:
        cx = child._element.spPr.find(f"{{{A}}}xfrm")
        cext = cx.find(f"{{{A}}}ext")
        c_ext = int(cext.get("cy"))
        cext.set("cy", str(c_ext + delta_emu))
        path = child._element.find(f".//{{{A}}}path")
        h_old = int(path.get("h"))
        path.set("h", str(h_old + delta_emu))
        moved = 0
        for cmd in path:
            pt = cmd.find(f"{{{A}}}pt")
            if pt is None:
                continue
            y = int(pt.get("y"))
            if y > h_old / 2.0:          # bottom half: corners + bottom edge
                pt.set("y", str(y + delta_emu))
                moved += 1
        print(f"     child id={child.shape_id}: ext.cy {c_ext} -> {c_ext + delta_emu}, "
              f"path.h {h_old} -> {h_old + delta_emu}, {moved} points extended")


def replace_run_text(shape, para_index, new_text, width_pt, size_pt, budget):
    """Replace a single-run paragraph's text, asserting the wrap budget holds."""
    p = shape.text_frame.paragraphs[para_index]
    assert len(p.runs) == 1, f"shape {shape.shape_id} P{para_index} has {len(p.runs)} runs"
    old = p.runs[0].text
    n_old = len(wrapped_lines(old, size_pt, width_pt))
    n_new = len(wrapped_lines(new_text, size_pt, width_pt))
    assert n_new <= budget, f"wrap budget blown: {n_old} -> {n_new} lines (max {budget})"
    p.runs[0].text = new_text
    print(f"  shape {shape.shape_id} P{para_index}: {n_old} -> {n_new} lines "
          f"({len(old)} -> {len(new_text)} chars, budget {budget})")


def main():
    prs = Presentation(SRC)
    shapes = prs.slides[3].shapes

    print("text updates")
    replace_run_text(find(shapes, 25), 1, P25_P1, 449.05, 8.0, 3)
    obj31 = find(shapes, 31)
    replace_run_text(obj31, 1, P31_P1, 289.50, 8.5, 3)
    replace_run_text(obj31, 2, P31_P2, 289.50, 8.5, 2)

    print("row (d) width fix")
    obj37 = find(shapes, 37)
    print(f"  shape 37 width {obj37.width/EMU_PT:.2f}pt -> {ROW37_W_PT}pt")
    obj37.width = Emu(int(ROW37_W_PT * EMU_PT))

    print("layout repair")
    grow_panel(find(shapes, PANEL26_ID), int(GROW_PT * EMU_PT))
    shift_down(shapes, int(GROW_PT * EMU_PT))

    if OUT != SRC:
        prs.save(OUT)
    else:
        shutil.copy2(SRC, BACKUP)
        print(f"  backup -> {BACKUP}")
        prs.save(SRC)
    print("saved ->", OUT)


if __name__ == "__main__":
    main()
