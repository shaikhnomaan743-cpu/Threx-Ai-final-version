"""Precise word-wrap line-count measurement for PPTX paragraphs.

Uses the real Calibri TTF from C:\\Windows\\Fonts so that the number of rendered
lines can be predicted before/after an edit. Keeps the deck's layout safe:
an edit is only accepted when it does not add a rendered line.
"""
import sys
from PIL import ImageFont

FONTS = {
    False: r"C:\Windows\Fonts\calibri.ttf",   # regular
    True: r"C:\Windows\Fonts\calibrib.ttf",  # bold
}
_cache = {}


def _font(pt, bold=False):
    key = (round(pt * 4), bold)
    if key not in _cache:
        _cache[key] = ImageFont.truetype(FONTS[bold], int(round(pt * 4)))
    return _cache[key]


def text_width(text, pt, bold=False):
    """Width of text in points (font loaded at 4x for sub-point precision)."""
    return _font(pt, bold).getlength(text) / 4.0


def wrapped_lines(text, pt, width_pt, bold=False):
    """Greedy word wrap, same algorithm PowerPoint uses; returns list of lines."""
    lines, cur = [], ""
    for word in text.split(" "):
        trial = word if not cur else cur + " " + word
        if text_width(trial, pt, bold) <= width_pt or not cur:
            cur = trial
        else:
            lines.append(cur)
            cur = word
    if cur:
        lines.append(cur)
    return lines


def report(label, text, pt, width_pt, bold=False):
    lines = wrapped_lines(text, pt, width_pt, bold)
    print(f"{label}: chars={len(text):4d} lines={len(lines)} "
          f"(width {width_pt:.1f}pt @ {pt}pt)")
    for i, ln in enumerate(lines, 1):
        print(f"    L{i}: {text_width(ln, pt, bold):6.1f}pt | {ln}")
    return len(lines)


if __name__ == "__main__":
    print("self-test:", report("hello", "hello world " * 20, 8, 200))
