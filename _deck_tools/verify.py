"""Verify the edit: which package parts changed, and which slides render identically."""
import os
import zipfile

from PIL import Image, ImageChops

HERE = os.path.dirname(os.path.abspath(__file__))
BEFORE = r"C:\Users\shaik\Downloads\THREX_SIH26145_work.pptx"
AFTER = os.path.join(HERE, "test_out.pptx")
RB = os.path.join(HERE, "render_before")
RA = os.path.join(HERE, "render_after")

print("### package part comparison (decompressed bytes)")
zb, za = zipfile.ZipFile(BEFORE), zipfile.ZipFile(AFTER)
nb, na = set(zb.namelist()), set(za.namelist())
print("  parts before/after:", len(nb), "/", len(na))
print("  added:", sorted(na - nb) or "none")
print("  removed:", sorted(nb - na) or "none")
changed = []
for n in sorted(nb & na):
    if zb.read(n) != za.read(n):
        changed.append(n)
print("  changed parts:", changed)
print("  identical parts:", len(nb & na) - len(changed))

print()
print("### rendered slide comparison (1600x900 PNG)")
for i in range(1, 7):
    fb, fa = os.path.join(RB, f"slide{i}.png"), os.path.join(RA, f"slide{i}.png")
    if not (os.path.exists(fb) and os.path.exists(fa)):
        print(f"  slide {i}: missing render")
        continue
    ib, ia = Image.open(fb).convert("RGB"), Image.open(fa).convert("RGB")
    if ib.size != ia.size:
        print(f"  slide {i}: size differs {ib.size} vs {ia.size}")
        continue
    diff = ImageChops.difference(ib, ia)
    bbox = diff.getbbox()
    if bbox is None:
        print(f"  slide {i}: IDENTICAL (0 differing pixels)")
    else:
        px = sum(1 for p in diff.convert("L").getdata() if p > 8)
        w = bbox[2] - bbox[0]
        h = bbox[3] - bbox[1]
        print(f"  slide {i}: differs in {px} px, bbox={bbox} ({w}x{h})")
