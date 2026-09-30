import glob, zipfile, re, os
keys = ["Feasibility and Viability", "Feasibility", "Caffeinated Coders", "Risk 2", "1,978.6", "JA4", "Feasibility: it already runs"]
cands = glob.glob(r'C:\Users\shaik\Downloads\*.pptx') + glob.glob(r'C:\Users\shaik\OneDrive\Desktop\**\*.pptx', recursive=True)
for f in cands:
    try:
        z = zipfile.ZipFile(f)
        names = [n for n in z.namelist() if re.match(r'ppt/slides/slide\d+\.xml$', n)]
        blob = ' '.join(z.read(n).decode('utf-8','ignore') for n in names)
        hits = [k for k in keys if k.lower() in blob.lower()]
        print(f"{len(names):3d} slides | {os.path.getsize(f):9d} | {os.path.basename(f)} | HITS: {hits}")
    except Exception as e:
        print(f"  ERR | {os.path.basename(f)} | {e}")
