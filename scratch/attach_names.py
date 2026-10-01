import struct
p = r"C:\Users\shaik\.cline\data\sessions\session_1790475217011_a2lie\user-attachments\b839789b-7ffb-4ac0-86ce-0a5a7af153e3-.pptx"
d = open(p,"rb").read()
found=[]
for i in range(len(d)-30):
    if d[i:i+4] != b"PK\x03\x04": continue
    nlen = d[i+26] | (d[i+27]<<8)
    if nlen == 0 or nlen > 120 or i+30+nlen > len(d): continue
    nm = d[i+30:i+30+nlen]
    try: s = nm.decode("ascii")
    except: continue
    if "." not in s or any(ord(c)<32 for c in s): continue
    csize = struct.unpack("<I", d[i+18:i+22])[0]
    found.append((i, s, csize))
print("plausible local headers:", len(found))
for f in found: print("  ", f)
