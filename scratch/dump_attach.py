import struct
p = r'C:\Users\shaik\.cline\data\sessions\session_1790475217011_a2lie\user-attachments\b839789b-7ffb-4ac0-86ce-0a5a7af153e3-.pptx'
d = open(p,"rb").read()
out = open("attach_entries.txt","w",encoding="utf-8")
pos = 0
names=[]
while True:
    i = d.find(b"PK\x03\x04", pos)
    if i < 0: break
    hdr = d[i:i+30]
    sig, ver, flag, method, mt, md, crc, csize, usize, nlen, elen = struct.unpack("<IHHHHHIIIHH", hdr)
    name = d[i+30:i+30+nlen].decode("utf-8","ignore")
    names.append((i, name, method, csize, usize))
    pos = i+4
out.write(f"total entries {len(names)} filesize {len(d)}\n")
for n in names:
    out.write(f"  off={n[0]:8d} method={n[2]} csize={n[3]:8d} usize={n[4]:8d}  {n[1]}\n")
out.close()
print("ok")
