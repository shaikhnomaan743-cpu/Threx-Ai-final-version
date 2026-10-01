import struct, zlib, os
p = r"C:\Users\shaik\.cline\data\sessions\session_1790475217011_a2lie\user-attachments\b839789b-7ffb-4ac0-86ce-0a5a7af153e3-.pptx"
d = open(p,"rb").read()
pos = 0
entries = []
while True:
    i = d.find(b"PK\x03\x04", pos)
    if i < 0 or i + 30 > len(d): break
    try:
        ver, flag, method, mt, md, crc, csize, usize, nlen, elen = struct.unpack("<HHHHHIIIHH", d[i+4:i+30])
    except Exception as e:
        break
    name = d[i+30:i+30+nlen].decode("utf-8","ignore")
    if not name or method not in (0,8):
        pos = i+4
        continue
    entries.append((i, name, method, csize, usize, flag, elen))
    pos = i+30+nlen+elen+ (0 if (flag & 0x08) else csize)
print("entries:", len(entries))
for e in entries[:8]:
    print(e)
