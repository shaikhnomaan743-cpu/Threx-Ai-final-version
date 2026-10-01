import struct, zipfile
p = r"C:\Users\shaik\Downloads\THREX_SIH26145_work.pptx"
d = open(p,"rb").read()
i = d.rfind(b"PK\x05\x06")
print("work.pptx size", len(d), "EOCD at", i)
print("EOCD bytes:", d[i:i+22].hex(" "))
z = zipfile.ZipFile(p)
names = z.namelist()
print("entries:", len(names))
for n in names: print("   ", n, z.getinfo(n).compress_size, z.getinfo(n).file_size)
