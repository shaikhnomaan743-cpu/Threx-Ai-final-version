from pptx import Presentation
import zipfile, hashlib, os
for f in [r"C:\Users\shaik\Downloads\THREX_SIH26145_work.pptx", r"C:\Users\shaik\Downloads\.pptx", r"C:\Users\shaik\Downloads\THREX_SIH26145_updated.pptx"]:
    print("="*90)
    print("FILE:", f)
    z = zipfile.ZipFile(f)
    for n in ("docProps/core.xml","docProps/app.xml","docProps/custom.xml"):
        try: print("  ", n, z.read(n).decode("utf-8")[:700])
        except Exception as e: print("  ", n, "ERR", e)
    print("   md5:", hashlib.md5(open(f,"rb").read()).hexdigest())
