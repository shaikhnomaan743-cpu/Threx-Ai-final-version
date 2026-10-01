from pathlib import Path
import ast
BE = "C:\\Users\\shaik\\OneDrive\\Desktop\\threx-AI"
p = Path(BE, "backend/cybersentinel-backend/app/models/beacon_detector.py")
lines = p.read_text().splitlines(keepends=True)
out = []
i = 0
while i < len(lines):
    line = lines[i]
    if line.lstrip().startswith("def detect(self, flow"):
        out.append("    " + line.lstrip())
        i += 1
        while i < len(lines):
            l = lines[i]
            if l.strip() == "":
                out.append(l)
                i += 1
                continue
            indent = len(l) - len(l.lstrip(" "))
            if indent <= 4 and l.lstrip() and not l.lstrip().startswith("#"):
                break
            if indent == 0:
                break
            if l.startswith("        "):
                out.append(l[4:])
            else:
                out.append(l)
            i += 1
        continue
    out.append(line)
    i += 1
p.write_text("".join(out))
ast.parse(p.read_text())
print("OK re-indented and parses")


