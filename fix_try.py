from pathlib import Path
p = Path(r"C:\Users\shaik\OneDrive\Desktop\threx-AI\backend\cybersentinel-backend\app\models\beacon_detector.py")
for i, l in enumerate(lines):
    # Line "    try:" should become "        try:"
    if l.rstrip("\n") == "    try:" and i > 0 and "def detect" in lines[i-1]:
        lines[i] = "        try:" + l[len("    try:"):]
        print("fixed line", i+1, repr(lines[i]))
        break
p.write_text("".join(lines))
import ast
ast.parse(p.read_text())
print("parses OK")
