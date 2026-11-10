"""Writes installer/License.rtf from LICENSE (run after changing LICENSE)."""
import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
text = (root / "LICENSE").read_text(encoding="utf-8")


def esc(s: str) -> str:
    out = []
    for ch in s:
        if ch in "\\{}":
            out.append("\\" + ch)
        elif ord(ch) > 127:
            out.append(f"\\u{ord(ch) if ord(ch) < 32768 else ord(ch) - 65536}?")
        else:
            out.append(ch)
    return "".join(out)


def inline(s: str) -> str:
    # **bold** and ***bold*** from the PolyForm text; drop backticks and <url> brackets.
    s = esc(s.replace("`", ""))
    s = re.sub(r"\*{2,3}(.+?)\*{2,3}", r"{\\b \1}", s)
    return s.replace("<", "").replace(">", "")


lines = []
for raw in text.splitlines():
    line = raw.rstrip()
    if line.startswith("#"):
        heading = line.lstrip("#").strip()
        lines.append(r"\pard\sb120\sa60{\b " + inline(heading) + r"}\par")
    elif set(line) == {"-"}:
        lines.append(r"\pard\sa60\par")
    elif line.startswith(">"):
        lines.append(r"\pard\li240 " + inline(line.lstrip("> ")) + r"\par")
    else:
        lines.append(r"\pard " + inline(line) + r"\par")

rtf = (
    r"{\rtf1\ansi\ansicpg1252\deff0{\fonttbl{\f0\fswiss\fcharset0 Segoe UI;}}"
    "\n" + r"\viewkind4\uc1\f0\fs17" + "\n" + "\n".join(lines) + "\n}\n"
)
target = root / "installer" / "License.rtf"
target.write_text(rtf, encoding="ascii")
print(f"Wrote {target} ({len(rtf)} bytes)")
