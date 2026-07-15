#!/usr/bin/env python3

from pathlib import Path
import re
import sys

if len(sys.argv) != 4:
    print("Usage:")
    print("  python3 build_icon.py frame.svg bolt.svg output.svg")
    sys.exit(1)

frame = Path(sys.argv[1]).read_text(encoding="utf-8")
bolt = Path(sys.argv[2]).read_text(encoding="utf-8")

#
# defs
#
m = re.search(r"<defs>(.*?)</defs>", bolt, re.S)
if not m:
    raise RuntimeError("No <defs> found in bolt.svg")

defs = "<defs>" + m.group(1) + "</defs>"

#
# bolt group
#
m = re.search(r"(<g.*?</g>)\s*</svg>", bolt, re.S)
if not m:
    raise RuntimeError("No bolt group found")

group = m.group(1)

#
# scale + move
#
group = f"""
<g transform="translate(28.7 15.2) scale(0.066)">
{group}
</g>
"""

#
# insert defs
#
frame = frame.replace("<!-- DEFS -->", defs)

#
# replace bolt marker
#
frame = frame.replace("<!-- BOLT -->", group)

Path(sys.argv[3]).write_text(frame, encoding="utf-8")

print("Built", sys.argv[3])
