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
# Blitzposition
#

BOLT_TRANSLATE_X = 28.7
BOLT_TRANSLATE_Y = 15.2
BOLT_SCALE = 0.069

#
# defs übernehmen
#

m = re.search(r"<defs>(.*?)</defs>", bolt, re.S)
if not m:
    raise RuntimeError("No <defs> found in bolt.svg")

defs = "<defs>" + m.group(1) + "</defs>"

frame = frame.replace("<!-- DEFS -->", defs)

#
# Blitzgruppe holen
#

m = re.search(r"(<g.*?</g>)\s*</svg>", bolt, re.S)
if not m:
    raise RuntimeError("No bolt group found")

bolt_group = f"""
<g transform="translate({BOLT_TRANSLATE_X} {BOLT_TRANSLATE_Y}) scale({BOLT_SCALE})">
{m.group(1)}
</g>
"""

frame = frame.replace("<!-- BOLT -->", bolt_group)

Path(sys.argv[3]).write_text(frame, encoding="utf-8")

print("Built", sys.argv[3])
