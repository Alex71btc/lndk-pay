#!/usr/bin/env python3

from pathlib import Path
from PIL import Image
import sys

if len(sys.argv) != 3:
    print("Usage:")
    print("python3 crop_transparent.py input.png output.png")
    sys.exit(1)

INPUT = Path(sys.argv[1])
OUTPUT = Path(sys.argv[2])

img = Image.open(INPUT).convert("RGBA")
alpha = img.getchannel("A")

w, h = img.size

MIN_ALPHA = 20          # Pixel darunter gelten als transparent
MIN_PIXELS = 5          # mindestens 5 sichtbare Pixel pro Zeile/Spalte

left = 0
while left < w:
    visible = sum(alpha.getpixel((left, y)) >= MIN_ALPHA for y in range(h))
    if visible >= MIN_PIXELS:
        break
    left += 1

right = w - 1
while right >= left:
    visible = sum(alpha.getpixel((right, y)) >= MIN_ALPHA for y in range(h))
    if visible >= MIN_PIXELS:
        break
    right -= 1

top = 0
while top < h:
    visible = sum(alpha.getpixel((x, top)) >= MIN_ALPHA for x in range(w))
    if visible >= MIN_PIXELS:
        break
    top += 1

bottom = h - 1
while bottom >= top:
    visible = sum(alpha.getpixel((x, bottom)) >= MIN_ALPHA for x in range(w))
    if visible >= MIN_PIXELS:
        break
    bottom -= 1

cropped = img.crop((left, top, right + 1, bottom + 1))
cropped.save(OUTPUT)

print(f"Cropped {INPUT}")
print(f" -> {OUTPUT}")
print(f"New size: {cropped.size}")
