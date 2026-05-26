"""Generate wrongsv header banner — dark-themed network proxy motif."""
from PIL import Image, ImageDraw, ImageFont
import math, os

W, H = 800, 200
OUT = os.path.join(os.path.dirname(__file__), "banner.png")

img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)

# Background with subtle gradient
for y in range(H):
    t = y / H
    r = int(10 + 3 * t)
    g = int(14 + 4 * t)
    b = int(24 + 6 * t)
    draw.line([(0, y), (W, y)], fill=(r, g, b, 255))

# Subtle grid pattern
for x in range(0, W, 40):
    draw.line([(x, 0), (x, H)], fill=(30, 36, 50, 40), width=1)
for y in range(0, H, 40):
    draw.line([(0, y), (W, y)], fill=(30, 36, 50, 40), width=1)

# Fonts
font_paths = [
    "/usr/share/fonts/google/roboto-mono/RobotoMono-Bold.ttf",
    "/usr/share/fonts/urw-base35/NimbusMonoPS-Bold.otf",
    "/usr/share/fonts/dejavu/DejaVuSansMono-Bold.ttf",
    "/usr/share/fonts/gnu-free/FreeMonoBold.ttf",
]
title_font = None
for fp in font_paths:
    if os.path.exists(fp):
        title_font = ImageFont.truetype(fp, 50)
        break
if title_font is None:
    title_font = ImageFont.truetype("/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf", 50)

mono_small = None
for fp in font_paths:
    if os.path.exists(fp):
        mono_small = ImageFont.truetype(fp, 14)
        break
if mono_small is None:
    mono_small = ImageFont.truetype("/usr/share/fonts/dejavu/DejaVuSansMono.ttf", 14)

# Accent bar at top
draw.rectangle([(0, 0), (W, 3)], fill=(80, 200, 140, 220))

# Title with shadow
draw.text((32, 30), "wrongsv", fill=(0, 0, 0, 120), font=title_font)
draw.text((30, 28), "wrongsv", fill=(80, 200, 140), font=title_font)

# Cursor/blink animation hint
draw.rectangle([(296, 34), (304, 70)], fill=(80, 200, 140, 200))

# Subtitle
draw.text((34, 88), "VLESS proxy server   ·   XTLS Vision   ·   REALITY   ·   ML-KEM-512 PQ", fill=(140, 160, 180), font=mono_small)

# Divider line
for x in range(30, 770, 2):
    alpha = 80 + int(40 * math.sin(x * 0.05))
    draw.line([(x, 118), (x + 1, 118)], fill=(80, 200, 140, min(alpha, 180)), width=1)

# Network flow diagram
y = 155
dot_r = 5

# Client
cx = 100
draw.ellipse([cx - dot_r, y - dot_r, cx + dot_r, y + dot_r], fill=(80, 160, 255))
draw.text((cx - 26, y + 12), "Client", fill=(140, 165, 200), font=mono_small)

# Arrow client → server
ax = cx + 16
draw.line([(ax, y), (ax + 90, y)], fill=(90, 130, 170), width=2)
draw.polygon([(ax + 90, y - 5), (ax + 100, y), (ax + 90, y + 5)], fill=(100, 180, 130))

# Server box with glow
sx = 310
box_w, box_h = 130, 32
# Glow
for i in range(4):
    alpha = 40 - i * 10
    draw.rectangle(
        [(sx - box_w // 2 - i, y - box_h // 2 - i), (sx + box_w // 2 + i, y + box_h // 2 + i)],
        outline=(80, 200, 140, alpha), width=1
    )
# Main box
draw.rectangle(
    [(sx - box_w // 2, y - box_h // 2), (sx + box_w // 2, y + box_h // 2)],
    fill=(22, 30, 44), outline=(80, 200, 140), width=2
)
draw.text((sx - 52, y - 11), "[  wrongsv  ]", fill=(80, 200, 140), font=mono_small)

# Arrow server → target
ax2 = sx + box_w // 2 + 8
draw.line([(ax2, y), (ax2 + 70, y)], fill=(90, 130, 170), width=2)
draw.polygon([(ax2 + 70, y - 5), (ax2 + 80, y), (ax2 + 70, y + 5)], fill=(255, 160, 100))

# Target
tx = ax2 + 100
draw.ellipse([tx - dot_r, y - dot_r, tx + dot_r, y + dot_r], fill=(255, 150, 100))
draw.text((tx - 32, y + 12), "Target", fill=(200, 175, 165), font=mono_small)

# Feature tags top-right
tags = [
    ("TLS 1.3", (255, 200, 60)),
    ("AEAD", (100, 200, 200)),
    ("PQ-KEM", (140, 100, 255)),
]
tag_x = 640
for i, (label, color) in enumerate(tags):
    ty = 22 + i * 24
    r, g, b = color
    draw.rounded_rectangle([(tag_x, ty), (tag_x + 85, ty + 18)], radius=4, outline=(r, g, b, 180), width=1)
    draw.text((tag_x + 8, ty + 1), label, fill=(r, g, b), font=mono_small)

img.save(OUT)
print(f"Banner saved to {OUT} ({W}x{H})")
