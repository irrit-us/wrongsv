"""Generate wrongsv header banner — white background, #7c91db accent, balanced layout."""
from PIL import Image, ImageDraw, ImageFont
import math, os

W, H = 800, 200
OUT = os.path.join(os.path.dirname(__file__), "banner.png")

ACCENT = (124, 145, 219)  # #7c91db
ACCENT_LIGHT = (179, 192, 237)
BG = (255, 255, 255)      # #ffffff
DARK = (38, 42, 58)
MUTED = (130, 140, 165)
LIGHT_LINE = (228, 231, 245)
TAG_BG = (242, 244, 252)

img = Image.new("RGBA", (W, H), BG + (255,))
draw = ImageDraw.Draw(img)

# Subtle dot-grid background
for x in range(20, W, 28):
    for y in range(20, H, 28):
        draw.ellipse([x - 1, y - 1, x + 1, y + 1], fill=ACCENT + (12,))

# ── Fonts ─────────────────────────────────────────────────────────────────────
font_paths = [
    "/usr/share/fonts/google/roboto-mono/RobotoMono-Bold.ttf",
    "/usr/share/fonts/urw-base35/NimbusMonoPS-Bold.otf",
    "/usr/share/fonts/dejavu/DejaVuSansMono-Bold.ttf",
    "/usr/share/fonts/gnu-free/FreeMonoBold.ttf",
]
title_font = None
for fp in font_paths:
    if os.path.exists(fp):
        title_font = ImageFont.truetype(fp, 46)
        break
if title_font is None:
    title_font = ImageFont.truetype("/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf", 46)

mono = None
for fp in font_paths:
    if os.path.exists(fp):
        mono = ImageFont.truetype(fp, 13)
        break
if mono is None:
    mono = ImageFont.truetype("/usr/share/fonts/dejavu/DejaVuSansMono.ttf", 13)

mono_sm = None
for fp in font_paths:
    if os.path.exists(fp):
        mono_sm = ImageFont.truetype(fp, 11)
        break
if mono_sm is None:
    mono_sm = mono

# ── Top section: title + subtitle ─────────────────────────────────────────────
# Left accent bar
draw.rectangle([(0, 0), (4, H)], fill=ACCENT + (255,))

# Title
tx, ty = 36, 26
draw.text((tx, ty), "wrongsv", fill=ACCENT, font=title_font)

# Cursor block
tw = tx + 298
draw.rounded_rectangle([(tw, ty + 6), (tw + 11, ty + 36)], radius=3, fill=ACCENT + (200,))

# Subtitle line 1
draw.text((tx + 4, 80), "VLESS proxy server", fill=MUTED, font=mono)
# Subtitle line 2 — features
draw.text((tx + 4, 98), "XTLS Vision  ·  REALITY  ·  AnyTLS  ·  ML-KEM-512  ·  AEAD", fill=MUTED + (200,), font=mono)

# ── Horizontal flow diagram ───────────────────────────────────────────────────
fl_y = 140
node_r = 7

# Client node
c_x = 120
draw.ellipse([c_x - node_r - 3, fl_y - node_r - 3, c_x + node_r + 3, fl_y + node_r + 3],
             outline=ACCENT + (100,), width=1)
draw.ellipse([c_x - node_r, fl_y - node_r, c_x + node_r, fl_y + node_r], fill=ACCENT + (200,))
draw.text((c_x - 18, fl_y - 30), "Client", fill=MUTED, font=mono_sm)

# Arrow 1
a1_x1 = c_x + 12
a1_x2 = 260
draw.line([(a1_x1, fl_y), (a1_x2, fl_y)], fill=ACCENT + (120,), width=2)
# arrowhead
draw.polygon([(a1_x2, fl_y - 5), (a1_x2 + 8, fl_y), (a1_x2, fl_y + 5)], fill=ACCENT + (180,))

# Server box
s_x = 400
s_w, s_h = 150, 34
draw.rounded_rectangle(
    [(s_x - s_w // 2, fl_y - s_h // 2), (s_x + s_w // 2, fl_y + s_h // 2)],
    radius=6, fill=TAG_BG, outline=ACCENT + (160,), width=2
)
draw.text((s_x - 48, fl_y - 11), "[  wrongsv  ]", fill=ACCENT, font=mono)
draw.text((s_x - 38, fl_y + 20), "VLESS + TLS", fill=MUTED + (180,), font=mono_sm)

# Arrow 2
a2_x1 = s_x + s_w // 2 + 4
a2_x2 = 580
draw.line([(a2_x1, fl_y), (a2_x2, fl_y)], fill=ACCENT + (120,), width=2)
draw.polygon([(a2_x2, fl_y - 5), (a2_x2 + 8, fl_y), (a2_x2, fl_y + 5)], fill=ACCENT + (180,))

# Target node
t_x = 630
draw.ellipse([t_x - node_r - 3, fl_y - node_r - 3, t_x + node_r + 3, fl_y + node_r + 3],
             outline=ACCENT + (100,), width=1)
draw.ellipse([t_x - node_r, fl_y - node_r, t_x + node_r, fl_y + node_r], fill=ACCENT + (200,))
draw.text((t_x - 18, fl_y - 30), "Target", fill=MUTED, font=mono_sm)

# ── Feature tags row (right-aligned, top section) ─────────────────────────────
tags = [
    "TLS 1.3",
    "REALITY",
    "AnyTLS",
    "PQ-KEM",
    "AEAD",
]
tag_x_start = 800 - 20 - sum(len(t) * 10 + 18 for t in tags) - (len(tags) - 1) * 10
tag_y_top = 28
cur_x = tag_x_start
for tag in tags:
    tw = len(tag) * 10 + 16
    draw.rounded_rectangle(
        [(cur_x, tag_y_top), (cur_x + tw, tag_y_top + 20)], radius=4,
        outline=ACCENT + (100,), width=1, fill=TAG_BG + (180,)
    )
    draw.text((cur_x + 6, tag_y_top + 3), tag, fill=ACCENT + (200,), font=mono_sm)
    cur_x += tw + 10

# Bottom subtle divider
for x in range(40, W - 40, 2):
    alpha = 30 + int(25 * math.sin(x * 0.03))
    draw.line([(x, H - 3), (x + 1, H - 3)], fill=ACCENT + (min(alpha, 80),), width=1)

img.save(OUT)
print(f"Banner saved to {OUT} ({W}x{H})")
