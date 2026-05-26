"""Generate wrongsv header banner — only #7c91db + #ffffff, minimal and balanced."""
from PIL import Image, ImageDraw, ImageFont
import os

W, H = 800, 200
OUT = os.path.join(os.path.dirname(__file__), "banner.png")

ACCENT = (124, 145, 219)  # #7c91db
WHITE = (255, 255, 255)   # #ffffff

img = Image.new("RGBA", (W, H), WHITE + (255,))
draw = ImageDraw.Draw(img)

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

mono_path = None
for fp in font_paths:
    if os.path.exists(fp):
        mono_path = fp
        break
if mono_path is None:
    mono_path = "/usr/share/fonts/dejavu/DejaVuSansMono.ttf"

mono = ImageFont.truetype(mono_path, 13)
mono_sm = ImageFont.truetype(mono_path, 11)

# ── Left accent bar ───────────────────────────────────────────────────────────
draw.rectangle([(0, 0), (4, H)], fill=ACCENT + (255,))

# ── Left column: title + subtitle ─────────────────────────────────────────────
tx, ty = 36, 36
draw.text((tx, ty), "wrongsv", fill=ACCENT + (255,), font=title_font)

title_bbox = draw.textbbox((tx, ty), "wrongsv", font=title_font)
cursor_x = title_bbox[2] + 10
cursor_y = title_bbox[1] + 6
cursor_h = title_bbox[3] - title_bbox[1] - 8
cursor_w = 12
draw.rounded_rectangle(
    [(cursor_x, cursor_y), (cursor_x + cursor_w, cursor_y + cursor_h)],
    radius=3, fill=ACCENT + (200,)
)

sub_x = tx + 4
sub_y1 = title_bbox[3] + 20
draw.text((sub_x, sub_y1), "VLESS proxy server", fill=ACCENT + (150,), font=mono)
draw.text((sub_x, sub_y1 + 18), "XTLS Vision  ·  REALITY  ·  AnyTLS  ·  ML-KEM-512  ·  AEAD",
          fill=ACCENT + (115,), font=mono)

# ── Right column: feature tags (vertically centered in banner) ────────────────
tags = ["TLS 1.3", "REALITY", "AnyTLS", "PQ-KEM", "AEAD"]
tag_h = 22
tag_pad_x = 10
tag_gap = 6
tag_right = W - 30

total_tags_h = len(tags) * tag_h + (len(tags) - 1) * tag_gap
tags_top = (H - total_tags_h) // 2

for i, tag in enumerate(tags):
    tag_text_w = draw.textbbox((0, 0), tag, font=mono_sm)[2]
    tag_w = tag_text_w + tag_pad_x * 2
    tag_left = tag_right - tag_w
    tag_y = tags_top + i * (tag_h + tag_gap)
    draw.rounded_rectangle(
        [(tag_left, tag_y), (tag_right, tag_y + tag_h)],
        radius=4, outline=ACCENT + (100,), width=1, fill=ACCENT + (15,)
    )
    # Center text in tag box
    text_h = draw.textbbox((0, 0), tag, font=mono_sm)[3]
    text_y = tag_y + (tag_h - text_h) // 2
    draw.text((tag_left + tag_pad_x, text_y), tag, fill=ACCENT + (210,), font=mono_sm)

# ── Bottom section: flow diagram ──────────────────────────────────────────────
fl_y = 154
node_r = 5

c_x = 130
s_x = 400
t_x = 670

# Client node
draw.ellipse([c_x - node_r, fl_y - node_r, c_x + node_r, fl_y + node_r], fill=ACCENT + (220,))
client_tw = draw.textbbox((0, 0), "Client", font=mono_sm)[2]
draw.text((c_x - client_tw // 2, fl_y - 24), "Client", fill=ACCENT + (160,), font=mono_sm)

# Arrow 1
a1s = c_x + node_r + 4
a1e = s_x - 78
draw.line([(a1s, fl_y), (a1e, fl_y)], fill=ACCENT + (100,), width=2)
draw.polygon([(a1e, fl_y - 4), (a1e + 6, fl_y), (a1e, fl_y + 4)], fill=ACCENT + (160,))

# Server box
s_w, s_h = 150, 28
draw.rounded_rectangle(
    [(s_x - s_w // 2, fl_y - s_h // 2), (s_x + s_w // 2, fl_y + s_h // 2)],
    radius=5, fill=ACCENT + (25,), outline=ACCENT + (160,), width=2
)
st = "[  wrongsv  ]"
draw.text((s_x - draw.textbbox((0, 0), st, font=mono)[2] // 2, fl_y - 9),
          st, fill=ACCENT + (255,), font=mono)

# Arrow 2
a2s = s_x + s_w // 2 + 4
a2e = t_x - node_r - 4
draw.line([(a2s, fl_y), (a2e, fl_y)], fill=ACCENT + (100,), width=2)
draw.polygon([(a2e, fl_y - 4), (a2e + 6, fl_y), (a2e, fl_y + 4)], fill=ACCENT + (160,))

# Target node
draw.ellipse([t_x - node_r, fl_y - node_r, t_x + node_r, fl_y + node_r], fill=ACCENT + (220,))
target_tw = draw.textbbox((0, 0), "Target", font=mono_sm)[2]
draw.text((t_x - target_tw // 2, fl_y - 24), "Target", fill=ACCENT + (160,), font=mono_sm)

# ── Bottom divider ────────────────────────────────────────────────────────────
draw.line([(36, H - 2), (W - 36, H - 2)], fill=ACCENT + (40,), width=1)

img.save(OUT)
print(f"Banner saved to {OUT} ({W}x{H})")
