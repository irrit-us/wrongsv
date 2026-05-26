"""Generate wrongsv header banner — centered vertical layout, two-color minimal."""
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
        title_font = ImageFont.truetype(fp, 44)
        break
if title_font is None:
    title_font = ImageFont.truetype("/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf", 44)

mono_path = None
for fp in font_paths:
    if os.path.exists(fp):
        mono_path = fp
        break
if mono_path is None:
    mono_path = "/usr/share/fonts/dejavu/DejaVuSansMono.ttf"

mono = ImageFont.truetype(mono_path, 13)
mono_sm = ImageFont.truetype(mono_path, 11)

# ── Vertical layout, all centered ─────────────────────────────────────────────
cx = W // 2  # horizontal center

# 1. Title
title = "wrongsv"
title_bbox = draw.textbbox((0, 0), title, font=title_font)
title_w = title_bbox[2] - title_bbox[0]
title_h = title_bbox[3] - title_bbox[1]
title_y = 36
draw.text((cx - title_w // 2, title_y), title, fill=ACCENT + (255,), font=title_font)

# Cursor block after title
cursor_x = cx + title_w // 2 + 10
cursor_y = title_y + 6
cursor_h = title_h - 10
cursor_w = 12
draw.rounded_rectangle(
    [(cursor_x, cursor_y), (cursor_x + cursor_w, cursor_y + cursor_h)],
    radius=3, fill=ACCENT + (200,)
)

# 2. Subtitle
subtitle = "VLESS proxy server"
sub_bbox = draw.textbbox((0, 0), subtitle, font=mono)
sub_w = sub_bbox[2] - sub_bbox[0]
sub_y = title_y + title_h + 14
draw.text((cx - sub_w // 2, sub_y), subtitle, fill=ACCENT + (160,), font=mono)

# 3. Keywords
keywords = "XTLS Vision  ·  REALITY  ·  AnyTLS  ·  ML-KEM-512  ·  AEAD"
kw_bbox = draw.textbbox((0, 0), keywords, font=mono_sm)
kw_w = kw_bbox[2] - kw_bbox[0]
kw_y = sub_y + 20
draw.text((cx - kw_w // 2, kw_y), keywords, fill=ACCENT + (120,), font=mono_sm)

# 4. Flow diagram at bottom
fl_y = 148
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
draw.line([(60, H - 2), (W - 60, H - 2)], fill=ACCENT + (40,), width=1)

img.save(OUT)
print(f"Banner saved to {OUT} ({W}x{H})")
