"""Generate wrongsv header banner — Liberation Mono title, equal row spacing."""
from PIL import Image, ImageDraw, ImageFont
import os

W, H = 800, 200
OUT = os.path.join(os.path.dirname(__file__), "banner.png")

ACCENT = (124, 145, 219)  # #7c91db
WHITE = (255, 255, 255)   # #ffffff

img = Image.new("RGBA", (W, H), WHITE + (255,))
draw = ImageDraw.Draw(img)

# ── Fonts ─────────────────────────────────────────────────────────────────────
TITLE_FONT = ImageFont.truetype(
    "/usr/share/fonts/liberation-mono-fonts/LiberationMono-Bold.ttf", 46
)

mono_paths = [
    "/usr/share/fonts/google/roboto-mono/RobotoMono-Bold.ttf",
    "/usr/share/fonts/urw-base35/NimbusMonoPS-Bold.otf",
    "/usr/share/fonts/dejavu/DejaVuSansMono-Bold.ttf",
]
mono_path = None
for fp in mono_paths:
    if os.path.exists(fp):
        mono_path = fp
        break
if mono_path is None:
    mono_path = "/usr/share/fonts/liberation-mono-fonts/LiberationMono-Regular.ttf"

sub_font = ImageFont.truetype(mono_path, 13)
kw_font = ImageFont.truetype(mono_path, 11)
flow_font = ImageFont.truetype(mono_path, 13)
flow_sm = ImageFont.truetype(mono_path, 11)

# ── Measure all elements ──────────────────────────────────────────────────────
cx = W // 2

title = "wrongsv"
tb = draw.textbbox((0, 0), title, font=TITLE_FONT)
title_w = tb[2] - tb[0]
title_h = tb[3] - tb[1]

subtitle = "VLESS proxy server"
sb = draw.textbbox((0, 0), subtitle, font=sub_font)
sub_w = sb[2] - sb[0]
sub_h = sb[3] - sb[1]

keywords = "XTLS Vision  ·  REALITY  ·  AnyTLS  ·  ML-KEM-512  ·  AEAD"
kb = draw.textbbox((0, 0), keywords, font=kw_font)
kw_w = kb[2] - kb[0]
kw_h = kb[3] - kb[1]

# Flow diagram height: label (22px) + node (10px diam) + some buffer ≈ 36px
flow_h = 36

# ── Layout: 4 rows, equal gaps ────────────────────────────────────────────────
top_pad = 24
bot_pad = 24
available = H - top_pad - bot_pad
content_h = title_h + sub_h + kw_h + flow_h
gap = (available - content_h) // 3

title_y = top_pad
sub_y = title_y + title_h + gap
kw_y = sub_y + sub_h + gap
fl_y = kw_y + kw_h + gap

# ── 1. Title ──────────────────────────────────────────────────────────────────
draw.text((cx - title_w // 2, title_y), title, fill=ACCENT + (255,), font=TITLE_FONT)

# ── 2. Subtitle ───────────────────────────────────────────────────────────────
draw.text((cx - sub_w // 2, sub_y), subtitle, fill=ACCENT + (170,), font=sub_font)

# ── 3. Keywords ───────────────────────────────────────────────────────────────
draw.text((cx - kw_w // 2, kw_y), keywords, fill=ACCENT + (130,), font=kw_font)

# ── 4. Flow diagram ───────────────────────────────────────────────────────────
node_r = 5
c_x = 130
s_x = 400
t_x = 670

# Client node
draw.ellipse([c_x - node_r, fl_y - node_r, c_x + node_r, fl_y + node_r], fill=ACCENT + (230,))
draw.text((c_x - draw.textbbox((0, 0), "Client", font=flow_sm)[2] // 2, fl_y - 22),
          "Client", fill=ACCENT + (160,), font=flow_sm)

# Arrow 1
a1e = s_x - 78
draw.line([(c_x + node_r + 4, fl_y), (a1e, fl_y)], fill=ACCENT + (100,), width=2)
draw.polygon([(a1e, fl_y - 4), (a1e + 6, fl_y), (a1e, fl_y + 4)], fill=ACCENT + (160,))

# Server box
s_w, s_h = 152, 28
draw.rounded_rectangle(
    [(s_x - s_w // 2, fl_y - s_h // 2), (s_x + s_w // 2, fl_y + s_h // 2)],
    radius=5, fill=ACCENT + (25,), outline=ACCENT + (170,), width=2
)
st = "wrongsv"
st_w = draw.textbbox((0, 0), st, font=flow_font)[2]
draw.text((s_x - st_w // 2, fl_y - 8), st, fill=ACCENT + (240,), font=flow_font)

# Arrow 2
a2s = s_x + s_w // 2 + 4
a2e = t_x - node_r - 4
draw.line([(a2s, fl_y), (a2e, fl_y)], fill=ACCENT + (100,), width=2)
draw.polygon([(a2e, fl_y - 4), (a2e + 6, fl_y), (a2e, fl_y + 4)], fill=ACCENT + (160,))

# Target node
draw.ellipse([t_x - node_r, fl_y - node_r, t_x + node_r, fl_y + node_r], fill=ACCENT + (230,))
draw.text((t_x - draw.textbbox((0, 0), "Target", font=flow_sm)[2] // 2, fl_y - 22),
          "Target", fill=ACCENT + (160,), font=flow_sm)

# ── Bottom divider ────────────────────────────────────────────────────────────
draw.line([(60, H - 2), (W - 60, H - 2)], fill=ACCENT + (40,), width=1)

# Report spacing
print(f"Banner saved to {OUT} ({W}x{H})")
print(f"  title_h={title_h} sub_h={sub_h} kw_h={kw_h} flow_h={flow_h}")
print(f"  gap={gap}px  top={top_pad}  bot={H - (fl_y + flow_h)}")
