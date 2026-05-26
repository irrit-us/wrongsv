"""Generate wrongsv header banner — Montserrat title, centered vertical layout."""
from PIL import Image, ImageDraw, ImageFont
import os

W, H = 800, 200
OUT = os.path.join(os.path.dirname(__file__), "banner.png")

ACCENT = (124, 145, 219)  # #7c91db
WHITE = (255, 255, 255)   # #ffffff

img = Image.new("RGBA", (W, H), WHITE + (255,))
draw = ImageDraw.Draw(img)

# ── Fonts ─────────────────────────────────────────────────────────────────────
MONT_BOLD = "/usr/share/fonts/julietaula-montserrat-fonts/Montserrat-SemiBold.otf"
MONT_REG = "/usr/share/fonts/julietaula-montserrat-fonts/Montserrat-Regular.otf"
MONT_LIGHT = "/usr/share/fonts/julietaula-montserrat-fonts/Montserrat-Light.otf"

title_font = ImageFont.truetype(MONT_BOLD, 44)
sub_font = ImageFont.truetype(MONT_REG, 14)
kw_font = ImageFont.truetype(MONT_LIGHT, 11)
flow_font = ImageFont.truetype(MONT_REG, 12)
flow_sm = ImageFont.truetype(MONT_LIGHT, 10)

# ── Vertical layout, all centered ─────────────────────────────────────────────
cx = W // 2

# 1. Title
title = "wrongsv"
tb = draw.textbbox((0, 0), title, font=title_font)
title_w = tb[2] - tb[0]
title_h = tb[3] - tb[1]
title_y = 34
draw.text((cx - title_w // 2, title_y), title, fill=ACCENT + (255,), font=title_font)

# Cursor block
cursor_x = cx + title_w // 2 + 10
cursor_y = title_y + 8
cursor_h = title_h - 12
cursor_w = 11
draw.rounded_rectangle(
    [(cursor_x, cursor_y), (cursor_x + cursor_w, cursor_y + cursor_h)],
    radius=3, fill=ACCENT + (200,)
)

# 2. Subtitle
subtitle = "VLESS proxy server"
sb = draw.textbbox((0, 0), subtitle, font=sub_font)
sub_w = sb[2] - sb[0]
sub_y = title_y + title_h + 12
draw.text((cx - sub_w // 2, sub_y), subtitle, fill=ACCENT + (170,), font=sub_font)

# 3. Keywords
keywords = "XTLS Vision  ·  REALITY  ·  AnyTLS  ·  ML-KEM-512  ·  AEAD"
kb = draw.textbbox((0, 0), keywords, font=kw_font)
kw_w = kb[2] - kb[0]
kw_y = sub_y + 22
draw.text((cx - kw_w // 2, kw_y), keywords, fill=ACCENT + (130,), font=kw_font)

# 4. Flow diagram at bottom
fl_y = 150
node_r = 5

c_x = 130
s_x = 400
t_x = 670

# Client node
draw.ellipse([c_x - node_r, fl_y - node_r, c_x + node_r, fl_y + node_r], fill=ACCENT + (230,))
draw.text((c_x - draw.textbbox((0, 0), "Client", font=flow_sm)[2] // 2, fl_y - 22),
          "Client", fill=ACCENT + (160,), font=flow_sm)

# Arrow 1
a1s = c_x + node_r + 4
a1e = s_x - 78
draw.line([(a1s, fl_y), (a1e, fl_y)], fill=ACCENT + (100,), width=2)
draw.polygon([(a1e, fl_y - 4), (a1e + 6, fl_y), (a1e, fl_y + 4)], fill=ACCENT + (160,))

# Server box
s_w, s_h = 150, 28
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

img.save(OUT)
print(f"Banner saved to {OUT} ({W}x{H})")
