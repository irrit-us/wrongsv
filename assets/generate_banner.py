"""Generate wrongsv header banner — Liberation Mono title, equal row spacing."""
from PIL import Image, ImageDraw, ImageFont
import os

W, H = 800, 200
OUT = os.path.join(os.path.dirname(__file__), "banner.png")

ACCENT = (124, 145, 219)
WHITE = (255, 255, 255)

img = Image.new("RGBA", (W, H), WHITE + (255,))
draw = ImageDraw.Draw(img)

# ── Fonts ─────────────────────────────────────────────────────────────────────
TITLE_FONT = ImageFont.truetype(
    "/usr/share/fonts/liberation-mono-fonts/LiberationMono-Bold.ttf", 46
)
mono_path = None
for fp in [
    "/usr/share/fonts/urw-base35/NimbusMonoPS-Bold.otf",
    "/usr/share/fonts/liberation-mono-fonts/LiberationMono-Regular.ttf",
    "/usr/share/fonts/adwaita-mono-fonts/AdwaitaMono-Regular.ttf",
]:
    if os.path.exists(fp):
        mono_path = fp
        break

sub_font = ImageFont.truetype(mono_path, 13)
kw_font = ImageFont.truetype(mono_path, 11)
flow_font = ImageFont.truetype(mono_path, 13)
flow_sm = ImageFont.truetype(mono_path, 11)

# ── Measure ───────────────────────────────────────────────────────────────────
cx = W // 2

title = "wrongsv"
tb = draw.textbbox((0, 0), title, font=TITLE_FONT)
title_w = tb[2] - tb[0]

subtitle = "VLESS proxy server"
sb = draw.textbbox((0, 0), subtitle, font=sub_font)
sub_w = sb[2] - sb[0]

keywords = "XTLS Vision  ·  REALITY  ·  AnyTLS  ·  ML-KEM-512  ·  AEAD"
kb = draw.textbbox((0, 0), keywords, font=kw_font)
kw_w = kb[2] - kb[0]

# ── Explicit positions with generous anti-alias spacing ───────────────────────
# 4 content rows: title, subtitle, keywords, flow-diagram
# 200px total. Spacing between row anchors must account for:
#   - bbox extent below anchor (tb[3], sb[3], etc.)
#   - AA bleed (~12px for 46px font, ~6px for 13px, ~5px for 11px)

# Positions tuned for roughly equal visual gaps (~20px each)
# Title: bbox=(0,14,193,49) → drawn at 14 → visual 28..63
# Sub:   bbox=(-1,0,141,11) → drawn at 82 → visual 82..93, gap=19
# KW:    bbox=(0,0,383,10)  → drawn at 113 → visual 113..123, gap=20
# Flow:  center at 162, label at 140, node at 162 → gap=17
title_y = 14
sub_y = 82
kw_y = 113
fl_y = 162  # flow center

# ── 1. Title ──────────────────────────────────────────────────────────────────
draw.text((cx - title_w // 2, title_y), title, fill=ACCENT + (255,), font=TITLE_FONT)

# ── 2. Subtitle ───────────────────────────────────────────────────────────────
draw.text((cx - sub_w // 2, sub_y), subtitle, fill=ACCENT + (170,), font=sub_font)

# ── 3. Keywords ───────────────────────────────────────────────────────────────
draw.text((cx - kw_w // 2, kw_y), keywords, fill=ACCENT + (130,), font=kw_font)

# ── 4. Flow diagram ───────────────────────────────────────────────────────────
node_r = 5
c_x, s_x, t_x = 130, 400, 670
fc = fl_y  # center-y of flow nodes

# Client
draw.ellipse([c_x - node_r, fc - node_r, c_x + node_r, fc + node_r], fill=ACCENT + (230,))
draw.text((c_x - draw.textbbox((0, 0), "Client", font=flow_sm)[2] // 2, fc - 22),
          "Client", fill=ACCENT + (160,), font=flow_sm)

# Arrow 1
a1e = s_x - 78
draw.line([(c_x + node_r + 4, fc), (a1e, fc)], fill=ACCENT + (100,), width=2)
draw.polygon([(a1e, fc - 4), (a1e + 6, fc), (a1e, fc + 4)], fill=ACCENT + (160,))

# Server box
s_w, s_h = 152, 28
draw.rounded_rectangle(
    [(s_x - s_w // 2, fc - s_h // 2), (s_x + s_w // 2, fc + s_h // 2)],
    radius=5, fill=ACCENT + (25,), outline=ACCENT + (170,), width=2
)
st = "wrongsv"
draw.text((s_x - draw.textbbox((0, 0), st, font=flow_font)[2] // 2, fc - 8),
          st, fill=ACCENT + (240,), font=flow_font)

# Arrow 2
a2s = s_x + s_w // 2 + 4
a2e = t_x - node_r - 4
draw.line([(a2s, fc), (a2e, fc)], fill=ACCENT + (100,), width=2)
draw.polygon([(a2e, fc - 4), (a2e + 6, fc), (a2e, fc + 4)], fill=ACCENT + (160,))

# Target
draw.ellipse([t_x - node_r, fc - node_r, t_x + node_r, fc + node_r], fill=ACCENT + (230,))
draw.text((t_x - draw.textbbox((0, 0), "Target", font=flow_sm)[2] // 2, fc - 22),
          "Target", fill=ACCENT + (160,), font=flow_sm)

# ── Bottom divider ────────────────────────────────────────────────────────────
draw.line([(60, H - 2), (W - 60, H - 2)], fill=ACCENT + (40,), width=1)

img.save(OUT)
print(f"Banner saved to {OUT} ({W}x{H})")
