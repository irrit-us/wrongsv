"""Generate wrongsv header banner — RGB only, no alpha channel."""
from PIL import Image, ImageDraw, ImageFont
import os

W, H = 800, 200
OUT = os.path.join(os.path.dirname(__file__), "banner.png")

ACCENT = (124, 145, 219)  # #7c91db
WHITE = (255, 255, 255)

# Pre-compute RGB blends — no alpha, all solid
def blend(pct):
    """Blend ACCENT into WHITE at given percentage (0-100)."""
    w = pct / 100.0
    return tuple(int(ACCENT[i] * w + WHITE[i] * (1 - w)) for i in range(3))

# Solid colors for each element
C_TITLE    = blend(100)  # pure accent
C_SUB      = blend(67)
C_KW       = blend(51)
C_FLOW_TEXT = blend(94)
C_FLOW_LABEL = blend(63)
C_FLOW_NODE = blend(90)
C_FLOW_ARROW = blend(39)
C_FLOW_ARROWHEAD = blend(63)
C_BOX       = blend(67)
C_DIVIDER   = blend(16)

img = Image.new("RGB", (W, H), WHITE)
draw = ImageDraw.Draw(img)

# ── Fonts ─────────────────────────────────────────────────────────────────────
TITLE_FONT = ImageFont.truetype(
    os.path.expanduser("~/.local/share/fonts/Cinzel-Bold.ttf"), 46
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

sub_font = ImageFont.truetype(mono_path, 14)
kw_font = ImageFont.truetype(mono_path, 12)
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

# ── Positions ─────────────────────────────────────────────────────────────────
title_y = 14
sub_y = 82
kw_y = 113
fl_y = 167

# ── 1. Title ──────────────────────────────────────────────────────────────────
draw.text((cx - title_w // 2, title_y), title, fill=C_TITLE, font=TITLE_FONT)

# ── 2. Subtitle ───────────────────────────────────────────────────────────────
draw.text((cx - sub_w // 2, sub_y), subtitle, fill=C_SUB, font=sub_font)

# ── 3. Keywords ───────────────────────────────────────────────────────────────
draw.text((cx - kw_w // 2, kw_y), keywords, fill=C_KW, font=kw_font)

# ── 4. Flow diagram ───────────────────────────────────────────────────────────
node_r = 5
c_x, s_x, t_x = 130, 400, 670
fc = fl_y

# Client
draw.ellipse([c_x - node_r, fc - node_r, c_x + node_r, fc + node_r], fill=C_FLOW_NODE)
draw.text((c_x - draw.textbbox((0, 0), "Client", font=flow_sm)[2] // 2, fc - 22),
          "Client", fill=C_FLOW_LABEL, font=flow_sm)

# Arrow 1
a1e = s_x - 78
draw.line([(c_x + node_r + 4, fc), (a1e, fc)], fill=C_FLOW_ARROW, width=2)
draw.polygon([(a1e, fc - 4), (a1e + 6, fc), (a1e, fc + 4)], fill=C_FLOW_ARROWHEAD)

# Server box
s_w, s_h = 152, 28
draw.rounded_rectangle(
    [(s_x - s_w // 2, fc - s_h // 2), (s_x + s_w // 2, fc + s_h // 2)],
    radius=5, outline=C_BOX, width=2
)
draw.text((s_x - draw.textbbox((0, 0), "wrongsv", font=flow_font)[2] // 2, fc - 8),
          "wrongsv", fill=C_FLOW_TEXT, font=flow_font)

# Arrow 2
a2s = s_x + s_w // 2 + 4
a2e = t_x - node_r - 4
draw.line([(a2s, fc), (a2e, fc)], fill=C_FLOW_ARROW, width=2)
draw.polygon([(a2e, fc - 4), (a2e + 6, fc), (a2e, fc + 4)], fill=C_FLOW_ARROWHEAD)

# Target
draw.ellipse([t_x - node_r, fc - node_r, t_x + node_r, fc + node_r], fill=C_FLOW_NODE)
draw.text((t_x - draw.textbbox((0, 0), "Target", font=flow_sm)[2] // 2, fc - 22),
          "Target", fill=C_FLOW_LABEL, font=flow_sm)

# ── Bottom divider ────────────────────────────────────────────────────────────
draw.line([(60, H - 2), (W - 60, H - 2)], fill=C_DIVIDER, width=1)

img.save(OUT)
print(f"Banner saved to {OUT} ({W}x{H})")
