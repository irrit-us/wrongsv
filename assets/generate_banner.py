"""Generate wrongsv header banner — RGB only, no alpha channel."""
from PIL import Image, ImageDraw, ImageFont
import os

W, H = 800, 200
OUT = os.path.join(os.path.dirname(__file__), "banner.png")

ACCENT = (124, 145, 219)
WHITE = (255, 255, 255)

def blend(pct):
    w = pct / 100.0
    return tuple(int(ACCENT[i] * w + WHITE[i] * (1 - w)) for i in range(3))

C_TITLE    = blend(100)
C_SUB      = blend(67)
C_KW       = blend(51)
C_FLOW_TEXT = blend(94)
C_FLOW_LABEL = blend(63)
C_FLOW_NODE = blend(90)
C_FLOW_ARROW = blend(39)
C_FLOW_ARROWHEAD = blend(63)
C_BOX = blend(67)
C_DIVIDER = blend(16)

img = Image.new("RGB", (W, H), WHITE)
draw = ImageDraw.Draw(img)

# ── Fonts (all +1 size) ───────────────────────────────────────────────────────
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

sub_font = ImageFont.truetype(mono_path, 15)   # was 14
kw_font = ImageFont.truetype(mono_path, 13)    # was 12
flow_font = ImageFont.truetype(mono_path, 14)  # was 13
flow_sm = ImageFont.truetype(mono_path, 12)    # was 11

# ── Measure ───────────────────────────────────────────────────────────────────
cx = W // 2

title = "wrongsv"
tb = draw.textbbox((0, 0), title, font=TITLE_FONT)
title_w = tb[2] - tb[0]
title_ext = tb[3]

subtitle = "VLESS proxy server"
sb = draw.textbbox((0, 0), subtitle, font=sub_font)
sub_w = sb[2] - sb[0]
sub_ext = sb[3]

keywords = "XTLS Vision  ·  REALITY  ·  AnyTLS  ·  ML-KEM-512  ·  AEAD"
kb = draw.textbbox((0, 0), keywords, font=kw_font)
kw_w = kb[2] - kb[0]
kw_ext = kb[3]

# ── Positions (recalculated for larger fonts) ─────────────────────────────────
title_y = 12
sub_y = 80
kw_y = 112
fl_y = 168   # flow center

# ── 1. Title ──────────────────────────────────────────────────────────────────
draw.text((cx - title_w // 2, title_y), title, fill=C_TITLE, font=TITLE_FONT)

# ── 2. Subtitle ───────────────────────────────────────────────────────────────
draw.text((cx - sub_w // 2, sub_y), subtitle, fill=C_SUB, font=sub_font)

# ── 3. Keywords ───────────────────────────────────────────────────────────────
draw.text((cx - kw_w // 2, kw_y), keywords, fill=C_KW, font=kw_font)

# ── 4. Flow diagram ───────────────────────────────────────────────────────────
node_r = 5
c_x = 130      # client node center
t_x = 670      # target node center
s_x = 400      # server box center
fc = fl_y      # center y for all flow elements

# --- Client node + label ---
draw.ellipse([c_x - node_r, fc - node_r, c_x + node_r, fc + node_r], fill=C_FLOW_NODE)
label_bbox = draw.textbbox((0, 0), "Client", font=flow_sm)
label_w = label_bbox[2] - label_bbox[0]
draw.text((c_x - label_w // 2, fc - 23), "Client", fill=C_FLOW_LABEL, font=flow_sm)

# --- Server box ---
s_w, s_h = 156, 30
box_left = s_x - s_w // 2
box_right = s_x + s_w // 2
box_top = fc - s_h // 2
box_bottom = fc + s_h // 2
draw.rounded_rectangle(
    [(box_left, box_top), (box_right, box_bottom)],
    radius=5, outline=C_BOX, width=2
)
# Center "wrongsv" both H and V within the box
st = "wrongsv"
st_bbox = draw.textbbox((0, 0), st, font=flow_font)
st_w = st_bbox[2] - st_bbox[0]
st_h = st_bbox[3] - st_bbox[1]
st_x = s_x - st_w // 2
st_y = fc - st_h // 2 - st_bbox[1]  # subtract bbox[1] to account for baseline offset
draw.text((st_x, st_y), st, fill=C_FLOW_TEXT, font=flow_font)

# --- Arrow 1: client → server (tip touches box edge) ---
a1_line_end = box_left - 9    # arrowhead tip lands at box_left - 2
draw.line([(c_x + node_r, fc), (a1_line_end, fc)], fill=C_FLOW_ARROW, width=2)
draw.polygon(
    [(a1_line_end, fc - 5), (a1_line_end + 7, fc), (a1_line_end, fc + 5)],
    fill=C_FLOW_ARROWHEAD
)

# --- Arrow 2: server → target (tip touches node edge) ---
a2_line_end = t_x - node_r - 7  # arrowhead tip lands at t_x - node_r - 1
draw.line([(box_right + 2, fc), (a2_line_end, fc)], fill=C_FLOW_ARROW, width=2)
draw.polygon(
    [(a2_line_end, fc - 5), (a2_line_end + 7, fc), (a2_line_end, fc + 5)],
    fill=C_FLOW_ARROWHEAD
)

# --- Target node + label ---
draw.ellipse([t_x - node_r, fc - node_r, t_x + node_r, fc + node_r], fill=C_FLOW_NODE)
target_bbox = draw.textbbox((0, 0), "Target", font=flow_sm)
draw.text((t_x - (target_bbox[2] - target_bbox[0]) // 2, fc - 23),
          "Target", fill=C_FLOW_LABEL, font=flow_sm)

# ── Bottom divider ────────────────────────────────────────────────────────────
draw.line([(60, H - 2), (W - 60, H - 2)], fill=C_DIVIDER, width=1)

img.save(OUT)
print(f"Banner saved to {OUT} ({W}x{H})")
print(f"  Arrow1: {c_x + node_r}->{a1_line_end} tip={a1_line_end+7}")
print(f"  Arrow2: {box_right + 2}->{a2_line_end} tip={a2_line_end+7}")
print(f"  Box: {box_left}-{box_right}, text center=({s_x},{fc})")
