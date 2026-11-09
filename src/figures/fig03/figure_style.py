"""Figure 1 style tokens reused for Figure 2, without modifying Figure 1.

Source: ../fig01/working/build_final.py (read-only).
All geometry and font sizes use points; the physical width is 170 mm.
"""

WIDTH_MM = 170
WIDTH_PT = WIDTH_MM / 25.4 * 72
FONT_FAMILY = "Nimbus Sans"
REGULAR_FONT = "<PROJECT_ROOT>/fonts/NimbusSans-Regular.otf"
BOLD_FONT = "<PROJECT_ROOT>/fonts/NimbusSans-Bold.otf"
MIN_FONT_PT = 8.0
INK = "#20262B"
GRAY = "#737A80"
LIGHT = "#F4F5F6"
BLUE = "#0072B2"  # Okabe–Ito blue, the code/dependencies family in Figure 1.


def tint(hex_color, strength):
    rgb = [int(hex_color[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round((1-strength)*255+strength*v):02x}" for v in rgb)
