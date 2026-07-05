import io
import os
from typing import Optional

from PIL import Image, ImageDraw, ImageFont

WIDTH, HEIGHT = 1200, 630

# Using standard fonts available or falling back
# Windows standard fonts
FONT_DIR = os.environ.get("FONT_DIR", "C:/Windows/Fonts")
FONT_BOLD = os.path.join(FONT_DIR, "segoeuib.ttf")
FONT_REG = os.path.join(FONT_DIR, "segoeui.ttf")

# ── Palette (institutional blue + emerald "verified" accent) ──
BG_TOP = (4, 28, 58)
BG_BOTTOM = (12, 74, 132)
ACCENT = (16, 185, 129)
WHITE = (255, 255, 255)
MUTED = (183, 205, 232)
LABEL = (150, 182, 220)

MARGIN = 72


def _get_font(path: str, size: int) -> Optional[ImageFont.FreeTypeFont]:
    try:
        return ImageFont.truetype(path, size)
    except Exception:
        # Fallback to default if font not found
        return ImageFont.load_default()


def _draw_tracked(draw, pos, text, font, fill, tracking):
    """Draw text with manual letter-spacing for a premium, kerned look."""
    x, y = pos
    if not isinstance(font, ImageFont.FreeTypeFont):
        # Fallback to normal text if not freetype
        draw.text((x, y), text, font=font, fill=fill)
        return

    for ch in text:
        draw.text((x, y), ch, font=font, fill=fill, anchor="lm")
        x += draw.textlength(ch, font=font) + tracking


def generate_dynamic_og_image(course_name: Optional[str] = None, student_name: Optional[str] = None) -> bytes:
    """Generate a dynamic Open Graph image (1200x630 PNG) as bytes.
    
    If course_name and student_name are provided, they are rendered dynamically.
    Otherwise, generic placeholders are used.
    """
    img = Image.new("RGB", (WIDTH, HEIGHT), BG_TOP)
    draw = ImageDraw.Draw(img, "RGBA")

    # Vertical gradient background.
    for y in range(HEIGHT):
        t = y / (HEIGHT - 1)
        draw.line(
            [(0, y), (WIDTH, y)],
            fill=tuple(int(BG_TOP[i] + (BG_BOTTOM[i] - BG_TOP[i]) * t) for i in range(3)),
        )

    # Decorative translucent concentric rings (subtle depth, right side).
    for radius, alpha in [(380, 14), (290, 20), (200, 26)]:
        draw.ellipse(
            [WIDTH - 150 - radius, 300 - radius, WIDTH - 150 + radius, 300 + radius],
            outline=(255, 255, 255, alpha),
            width=2,
        )

    # Top institutional label (letter-spaced).
    _draw_tracked(
        draw,
        (MARGIN, 86),
        "UTN · FACULTAD REGIONAL TUCUMÁN",
        _get_font(FONT_BOLD, 26),
        LABEL,
        tracking=3,
    )

    # "Verified" badge: emerald circle with a white check.
    cx, cy, r = 150, 300, 66
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=ACCENT)
    draw.line(
        [(cx - 30, cy + 4), (cx - 8, cy + 26), (cx + 32, cy - 24)],
        fill=WHITE,
        width=15,
        joint="curve",
    )

    hx = 252

    # Dynamic text injection
    if course_name and student_name:
        # Dynamic course and student
        # We need to truncate course_name if it is too long
        truncated_course = course_name if len(course_name) < 40 else course_name[:37] + "..."
        draw.text((hx, 242), truncated_course, font=_get_font(FONT_BOLD, 64), fill=WHITE, anchor="lm")
        draw.text((hx, 322), student_name, font=_get_font(FONT_BOLD, 48), fill=MUTED, anchor="lm")
        draw.text((hx, 382), "Credencial Verificada", font=_get_font(FONT_BOLD, 36), fill=WHITE, anchor="lm")
        underline_w = 400
        draw.rounded_rectangle([hx, 416, hx + underline_w, 424], radius=4, fill=ACCENT)
    else:
        # Generic text
        draw.text((hx, 242), "Credencial", font=_get_font(FONT_BOLD, 92), fill=WHITE, anchor="lm")
        draw.text((hx, 342), "Verificada", font=_get_font(FONT_BOLD, 92), fill=WHITE, anchor="lm")
        # Try to calculate underline width
        font_b = _get_font(FONT_BOLD, 92)
        if isinstance(font_b, ImageFont.FreeTypeFont):
            underline_w = draw.textlength("Verificada", font=font_b)
        else:
            underline_w = 400
        draw.rounded_rectangle([hx, 396, hx + underline_w, 404], radius=4, fill=ACCENT)

    # Subline.
    draw.text(
        (hx, 464 if (course_name and student_name) else 444),
        "Respaldada en blockchain pública · Hyperledger Besu",
        font=_get_font(FONT_REG, 33),
        fill=MUTED,
        anchor="lm",
    )

    # Divider + footer.
    draw.line([(MARGIN, 536), (WIDTH - MARGIN, 536)], fill=(255, 255, 255, 45), width=2)
    draw.text(
        (MARGIN, 578),
        "portal-credenciales.utnpf.site",
        font=_get_font(FONT_BOLD, 30),
        fill=WHITE,
        anchor="lm",
    )
    draw.text(
        (WIDTH - MARGIN, 578),
        "Microcredenciales · Verificación pública",
        font=_get_font(FONT_REG, 26),
        fill=MUTED,
        anchor="rm",
    )

    buffer = io.BytesIO()
    img.save(buffer, format="PNG", optimize=True)
    return buffer.getvalue()
