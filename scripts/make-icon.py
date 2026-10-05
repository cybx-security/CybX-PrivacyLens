#!/usr/bin/env python3
"""Draws the PrivacyLens app icon and writes it in every format the build
needs: packaging/icon/icon.png (1024 px master), icon-256.png and icon.ico
(Windows), and icon.icns (macOS, via iconutil).

The artwork is a placeholder - a lens over lines of text, in the GUI's
colors. To use real brand artwork, replace icon.png with a square 1024 px
PNG and run this script with --from-png to regenerate the .ico and .icns.

Needs Pillow (pip install pillow); the .icns step needs macOS.
"""
import os
import shutil
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "packaging", "icon")
SIZE = 1024
SS = 4  # supersampling factor for smooth edges


def draw():
    n = SIZE * SS
    img = Image.new("RGBA", (n, n), (0, 0, 0, 0))

    # Background: rounded square, vertical gradient from the GUI accent blue
    # to a deeper navy.
    top, bottom = (11, 95, 255), (14, 48, 138)
    grad = Image.new("RGBA", (n, n))
    gd = ImageDraw.Draw(grad)
    for y in range(n):
        t = y / (n - 1)
        gd.line([(0, y), (n, y)], fill=tuple(round(a + (b - a) * t) for a, b in zip(top, bottom)) + (255,))
    mask = Image.new("L", (n, n), 0)
    pad = int(n * 0.06)
    ImageDraw.Draw(mask).rounded_rectangle([pad, pad, n - pad, n - pad], radius=int(n * 0.20), fill=255)
    img.paste(grad, (0, 0), mask)

    # "Document" lines behind the lens - the text being searched. Drawn on
    # an overlay and composited: drawing translucent shapes straight onto an
    # RGBA image replaces pixels instead of blending them.
    overlay = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    od = ImageDraw.Draw(overlay)
    lh = int(n * 0.035)
    for i, width in enumerate([0.50, 0.62, 0.44, 0.58, 0.36]):
        y = int(n * (0.24 + i * 0.105))
        od.rounded_rectangle([int(n * 0.20), y, int(n * (0.20 + width)), y + lh], radius=lh // 2, fill=(255, 255, 255, 85))
    img = Image.alpha_composite(img, overlay)

    d = ImageDraw.Draw(img)

    # The lens: white ring with a faint glass fill, and a handle.
    cx, cy, r = int(n * 0.45), int(n * 0.45), int(n * 0.215)
    ring = int(n * 0.058)
    hx0, hy0 = cx + int(r * 0.74), cy + int(r * 0.74)
    hx1, hy1 = int(n * 0.795), int(n * 0.795)
    d.line([(hx0, hy0), (hx1, hy1)], fill=(255, 255, 255, 255), width=int(n * 0.085))
    cap = int(n * 0.0425)
    d.ellipse([hx1 - cap, hy1 - cap, hx1 + cap, hy1 + cap], fill=(255, 255, 255, 255))
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(255, 255, 255, 255))
    inner = r - ring
    d.ellipse([cx - inner, cy - inner, cx + inner, cy + inner], fill=(20, 72, 190, 255))

    # Inside the lens the text is "found": two bright lines, one highlighted.
    hl = int(n * 0.042)
    d.rounded_rectangle([cx - int(inner * 0.60), cy - int(inner * 0.34), cx + int(inner * 0.60), cy - int(inner * 0.34) + hl],
                        radius=hl // 2, fill=(255, 255, 255, 235))
    d.rounded_rectangle([cx - int(inner * 0.60), cy + int(inner * 0.12), cx + int(inner * 0.22), cy + int(inner * 0.12) + hl],
                        radius=hl // 2, fill=(255, 196, 64, 255))

    return img.resize((SIZE, SIZE), Image.LANCZOS)


def main():
    os.makedirs(HERE, exist_ok=True)
    png = os.path.join(HERE, "icon.png")
    if "--from-png" in sys.argv:
        master = Image.open(png).convert("RGBA").resize((SIZE, SIZE), Image.LANCZOS)
    else:
        master = draw()
        master.save(png)

    # 256 px copy: the largest size a Windows icon holds, and what the
    # build embeds in the .exe files.
    master.resize((256, 256), Image.LANCZOS).save(os.path.join(HERE, "icon-256.png"))
    master.save(os.path.join(HERE, "icon.ico"),
                sizes=[(s, s) for s in (16, 20, 24, 32, 40, 48, 64, 128, 256)])

    if shutil.which("iconutil"):
        with tempfile.TemporaryDirectory() as tmp:
            iconset = os.path.join(tmp, "icon.iconset")
            os.makedirs(iconset)
            for pts in (16, 32, 128, 256, 512):
                master.resize((pts, pts), Image.LANCZOS).save(os.path.join(iconset, f"icon_{pts}x{pts}.png"))
                master.resize((pts * 2, pts * 2), Image.LANCZOS).save(os.path.join(iconset, f"icon_{pts}x{pts}@2x.png"))
            subprocess.run(["iconutil", "-c", "icns", iconset, "-o", os.path.join(HERE, "icon.icns")], check=True)
    else:
        print("iconutil not found (not macOS): icon.icns was not regenerated", file=sys.stderr)


if __name__ == "__main__":
    main()
