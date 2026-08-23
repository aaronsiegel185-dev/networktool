#!/usr/bin/env python3
"""Render the nettool app icon (a 1024x1024 PNG) with no third-party libraries.

`build-app.sh` turns this into an .icns with sips/iconutil on macOS. Regenerate with:

    python3 gui/macos/make-icon.py gui/macos/icon.png
"""

import math
import struct
import sys
import zlib

SIZE = 1024
SUPERSAMPLE = 3          # rendered at 3x then box-filtered, which is our anti-aliasing

BG_TOP = (28, 33, 40)
BG_BOTTOM = (16, 19, 24)
ACCENT = (110, 195, 255)
ACCENT_DIM = (72, 132, 178)
NODE = (235, 245, 255)


def write_png(path, width, height, pixels):
    """pixels: flat bytearray of RGBA rows."""
    raw = bytearray()
    stride = width * 4
    for y in range(height):
        raw.append(0)                       # filter type 0
        raw.extend(pixels[y * stride:(y + 1) * stride])

    def chunk(tag, data):
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    with open(path, "wb") as fh:
        fh.write(b"\x89PNG\r\n\x1a\n")
        fh.write(chunk(b"IHDR", header))
        fh.write(chunk(b"IDAT", zlib.compress(bytes(raw), 9)))
        fh.write(chunk(b"IEND", b""))


def rounded_rect_contains(x, y, size, radius):
    inner_min = radius
    inner_max = size - radius
    cx = min(max(x, inner_min), inner_max)
    cy = min(max(y, inner_min), inner_max)
    return (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2


def blend(base, colour, alpha):
    return tuple(int(round(base[i] * (1 - alpha) + colour[i] * alpha)) for i in range(3))


def render():
    size = SIZE * SUPERSAMPLE
    radius = int(size * 0.22)
    pixels = bytearray(size * size * 4)

    origin_x = size / 2.0
    origin_y = size * 0.78                  # arcs radiate from a node near the bottom
    node_radius = size * 0.052
    arcs = [(size * 0.17, ACCENT_DIM), (size * 0.30, ACCENT), (size * 0.43, ACCENT)]
    thickness = size * 0.055

    for y in range(size):
        gradient = y / float(size - 1)
        row_bg = blend(BG_TOP, BG_BOTTOM, gradient)
        for x in range(size):
            index = (y * size + x) * 4
            if not rounded_rect_contains(x + 0.5, y + 0.5, size, radius):
                pixels[index + 3] = 0
                continue
            colour = row_bg
            dx = x + 0.5 - origin_x
            dy = y + 0.5 - origin_y
            distance = math.hypot(dx, dy)
            if distance <= node_radius:
                colour = NODE
            else:
                angle = math.degrees(math.atan2(-dy, dx))     # 90 deg = straight up
                if 32 <= angle <= 148:
                    for arc_radius, arc_colour in arcs:
                        if abs(distance - arc_radius) <= thickness / 2:
                            fade = 1.0 - (abs(angle - 90) / 58.0) * 0.35
                            colour = blend(row_bg, arc_colour, max(0.0, min(1.0, fade)))
                            break
            pixels[index] = colour[0]
            pixels[index + 1] = colour[1]
            pixels[index + 2] = colour[2]
            pixels[index + 3] = 255
    return downsample(pixels, size, SUPERSAMPLE)


def downsample(pixels, size, factor):
    out_size = size // factor
    out = bytearray(out_size * out_size * 4)
    area = factor * factor
    for y in range(out_size):
        for x in range(out_size):
            totals = [0, 0, 0, 0]
            for sy in range(factor):
                row = (y * factor + sy) * size
                for sx in range(factor):
                    index = (row + x * factor + sx) * 4
                    totals[0] += pixels[index]
                    totals[1] += pixels[index + 1]
                    totals[2] += pixels[index + 2]
                    totals[3] += pixels[index + 3]
            index = (y * out_size + x) * 4
            for channel in range(4):
                out[index + channel] = totals[channel] // area
    return out


def main(argv):
    path = argv[1] if len(argv) > 1 else "icon.png"
    write_png(path, SIZE, SIZE, render())
    print("wrote %s (%dx%d)" % (path, SIZE, SIZE))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
