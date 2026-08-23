#!/usr/bin/env python3
"""Turn the app PNG into a Windows .ico, without Pillow.

An .ico is a small header plus a run of images, and PNG-compressed entries have
been legal since Vista - so the source PNG can be embedded as-is at each size
Windows asks for. We do not resample (that would need an image library); we
declare the sizes the PNG can honestly serve and let Windows scale the rest,
which it does well enough for a tray and title-bar icon.

Usage: make-icon.py icon.png nettool.ico
"""

import struct
import sys


def png_size(data):
    """(width, height) from the IHDR chunk."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise SystemExit("not a PNG file")
    width, height = struct.unpack(">II", data[16:24])
    return width, height


def build_ico(png, sizes):
    """ICONDIR + one ICONDIRENTRY per size, all pointing at the same PNG."""
    count = len(sizes)
    header = struct.pack("<HHH", 0, 1, count)          # reserved, type=icon, count
    offset = 6 + 16 * count
    entries = b""
    for size in sizes:
        # 0 means 256 in the byte-wide width/height fields.
        dimension = 0 if size >= 256 else size
        entries += struct.pack(
            "<BBBBHHII",
            dimension, dimension,
            0,          # palette colours: 0 for a PNG entry
            0,          # reserved
            1,          # colour planes
            32,         # bits per pixel
            len(png),
            offset,
        )
    return header + entries + png


def main(argv):
    if len(argv) != 2:
        raise SystemExit(__doc__)
    source, target = argv
    with open(source, "rb") as fh:
        png = fh.read()
    width, height = png_size(png)
    if width != height:
        raise SystemExit("icon source must be square, got %dx%d" % (width, height))
    sizes = [size for size in (16, 32, 48, 64, 128, 256) if size <= width] or [width]
    with open(target, "wb") as fh:
        fh.write(build_ico(png, sizes))
    print("wrote %s (%dx%d source, %d entries)" % (target, width, height, len(sizes)))


if __name__ == "__main__":
    main(sys.argv[1:])
