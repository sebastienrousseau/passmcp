#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail

# Regenerate the raster icons from brand/icon.svg.
#
# The output is committed rather than built, so neither the site build nor
# CI needs ImageMagick — they only copy. Run this when the mark changes,
# which is approximately never, and commit what it writes.
#
# Requires: ImageMagick (brew install imagemagick).

cd "$(git rev-parse --show-toplevel)"

command -v magick >/dev/null || {
  echo "ImageMagick is missing. brew install imagemagick" >&2; exit 1; }

SRC=brand/icon.svg
MASK=brand/icon-maskable.svg
OUT=brand

# favicon.ico carries three sizes in one file. 16 and 32 are what a tab and
# a bookmark bar ask for; 48 is what Windows shortcuts use.
magick -background none "$SRC" -resize 16x16 "$OUT/f16.png"
magick -background none "$SRC" -resize 32x32 "$OUT/f32.png"
magick -background none "$SRC" -resize 48x48 "$OUT/f48.png"
magick "$OUT/f16.png" "$OUT/f32.png" "$OUT/f48.png" "$OUT/favicon.ico"
rm -f "$OUT/f16.png" "$OUT/f32.png" "$OUT/f48.png"

# iOS composites a transparent icon onto black and ignores rounding, so the
# touch icon gets the opaque variant.
magick -background none "$MASK" -resize 180x180 "$OUT/apple-touch-icon.png"

# Manifest icons. The maskable one is opaque because a launcher crops it to
# whatever shape the platform likes.
magick -background none "$SRC" -resize 192x192 "$OUT/icon-192.png"
magick -background none "$SRC" -resize 512x512 "$OUT/icon-512.png"
magick -background none "$MASK" -resize 512x512 "$OUT/icon-maskable-512.png"

# The scalable one browsers prefer when they support it.
cp "$SRC" "$OUT/favicon.svg"

echo "wrote:"
ls -1 "$OUT" | sed 's/^/  /'
