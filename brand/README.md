<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Brand assets

`icon.svg` is passmcp's flame on a square canvas. The paths are the mark from
`.github/logo.svg`, unmodified — only the framing is new, so the two files
cannot drift in shape. `icon-maskable.svg` is the same on an opaque ground,
for the places that composite an icon onto black or crop it to a shape.

Everything else here is generated from those two by
`scripts/gen-icons.sh`, which needs ImageMagick:

```sh
./scripts/gen-icons.sh
```

## Why the output is committed

`ssg` wipes its output directory on every build, so an icon committed inside
`internal/web/dist` is destroyed the next time it is built. The files live
here instead and the build copies them in, which also means CI needs no
ImageMagick. satellion.com copies the same files into satellion.com from
the passmcp release it builds against.

| File | Where it is used |
|---|---|
| `favicon.ico` | 16, 32 and 48 in one file — tabs, bookmarks, Windows shortcuts |
| `favicon.svg` | browsers that prefer a scalable icon |
| `apple-touch-icon.png` | 180×180, opaque: iOS composites transparency onto black |
| `icon-192.png`, `icon-512.png` | web app manifest |
| `icon-maskable-512.png` | launchers that crop an icon to their own shape |
