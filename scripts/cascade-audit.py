# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
"""Find declarations that can never apply, and breakpoints that miss real devices.

Not a general CSS engine. It answers two narrow questions that produced
every layout bug in this stylesheet so far:

  1. Is the same property set for the same selector in two different
     @layers?  Layer order beats specificity, so the one in the earlier
     layer is dead no matter how it reads.
  2. Does a max-width breakpoint fall inside the range of common phone
     widths, so that it looks like a mobile rule and is not one?
"""
import re
import sys
from collections import defaultdict

with open(sys.argv[1], encoding="utf-8") as f:
    src = f.read()

# Comments have to go before anything else looks at this. A /* ... */ sitting
# above a rule is otherwise swallowed into the selector buffer, and the rule
# is recorded under a selector made of prose — which is silent, and makes
# every finding near a comment wrong. Newlines are kept so reported line
# numbers still point at the real source.
def _strip_comments(text):
    out, i = [], 0
    while i < len(text):
        if text.startswith('/*', i):
            end = text.find('*/', i + 2)
            if end == -1:
                break
            out.append('\n' * text.count('\n', i, end))
            i = end + 2
        else:
            out.append(text[i])
            i += 1
    return ''.join(out)

src = _strip_comments(src)

# ── Walk the file, tracking the current @layer and @media ──────────────
# Layers are ordered by first declaration, and a file may declare them in
# several statements — reading only the first gets the order backwards for
# every layer named later.
layer_order = []
for m in re.finditer(r'@layer ([a-z.,\s]+);', src):
    for name in m.group(1).split(','):
        name = name.strip()
        if name and name not in layer_order:
            layer_order.append(name)

rules = []           # (layer, media, selector, prop, value, line)
layer_stack, media_stack = [], []
depth_stack = []
line_no = 1
i = 0
buf = ''
while i < len(src):
    ch = src[i]
    if ch == '\n':
        line_no += 1
    if ch == '{':
        head = buf.strip()
        buf = ''
        if head.startswith('@layer'):
            name = head[6:].strip()
            layer_stack.append(name)
            depth_stack.append('layer')
        elif head.startswith('@media'):
            media_stack.append(head[6:].strip())
            depth_stack.append('media')
        elif head.startswith(('@supports', '@page')):
            depth_stack.append('at')
        else:
            depth_stack.append(('sel', head))
    elif ch == '}':
        if depth_stack:
            top = depth_stack.pop()
            if top == 'layer' and layer_stack:
                layer_stack.pop()
            elif top == 'media' and media_stack:
                media_stack.pop()
        buf = ''
    elif ch == ';':
        decl = buf.strip()
        buf = ''
        if ':' in decl and depth_stack and isinstance(depth_stack[-1], tuple):
            sel = depth_stack[-1][1]
            prop, _, val = decl.partition(':')
            rules.append((
                '.'.join(layer_stack) or '(unlayered)',
                ' and '.join(media_stack),
                sel.strip(), prop.strip(), val.strip(), line_no))
    else:
        buf += ch
    i += 1

def rank(layer):
    if layer == '(unlayered)':
        return 999            # unlayered beats every layer
    for n, name in enumerate(layer_order):
        if layer == name:
            return n
    return -1

# ── 1. Same selector + property, different layers ──────────────────────
by_key = defaultdict(list)
for layer, media, sel, prop, val, ln in rules:
    for one in [x.strip() for x in sel.split(',')]:
        by_key[(one, prop, media)].append((layer, val, ln))

print("── Declarations overridden across @layer ──────────────────────────")
dead = 0
for (sel, prop, media), hits in sorted(by_key.items()):
    layers = {h[0] for h in hits}
    if len(layers) < 2:
        continue
    # Within one layer the cascade falls back to source order for equal
    # specificity, so ranking by layer alone reports the wrong winner for
    # two rules in the same layer — which is most of the unlayered tail.
    ranked = sorted(hits, key=lambda h: (rank(h[0]), h[2]))
    winner = ranked[-1]
    losers = [h for h in ranked[:-1] if h[1] != winner[1]]
    if not losers:
        continue
    dead += len(losers)
    where = f" @media {media}" if media else ""
    print(f"\n  {sel} {{ {prop} }}{where}")
    for lay, val, ln in losers:
        print(f"     dead  L{ln:<5} {lay:<18} {prop}: {val}")
    print(f"     wins  L{winner[2]:<5} {winner[0]:<18} {prop}: {winner[1]}")
print(f"\n  {dead} dead declaration(s)\n")

# ── 2. Breakpoints that miss real phones ───────────────────────────────
PHONES = [(320,'small'),(360,'Android'),(375,'iPhone SE/13 mini'),(390,'iPhone 14'),
          (393,'Pixel'),(414,'iPhone Plus'),(430,'iPhone Pro Max')]
print("── max-width breakpoints vs real device widths ────────────────────")
seen = set()
for mq in sorted({r[1] for r in rules if r[1]}):
    for val, unit in re.findall(r'max-width:\s*([\d.]+)(rem|px)', mq):
        px = float(val) * (16 if unit == 'rem' else 1)
        if px in seen:
            continue
        seen.add(px)
        missed = [n for w, n in PHONES if w > px]
        flag = "  <-- misses " + ", ".join(missed) if missed else ""
        print(f"  {val}{unit} = {px:.0f}px{flag}")
