# Prompt 03: Slab & Swatch Image Overhaul
**Priority:** HIGH
**Run from:** `~/Downloads/alpha-surfaces-site/`
**Depends on:** Prompt 01 (stones.json updated to 47 stones — includes 5 new C05 stones, moves, and removals)

---

## Context

Belinda has provided hi-res slab and close-up images in a Dropbox download. All images have been copied into the `assets/` folder within this repo:
- `assets/slabs-closeups-2026/` — RGB slab and close-up images by collection (e.g., "Collection 01-Jewel-SLAB.jpg")

Additional Alpha Zero assets:
- `assets/missing-swatches/` — 7 hi-res swatches (acropolis, calacatta-borghini, elba, glacier-grey, mont-blanc, serena, unique-carrara)
- `assets/alpha-zero-swatches/` — 8 Alpha Zero swatches (Acropolis, Basaltina, Calacatta Oro, Carbon, Glacier Grey, Grande Glacier, Serena, Silver Travertine)
- `assets/slabs-closeups-2026/27.AU71149-SLABCALACATTA-BORGHINI-scaled.jpg` — loose slab image

### Image specifications for the site:
| Image Type | Filename Pattern | Target Size | Format |
|-----------|-----------------|-------------|--------|
| Hero | `{slug}.webp` | ~800×571 | WebP |
| Thumbnail | `{slug}-thumb.webp` | ~400×286 | WebP |
| Swatch (close-up) | `{slug}-swatch.webp` | ~800×571 or 300×300 | WebP |
| Slab (full view) | `{slug}-slab.webp` | ~1579×789 | WebP |

## What to Do

### Step 1: Audit the new image folder
```bash
find assets/slabs-closeups-2026/ -type f \( -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" -o -name "*.webp" \) | sort
```

List every file with its dimensions:
```bash
find assets/slabs-closeups-2026/ -type f \( -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" \) -exec sh -c 'echo "$(identify -format "%wx%h" "$1" 2>/dev/null || echo "???") $1"' _ {} \;
```

If `identify` (ImageMagick) is not installed:
```bash
python3 -c "
from PIL import Image
import os, glob
folder = 'assets/slabs-closeups-2026/'
for root, dirs, files in os.walk(folder):
    for f in sorted(files):
        if f.lower().endswith(('.jpg','.jpeg','.png','.webp')):
            path = os.path.join(root, f)
            try:
                img = Image.open(path)
                print(f'{img.size[0]}x{img.size[1]:4d}  {path}')
            except: print(f'ERROR     {path}')
"
```

### Step 2: Map images to stones

Create a mapping of each image file to the stone it belongs to. The slug format used in the site is lowercase-hyphenated (e.g., "Calacatta Leggera" → "calacatta-leggera").

For each stone currently in stones.json (47 total), determine:
- Does a NEW slab image exist in the Dropbox folder? → Process as `{slug}-slab.webp`
- Does a NEW close-up/swatch image exist? → Process as `{slug}-swatch.webp`
- Is the current swatch actually just the hero image? → Replace with the real swatch

**IMPORTANT — NEW C05 STONES:** 5 brand new stones were added to Collection 05 (Perla Mahal, Emerald Haze, Viola Ligerra, Crystal Mahal, Venato). Check the Dropbox folder for images of these stones. Also check for Taj Mahal images (moved from Alpha Zero to C05 — may need its images recategorised). If images don't exist yet for these stones, flag them with `"images_pending": true` in stones.json.

**IMPORTANT — ARABESCATO:** Moved from C05 to C04. Existing images should still work but verify the paths are correct after the collection change.

### Step 3: Process images

For each new image, convert to WebP at the target dimensions:

```python
from PIL import Image
import os

def process_image(input_path, output_path, target_width, target_height):
    img = Image.open(input_path)
    img = img.resize((target_width, target_height), Image.LANCZOS)
    img.save(output_path, 'WEBP', quality=85)
    print(f"  Saved: {output_path} ({target_width}x{target_height})")

# Example for a slab image:
# process_image('assets/slabs-closeups-2026/Collection 01-Jewel-SLAB.jpg',
#               'public/images/stones/jewel-slab.webp', 1579, 789)
```

**Important:** Maintain aspect ratio. If the source image has a different aspect ratio than the target, crop to fill (center crop) rather than stretching.

### Step 4: Process Alpha Zero images

For the Alpha Zero stones that remain on the site (10 stones per updated spreadsheet):

1. Check existing swatches — many currently use the hero image as swatch (flagged with ⚠️ in the completion report)
2. Process available real swatches:
   - From `assets/missing-swatches/`: acropolis, calacatta-borghini, elba, glacier-grey, mont-blanc, serena, unique-carrara
   - From `assets/alpha-zero-swatches/`: Basaltina, Calacatta Oro, Carbon, Grande Glacier, Silver Travertine (plus Acropolis, Glacier Grey, Serena duplicates)
3. For Calacatta Oro: check if the 500×500 version from the GDrive folder is usable (it was noted as very small at 9KB)

### Step 5: Update stones.json image paths

For every stone where you've added or replaced an image, update the corresponding field in `stones.json`:
- `swatch` → point to the new `{slug}-swatch.webp` (not the hero image)
- `slab` → point to the new `{slug}-slab.webp`

### Step 6: Handle missing slab images

For Alpha Zero stones where no slab image exists:
- Add a field `"has_slab": false` to those stones in stones.json
- In the stone detail page template, conditionally hide the "View Full Slab" toggle/button when `has_slab` is false
- OR display a message: "Full slab image not available for discontinued colours"

### Step 7: Verify all images load
```bash
# Check that every image path in stones.json points to an actual file
python3 -c "
import json, os
with open('public/data/stones.json') as f:
    data = json.load(f)
missing = []
for s in data['stones']:
    for img_type in ['hero','thumb','swatch','slab']:
        path = s.get(img_type, s.get(f'{img_type}_image', ''))
        if path:
            full = 'public' + path if path.startswith('/') else f'public/images/stones/{path}'
            if not os.path.exists(full):
                missing.append(f\"{s['name']} ({img_type}): {full}\")
if missing:
    print(f'MISSING {len(missing)} images:')
    for m in missing: print(f'  {m}')
else:
    print('All image paths resolve to actual files.')
"
```

### Step 8: Commit
```bash
git add public/images/stones/ public/data/stones.json
git diff --cached --stat
git commit -m "feat: replace slab/swatch images with hi-res versions from Belinda's Dropbox delivery"
```
