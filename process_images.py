#!/usr/bin/env python3
"""Process and optimise approved stone photography for Alpha Surfaces site."""

import json
import os
from pathlib import Path
from PIL import Image

SRC = Path(os.path.expanduser("~/Downloads/00_Imagery_approved by Bel"))
SITE = Path("/Users/seanstone/Downloads/alpha-surfaces-site/public")
OUT = SITE / "images" / "stones"
GALLERY_OUT = OUT / "gallery"

OUT.mkdir(parents=True, exist_ok=True)
GALLERY_OUT.mkdir(parents=True, exist_ok=True)

# ── Stone inventory ──
STONES = {
    "autumn-gold": {
        "files": ["Autumn Gold_Collection 05/Autumn Gold_Collection 05.jpg"],
    },
    "calacatta-leggera": {
        "files": [
            "Calacatta Leggera_Collection 04/Bianco_Caloundra, Qld Development/0G0A4078.jpg",
            "Calacatta Leggera_Collection 04/Bianco_Caloundra, Qld Development/0G0A4083.jpg",
            "Calacatta Leggera_Collection 04/Bianco_Caloundra, Qld Development/0G0A4096.jpg",
            "Calacatta Leggera_Collection 04/Bianco_Caloundra, Qld Development/0G0A4119.jpg",
            "Calacatta Leggera_Collection 04/Bianco_Caloundra, Qld Development/0G0A4161.jpg",
            "Calacatta Leggera_Collection 04/Bianco_Caloundra, Qld Development/0G0A4188.jpg",
            "Calacatta Leggera_Collection 04/Bianco_Caloundra, Qld Development/0G0A4197.jpg",
            "Calacatta Leggera_Collection 04/Bianco_Caloundra, Qld Development/0G0A4213.jpg",
            "Calacatta Leggera_Collection 04/Bianco_Caloundra, Qld Development/0G0A4215.jpg",
            "Calacatta Leggera_Collection 04/Bianco_Caloundra, Qld Development/0G0A4241.jpg",
        ],
    },
    "calacatta-viola": {
        "files": ["Calacatta Viola_Collection 05/Calacatta Viola_270226.jpg"],
    },
    "carrara": {
        "files": ["Carrara_Collection 02/CARARRA.jpg"],
    },
    "davinci-gris": {
        "files": ["Davinci Gris_Collection 03/Davinci Gris.jpeg"],
    },
    "opal-mist": {
        "files": ["Opal Mist_Collection 04/Opal Mist_Final.jpg"],
    },
    "patagonia": {
        "files": [
            "Patagonia_Zero/0G0A3946.jpg",
            "Patagonia_Zero/0G0A3952.jpg",
            "Patagonia_Zero/0G0A3955.jpg",
        ],
    },
    "statuario-gold": {
        "files": ["Statuario Gold_Collection 04/STATUARIO GOLD.jpg"],
    },
    "taj-mahal": {
        "files": [
            "Taj Mahal_Zero/Cogill Road Buderim_Taj Mahal/0G0A4955.jpg",
            "Taj Mahal_Zero/Cogill Road Buderim_Taj Mahal/0G0A4961.jpg",
            "Taj Mahal_Zero/Cogill Road Buderim_Taj Mahal/0G0A4973-Edit.jpg",
            "Taj Mahal_Zero/Cogill Road Buderim_Taj Mahal/0G0A4977.jpg",
            "Taj Mahal_Zero/Cogill Road Buderim_Taj Mahal/0G0A4992.jpg",
            "Taj Mahal_Zero/Cogill Road Buderim_Taj Mahal/0G0A5000.jpg",
            "Taj Mahal_Zero/Cogill Road Buderim_Taj Mahal/0G0A5054.jpg",
            "Taj Mahal_Zero/Cogill Road Buderim_Taj Mahal/0G0A5056.jpg",
            "Taj Mahal_Zero/Cogill Road Buderim_Taj Mahal/0G0A5057.jpg",
            "Taj Mahal_Zero/Cogill Road Buderim_Taj Mahal/0G0A5058.jpg",
            "Taj Mahal_Zero/Cogill Road Buderim_Taj Mahal/0G0A5060.jpg",
            "Taj Mahal_Zero/Cogill Road Buderim_Taj Mahal/0G0A5061.jpg",
            "Taj Mahal_Zero/Cogill Road Buderim_Taj Mahal/0G0A5071.jpg",
            "Taj Mahal_Zero/Cogill Road Buderim_Taj Mahal/0G0A5073.jpg",
            "Taj Mahal_Zero/Cogill Road Buderim_Taj Mahal/0G0A5074.jpg",
        ],
    },
    "whitehaven": {
        "files": [
            "Whitehaven_Collection 03-Indoor-Outdoor/0G0A4046.jpg",
            "Whitehaven_Collection 03-Indoor-Outdoor/0G0A4048-Edit.jpg",
            "Whitehaven_Collection 03-Indoor-Outdoor/0G0A4050-Edit.jpg",
            "Whitehaven_Collection 03-Indoor-Outdoor/0G0A4054.jpg",
            "Whitehaven_Collection 03-Indoor-Outdoor/0G0A4063-Edit V2.jpg",
            "Whitehaven_Collection 03-Indoor-Outdoor/0G0A4063-Edit.jpg",
        ],
    },
}


def fmt_size(b):
    if b < 1024:
        return f"{b}B"
    if b < 1024 * 1024:
        return f"{b / 1024:.1f}KB"
    return f"{b / (1024 * 1024):.1f}MB"


def process_image(src_path, dest_path, max_width, quality):
    """Resize, strip EXIF, convert to WebP."""
    img = Image.open(src_path)
    # Convert to RGB if needed (handles CMYK, RGBA, palette)
    if img.mode not in ("RGB",):
        img = img.convert("RGB")

    # Resize if wider than max
    w, h = img.size
    if w > max_width:
        ratio = max_width / w
        new_h = int(h * ratio)
        img = img.resize((max_width, new_h), Image.LANCZOS)

    img.save(dest_path, "WEBP", quality=quality)
    return os.path.getsize(src_path), os.path.getsize(dest_path), img.size


def main():
    total_before = 0
    total_after = 0
    files_processed = 0
    updates = {}  # slug -> {image, thumbnail, gallery}

    print("=" * 70)
    print("ALPHA SURFACES — IMAGE PROCESSING")
    print("=" * 70)

    for slug, info in STONES.items():
        files = info["files"]
        has_gallery = len(files) > 1

        print(f"\n{'─' * 50}")
        print(f"  {slug.upper().replace('-', ' ')}  ({len(files)} file{'s' if len(files) > 1 else ''})")
        print(f"{'─' * 50}")

        stone_update = {}
        gallery_paths = []

        for i, rel in enumerate(files):
            src_path = SRC / rel

            if not src_path.exists():
                print(f"  ✗ MISSING: {rel}")
                continue

            ext = src_path.suffix.lower()
            if ext in (".tif", ".tiff", ".pdf"):
                print(f"  ⊘ SKIPPED (unsupported): {src_path.name}")
                continue

            if i == 0:
                # ── Hero (1920px, q85) ──
                hero_dest = OUT / f"{slug}.webp"
                before, after, dims = process_image(src_path, hero_dest, 1920, 85)
                total_before += before
                total_after += after
                files_processed += 1
                print(f"  ✓ hero     {src_path.name}")
                print(f"             {dims[0]}×{dims[1]}  {fmt_size(before)} → {fmt_size(after)}  ({100 - after / before * 100:.0f}% smaller)")
                stone_update["image"] = f"/images/stones/{slug}.webp"

                # ── Thumbnail (600px, q80) ──
                thumb_dest = OUT / f"{slug}-thumb.webp"
                tb, ta, td = process_image(src_path, thumb_dest, 600, 80)
                total_after += ta
                files_processed += 1
                print(f"  ✓ thumb    {slug}-thumb.webp")
                print(f"             {td[0]}×{td[1]}  → {fmt_size(ta)}")
                stone_update["thumbnail"] = f"/images/stones/{slug}-thumb.webp"

                if has_gallery:
                    gallery_paths.append(f"/images/stones/gallery/{slug}-1.webp")
                    gal_dest = GALLERY_OUT / f"{slug}-1.webp"
                    gb, ga, gd = process_image(src_path, gal_dest, 1200, 85)
                    total_after += ga
                    files_processed += 1
                    print(f"  ✓ gallery  {slug}-1.webp")
                    print(f"             {gd[0]}×{gd[1]}  → {fmt_size(ga)}")
            else:
                # ── Gallery images (1200px, q85) ──
                gal_idx = i + 1
                gal_dest = GALLERY_OUT / f"{slug}-{gal_idx}.webp"
                before, after, dims = process_image(src_path, gal_dest, 1200, 85)
                total_before += before
                total_after += after
                files_processed += 1
                gallery_paths.append(f"/images/stones/gallery/{slug}-{gal_idx}.webp")
                print(f"  ✓ gallery  {slug}-{gal_idx}.webp")
                print(f"             {dims[0]}×{dims[1]}  {fmt_size(before)} → {fmt_size(after)}  ({100 - after / before * 100:.0f}% smaller)")

        if gallery_paths:
            stone_update["gallery"] = gallery_paths

        updates[slug] = stone_update

    # ── Update stones.json ──
    print(f"\n{'=' * 70}")
    print("UPDATING stones.json")
    print(f"{'=' * 70}")

    json_path = SITE / "data" / "stones.json"
    with open(json_path) as f:
        data = json.load(f)

    matched = 0
    for collection in data["collections"]:
        for stone in collection["stones"]:
            if stone["slug"] in updates:
                upd = updates[stone["slug"]]
                for key, val in upd.items():
                    stone[key] = val
                matched += 1
                print(f"  ✓ {stone['slug']}: image={upd.get('image', '—')}")

    with open(json_path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

    print(f"\n  Updated {matched} stones in stones.json")

    # ── Summary ──
    print(f"\n{'=' * 70}")
    print("SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Files processed:  {files_processed}")
    print(f"  Source total:      {fmt_size(total_before)}")
    print(f"  Output total:     {fmt_size(total_after)}")
    if total_before > 0:
        print(f"  Reduction:        {100 - total_after / total_before * 100:.0f}%")
    print(f"  Stones updated:   {matched}")
    print()


if __name__ == "__main__":
    main()
