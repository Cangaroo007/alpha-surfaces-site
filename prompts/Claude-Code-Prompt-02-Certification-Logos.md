# Prompt 02: Certification Logos
**Priority:** HIGH
**Run from:** `~/Downloads/alpha-surfaces-site/`
**Depends on:** Prompt 01 (stones.json updated)

---

## Context

Alpha Surfaces has certification logos that need to appear on stone detail pages and the quality assurance sections. Belinda has sent 3 logo folders and the 4th (EPD) needs to be downloaded from the certification body's website.

## Asset Locations

The certification logo folders are in `assets/certification-logos/` within this repo:

1. `assets/certification-logos/kosher/` — Kosher certification (contains .ai and .png)
2. `assets/certification-logos/greenguard/` — UL Greenguard certification (contains .svg and .png)
3. `assets/certification-logos/nsf/` — NSF International certification (contains .ai and .png)
4. EPD logo — download from: https://www.environdec.com/resources/brand-assets

## What to Do

### Step 1: Inventory the logo files
```bash
echo "=== Kosher ===" && ls -la assets/certification-logos/kosher/
echo "=== UL Greenguard ===" && ls -la assets/certification-logos/greenguard/
echo "=== NSF ===" && ls -la assets/certification-logos/nsf/
```

Look for SVG or high-res PNG files. Prefer SVG if available (scalable, no quality loss). If only EPS or AI files, convert to SVG using Inkscape or similar.

### Step 2: Download the EPD logo
Visit https://www.environdec.com/resources/brand-assets and download the EPD (Environmental Product Declaration) logo. Save to `assets/certification-logos/epd/`.

If you cannot download it programmatically, note this as a manual step for Sean.

### Step 3: Create the certifications directory
```bash
mkdir -p public/images/certifications/
```

### Step 4: Process and copy logos

For each logo:
- If SVG: copy directly to `public/images/certifications/`
- If PNG/JPG: optimise and convert to WebP using:
```bash
# Example for PNG conversion
cwebp -q 90 input.png -o public/images/certifications/kosher.webp
```
- If the source is a vector format (SVG), keep the SVG — don't convert to raster.
- Use clean, consistent filenames:
  - `kosher.svg` (or `.webp`)
  - `greenguard.svg` (or `.webp`)
  - `nsf.svg` (or `.webp`)
  - `epd.svg` (or `.webp`)

### Step 5: Add logos to stone detail pages

Find the template/section in stone detail pages where certification information is displayed. This is likely in the stone detail HTML template or in a shared partial.

Add the certification logos in a row/grid format:
```html
<div class="certification-logos">
  <img src="/images/certifications/kosher.svg" alt="Kosher Certified" class="cert-logo" />
  <img src="/images/certifications/greenguard.svg" alt="UL Greenguard Certified" class="cert-logo" />
  <img src="/images/certifications/nsf.svg" alt="NSF International Certified" class="cert-logo" />
  <img src="/images/certifications/epd.svg" alt="Environmental Product Declaration" class="cert-logo" />
</div>
```

Style with CSS:
```css
.certification-logos {
  display: flex;
  align-items: center;
  gap: 24px;
  flex-wrap: wrap;
  padding: 20px 0;
}
.cert-logo {
  height: 48px;
  width: auto;
  opacity: 0.85;
  transition: opacity 0.2s;
}
.cert-logo:hover {
  opacity: 1;
}
```

### Step 6: Add logos to quality assurance sections

The quality assurance section lives on `collections.html`. Add the same certification logo row there.

Also check `about.html` for any quality/certification section and add there too.

### Step 7: Apply consistently

Ensure the certification logos appear on:
- [ ] Every stone detail page (all 47 stones)
- [ ] Collections page quality assurance section
- [ ] About page (if there's a quality/certifications section)

### Step 8: Cache-bust
After adding new CSS, increment the `?v=N` on all CSS `<link>` tags across affected HTML files.

### Step 9: Commit
```bash
git add public/images/certifications/ public/styles.css
git add -A  # catch any HTML changes
git diff --cached --stat
git commit -m "feat: add certification logos (Kosher, Greenguard, NSF, EPD) to stone detail pages and quality sections"
```
