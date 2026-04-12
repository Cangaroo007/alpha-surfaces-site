# Prompt 06: About Page Updates
**Priority:** HIGH
**Run from:** `~/Downloads/alpha-surfaces-site/`
**File:** `public/about.html`

---

## Context

The About page needs its hero image swapped (bathroom/lifestyle image that is currently on the Collections page in Figma) and several previously-built fixes verified.

**IMPORTANT OVERLAY RULE:** Background images are CLEAN (no baked-in icons/text). All icons and text come from HTML overlays. The Alpha Shield logo PNG (3194×3738) includes "ALPHA SHIELD" text — NEVER add a separate `<span>`. Use `height:auto`, never forced square.

## What to Do

### Change 1: Hero Image Swap

The About page hero should be the bathroom/lifestyle image that is currently shown on the Collections page in Figma.

**Action:** This is an image swap:
- The bathroom image moves FROM the Collections page TO the About page
- The Collections page keeps its current hero (confirmed in April 2 meeting)

Find the current About page hero:
```bash
grep -n "hero\|banner\|lifestyle.*image" public/about.html | head -20
```

If the bathroom image is already in `public/images/` (possibly as the Collections hero), copy/rename it for the About page. If it needs to be exported from Figma, add a TODO:
```html
<!-- TODO: Replace hero with bathroom/lifestyle image from Figma — Sean to export -->
```

### Change 2: Verify Module Layout (from Handoff Update)

The following changes were made to the about page modules in a previous session but may NOT have been committed due to file sync issues. Verify each one is present:

**Grid layout:**
```bash
grep -n "min(525px\|45%\|clamp(60px" public/about.html
```
Expected: `grid-template-columns: min(525px, 45%) 1fr` with `gap: clamp(60px, 12vw, 174px)`

**Image aspect ratio:**
```bash
grep -n "aspect-ratio" public/about.html
```
Expected: `aspect-ratio: 1/1` (square, per Figma 525×525)

**Overlay position:**
Expected: `padding-bottom: 35%`

**ZERO SILICA label:**
Expected: `.about-module-overlay-label` class, `font-size: 26px`

**Mobile responsiveness:**
Expected: `aspect-ratio: 4/3`, single column

If ANY of these are missing, apply them now. The commit prompt file was `Claude-Code-Fix-About-Modules.md`.

### Change 3: Verify Feature Section Overlays

Check that the three feature section overlays are correct:

**Alpha Shield section:**
- Should show: `<img>` of the Alpha Shield logo ONLY (no separate `<span>ALPHA SHIELD</span>`)
- Logo should have `height: auto` (NOT a fixed height)
- If a `<span>ALPHA SHIELD</span>` exists alongside the logo `<img>`, REMOVE the span

```bash
grep -n -A 3 "alpha.*shield\|alphashield" public/about.html | head -30
```

**Indoor-Outdoor section:**
- Should show: starburst icon scaled to 160–220px
- Icon is square (4370×4370) — `width: 160-220px; height: same` is correct

**Zero Silica section:**
- Should show: text overlay "ZERO SILICA" only, no icon
- Using `.about-module-overlay-label` class

### Change 4: Emerald Haze Label

Verify the kitchen image label has been corrected:
- **Wrong:** "Carrara / Collection 02"
- **Correct:** "Emerald Haze / Collection 05"

```bash
grep -n "Carrara\|Emerald Haze" public/about.html
```

If it still says "Carrara / Collection 02", change it to "Emerald Haze / Collection 05".

### Step 5: Cache-bust and commit
```bash
git add public/about.html public/styles.css
git commit -m "feat: about page — swap hero to bathroom image, verify module layout and overlays"
```
