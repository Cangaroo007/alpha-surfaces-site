# Prompt 04: Homepage Updates
**Priority:** HIGH
**Run from:** `~/Downloads/alpha-surfaces-site/`
**File:** `public/index.html`

---

## Context

The homepage was reviewed on April 2 by Belinda and Jay and declared "nearly 100%". The remaining changes are specific and well-defined. Belinda's follow-up email confirmed the text change: "CRAFTSMANSHIP" → "SUPERIOR QUALITY AND DURABILITY".

**IMPORTANT:** Transitions and micro-animations are DEFERRED — not in launch scope. Do NOT implement any new scroll animations beyond what's specified here for the A logo.

## What to Do

### Change 1: "A" Logo Behaviour

The decorative "A" watermark on the hero section needs three fixes:

**1a. Round the bottom**
The bottom of the "A" shape is cut off/missing. Fix the SVG or image so the full A shape renders with a rounded bottom, matching how the A appears in other instances on the site.

```bash
# Find the A logo asset
grep -rn "hero-logo\|watermark\|\.hero.*logo\|logo.*overlay" public/index.html | head -20
```

**1b. Sticky behaviour**
The A logo should:
- Be visible during the hero image section
- Lock/stick at the base of the hero images
- NOT scroll freely with the page past the hero section

Current implementation: `position: fixed` with parallax JS at 0.4× speed (committed in `be5ebb0`).

New behaviour:
```javascript
// Pseudo-logic:
// 1. A logo is position: fixed during hero section scroll
// 2. When user scrolls past hero section bottom, A logo stops (locks at hero bottom)
// 3. A logo fades out as user scrolls further below
```

**1c. Fade out below hero**
After the A logo locks at the base of the hero images, it should fade to transparent as the user continues scrolling down. Use `opacity` transition driven by scroll position.

### Change 2: Swap Intro and Quote Order

Currently on the homepage, the pull quote appears before the introductory paragraph. Swap them:

**Before:** Quote → Intro paragraph
**After:** Intro paragraph → Quote

Find these sections in `index.html` and swap their DOM order. Do NOT change the content or styling — only the order.

```bash
# Find the sections
grep -n "quote\|intro\|about.*section\|tagline" public/index.html | head -20
```

### Change 3: Replace "CRAFTSMANSHIP" with "SUPERIOR QUALITY AND DURABILITY"

This is a **CONFIRMED** text change from Belinda's follow-up email (received after April 2 meeting). The exact replacement is:

**Old text:** "CRAFTSMANSHIP" (or "Craftsmanship" in any case)
**New text:** "SUPERIOR QUALITY AND DURABILITY"

This applies to the homepage feature tiles AND anywhere else it appears. Search the ENTIRE codebase:

```bash
grep -rni "craftsmanship" public/ --include="*.html" --include="*.js" --include="*.json"
```

Replace ALL instances of "CRAFTSMANSHIP" (case-insensitive) with "SUPERIOR QUALITY AND DURABILITY". This is NOT a placeholder — it is the confirmed final wording from Belinda.

### Change 4: Verify Previous Fixes

Check that these previously-identified fixes are already deployed. If NOT done, fix them now:

**4a. "Stone. Life. Style." spacing**
The tagline should read "Stone. Life. Style." with consistent spacing (space after "Stone."). Check:
```bash
grep -rn "Stone\.\|Stone\.Life\|Stone\..*Life" public/index.html
```

**4b. Autumn Gold duplicate label**
There should be only ONE instance of the "Autumn Gold / Collection 05" label on the hero. Check:
```bash
grep -rn "Autumn Gold" public/index.html
```

**4c. "Click images to show full slabs" hint text**
On collection pages (not homepage), there should be hint text telling users they can click stone thumbnails to see full slabs.

### Step 5: Cache-bust
Increment `?v=N` on CSS and JS references in `index.html`.

### Step 6: Test locally
```bash
node server.js &
# Open http://localhost:3000 in browser
# Test:
# - [ ] A logo renders with full shape (rounded bottom)
# - [ ] A logo sticks at hero bottom, fades out below
# - [ ] Intro paragraph appears before quote
# - [ ] "SUPERIOR QUALITY AND DURABILITY" appears where "CRAFTSMANSHIP" was
# - [ ] "Stone. Life. Style." has correct spacing
# - [ ] No duplicate Autumn Gold label
kill %1
```

### Step 7: Commit
```bash
git add public/index.html public/styles.css
git add -A  # catch any JS changes
git commit -m "feat: homepage — A logo sticky+fade, swap intro/quote order, CRAFTSMANSHIP → SUPERIOR QUALITY AND DURABILITY"
```
