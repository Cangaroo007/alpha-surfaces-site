# Prompt 07: Alpha Zero / Discontinued Page
**Priority:** MEDIUM-HIGH
**Run from:** `~/Downloads/alpha-surfaces-site/`
**Depends on:** Prompt 01 (stones.json updated — Alpha Zero now 10 stones, Taj Mahal moved to C05, 5 removed entirely)

---

## Context

The April 2 meeting decision: Alpha Zero stones are discontinued run-out stock. They should remain on the site (sales team sends links) but not be prominently promoted. Swatches should click through to full slab image ONLY — no individual detail pages.

## What to Do

### Change 1: Rename the Collection

Everywhere "Original AlphaZero" or "Original Alpha Zero" appears, rename to **"Discontinued AlphaZero"** (or "Alpha Zero — Discontinued").

```bash
grep -rni "original.*alpha.*zero\|alpha.*zero\|alphaZero" public/ --include="*.html" --include="*.js" --include="*.json" | head -30
```

Update:
- `collections.html` — section heading
- `nav.js` / `nav.html` — navigation label
- `stones.json` — collection name field
- Any stone detail HTML files that reference the collection name

### Change 2: Add Discontinued Messaging

Add prominent copy to the Alpha Zero section on the Collections page:

```html
<div class="discontinued-banner">
  <p class="discontinued-message">
    These colours are discontinued and available as heavily discounted run-out stock.
    Contact Alpha Surfaces for current availability and pricing.
  </p>
  <a href="/contact" class="btn btn-secondary">Contact Us for Pricing</a>
  <!-- Or use: <a href="tel:+61XXXXXXXXX">Call Us</a> or mailto link -->
</div>
```

Style to be noticeable but not alarming:
```css
.discontinued-banner {
  background: var(--cream, #f3f1e6);
  border-left: 4px solid var(--olive, #564D22);
  padding: 24px 32px;
  margin: 24px 0;
  text-align: center;
}
.discontinued-message {
  font-family: 'Degular', sans-serif;
  font-size: 16px;
  color: #333;
  margin-bottom: 16px;
}
```

### Change 3: Swatch Click → Full Slab Only

For discontinued stones, clicking a swatch should open the full slab image directly (in a lightbox or new view) — NOT navigate to an individual stone detail page.

```bash
# Find how stone clicks are currently handled
grep -n "stone.*click\|swatch.*href\|stone.*link\|detail.*page" public/collections.html public/js/*.js 2>/dev/null | head -20
```

Options:
1. **Lightbox approach:** Clicking the swatch opens a full-screen/modal view of the slab image with a close button
2. **New tab approach:** Clicking the swatch opens `{slug}-slab.webp` directly in a new tab
3. **Inline expand:** Clicking the swatch expands/replaces the swatch with the slab image inline

Approach 1 (lightbox) is preferred for the best UX.

For stones where no slab image exists (`has_slab: false` in stones.json), clicking the swatch should either:
- Do nothing (with a tooltip "Full slab image not available")
- Open the swatch/hero image at larger size

### Change 4: Remove/Redirect Detail Pages for Removed Stones

The 5 stones removed entirely in Prompt 01 (Venatino, Patagonia, Calacatta Borghini, Biscotti, Infinity Gris) may have individual HTML detail pages or dynamic routes. Additionally, Taj Mahal has moved from Alpha Zero to Collection 05 — it is no longer discontinued. Handle these:

```bash
# Check for static HTML pages for removed stones
ls public/stones/venatino* public/stones/patagonia* public/stones/calacatta-borghini* public/stones/biscotti* public/stones/infinity-gris* 2>/dev/null
# Check Taj Mahal — it should now be in C05, not Alpha Zero
grep -rn "taj.mahal" public/data/stones.json
```

- For the 5 removed stones: delete their pages if they exist; routes driven by stones.json will auto-disappear
- For Taj Mahal: verify it is now listed under Collection 05 with `"discontinued": false` (or no discontinued field)
- Consider adding a redirect/404 handler for old URLs

### Change 5: Navigation Visibility

The discontinued collection should be accessible but not prominently promoted. Check current nav structure:

```bash
grep -n "alpha.*zero\|discontinued" public/nav.js public/nav.html 2>/dev/null
```

Keep the link in the navigation but style it subtly (e.g., smaller text, "Discontinued" suffix, grouped separately from Collections 01-05).

### Step 6: Test
- [ ] "Discontinued AlphaZero" heading appears on Collections page
- [ ] Discount messaging is visible and clear
- [ ] Clicking a discontinued swatch opens slab image (NOT a detail page)
- [ ] The 5 removed stones (Venatino, Patagonia, Calacatta Borghini, Biscotti, Infinity Gris) no longer appear anywhere
- [ ] Taj Mahal no longer appears in Alpha Zero (it moved to C05)
- [ ] Navigation shows the section but doesn't promote it

### Step 7: Commit
```bash
git add -A
git commit -m "feat: alpha zero — rename to Discontinued, add run-out messaging, swatch→slab click only"
```
