# Prompt 05: Collections Page Updates
**Priority:** HIGH
**Run from:** `~/Downloads/alpha-surfaces-site/`
**File:** `public/collections.html`

---

## Context

The Collections page was reviewed in the April 2 meeting. The hero image is CONFIRMED correct and should stay. Two specific changes are needed: replace the green kitchen image and build an Instagram carousel shell.

## What to Do

### Change 1: Keep Current Hero Image (CONFIRMED)
No action needed. The hero/lifestyle image on the Collections page is correct. Do NOT change it.

### Change 2: Replace Kitchen Lifestyle Image

The green kitchen image currently on the Collections page (mid-page) needs to be replaced with the correct image from Figma.

**Figma file:** `88KD34puTUAFmxuxM7k9rv`
**Figma link:** https://www.figma.com/design/88KD34puTUAFmxuxM7k9rv/Alpha-Surfaces?node-id=963-13305

**Action:** Sean needs to export the correct kitchen image from Figma manually (or use Figma MCP if configured). The image should be:
- Exported at 2x resolution
- Converted to WebP
- Saved to `public/images/` with an appropriate name (e.g., `collections-kitchen.webp`)

If the correct Figma image is not yet available locally, add a TODO comment:
```html
<!-- TODO: Replace this kitchen image with the correct version from Figma node 963-13305 -->
```

Find the current green kitchen image:
```bash
grep -n "kitchen\|green.*kitchen\|lifestyle.*image\|quality.*assurance" public/collections.html | head -20
```

### Change 3: Instagram Carousel (Shell)

Build a carousel component that will pull the latest 4 posts from `@alpha.surfaces` Instagram.

**BLOCKED:** Instagram API credentials have not been received from Belinda yet. Build the UI shell with placeholder content.

```html
<section class="instagram-section">
  <h2>Follow Us on Instagram</h2>
  <p class="instagram-handle">@alpha.surfaces</p>
  <div class="instagram-carousel">
    <!-- TODO: Connect to Instagram Graph API once credentials received from Belinda -->
    <div class="instagram-post placeholder">
      <div class="instagram-placeholder-img"></div>
    </div>
    <div class="instagram-post placeholder">
      <div class="instagram-placeholder-img"></div>
    </div>
    <div class="instagram-post placeholder">
      <div class="instagram-placeholder-img"></div>
    </div>
    <div class="instagram-post placeholder">
      <div class="instagram-placeholder-img"></div>
    </div>
  </div>
  <a href="#" class="instagram-link" target="_blank" rel="noopener">
    <!-- TODO: Replace # with actual Instagram profile URL -->
    View More on Instagram
  </a>
</section>
```

CSS for the carousel:
```css
.instagram-section {
  padding: 80px 5%;
  text-align: center;
}
.instagram-carousel {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
  max-width: 1200px;
  margin: 32px auto;
}
.instagram-post {
  aspect-ratio: 1;
  overflow: hidden;
  border-radius: 4px;
}
.instagram-post img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}
.instagram-placeholder-img {
  width: 100%;
  height: 100%;
  background: var(--cream, #f3f1e6);
}
@media (max-width: 768px) {
  .instagram-carousel {
    grid-template-columns: repeat(2, 1fr);
  }
}
```

### Change 4: Collections Navigation Simplification

The mega-dropdown that lists all stone names when hovering over "Collections" should be simplified. Clicking "Collections" should go directly to the collections page.

```bash
# Find the nav/dropdown code
grep -n "collections\|mega.*menu\|dropdown\|nav.*collection" public/nav.js public/nav.html 2>/dev/null | head -30
```

Options (in order of preference):
1. Remove the mega-dropdown entirely — Collections link goes straight to `/collections`
2. Simplify to show collection NUMBERS only (Collection 01, 02, etc.) instead of individual stone names
3. Keep the dropdown but make the "Collections" text itself a direct link

### Change 5: Quality Assurance Section — Add Certification Logos

If Prompt 02 has been run, the certification logo files should be in `public/images/certifications/`. Add them to the quality assurance section on this page.

### Step 6: Cache-bust and commit
```bash
git add public/collections.html public/styles.css public/nav.js
git add -A
git commit -m "feat: collections page — replace kitchen image, add Instagram carousel shell, simplify nav"
```
