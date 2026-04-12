# Prompt 09: Social Links & Instagram Connection
**Priority:** MEDIUM
**Run from:** `~/Downloads/alpha-surfaces-site/`
**PARTIALLY BLOCKED:** Instagram and Facebook URLs not yet confirmed by Belinda

---

## Context

The April 2 meeting confirmed Instagram handle appears to be `@alpha.surfaces` but Belinda hasn't formally confirmed or sent the profile URLs. Facebook page link is also pending.

Build the social link infrastructure now with placeholder URLs. They can be swapped in with a single find-and-replace when Belinda confirms.

## What to Do

### Step 1: Add Social Icons to Footer

Find the footer across all main pages:
```bash
grep -n "footer\|social\|instagram\|facebook" public/index.html public/about.html public/collections.html | head -30
```

Add social icon links to the footer. Use simple SVG icons (no external icon library dependency):

```html
<div class="social-links">
  <!-- TODO: Replace href values with actual URLs from Belinda -->
  <a href="https://www.instagram.com/alpha.surfaces/" target="_blank" rel="noopener" aria-label="Follow us on Instagram" class="social-link">
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <rect x="2" y="2" width="20" height="20" rx="5" ry="5"></rect>
      <circle cx="12" cy="12" r="5"></circle>
      <circle cx="17.5" cy="6.5" r="1.5" fill="currentColor" stroke="none"></circle>
    </svg>
  </a>
  <a href="#" target="_blank" rel="noopener" aria-label="Follow us on Facebook" class="social-link">
    <!-- TODO: Replace # with actual Facebook URL from Belinda -->
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M18 2h-3a5 5 0 0 0-5 5v3H7v4h3v8h4v-8h3l1-4h-4V7a1 1 0 0 1 1-1h3z"></path>
    </svg>
  </a>
</div>
```

CSS:
```css
.social-links {
  display: flex;
  gap: 16px;
  align-items: center;
}
.social-link {
  color: white;
  opacity: 0.7;
  transition: opacity 0.2s;
}
.social-link:hover {
  opacity: 1;
}
```

### Step 2: Apply to ALL pages

The social links need to appear in the footer of every page. Check if the footer is a shared partial or duplicated per page:

```bash
grep -rn "nav\.html\|footer.*include\|footer.*partial" public/ --include="*.html" | head -10
```

If duplicated: add the social links to every footer instance.
If shared partial: add once and it propagates.

### Step 3: Link Instagram Carousel (if Prompt 05 has been run)

If the Instagram carousel shell from Prompt 05 exists on collections.html, update the "View More on Instagram" link:

```bash
grep -n "instagram.*link\|View More" public/collections.html
```

Set href to `https://www.instagram.com/alpha.surfaces/` (best guess — will be confirmed by Belinda).

### Step 4: Add marker comments for easy find-and-replace later

Throughout the codebase, wherever a social URL placeholder exists, use a consistent marker:

```html
<!-- SOCIAL:INSTAGRAM = https://www.instagram.com/alpha.surfaces/ -->
<!-- SOCIAL:FACEBOOK = # -->
```

This makes it trivial to do a global find-and-replace when Belinda confirms the URLs.

### Step 5: Commit
```bash
git add -A
git commit -m "feat: add social link icons (Instagram, Facebook) to footer — URLs pending confirmation"
```
