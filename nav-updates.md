# Navigation Updates for index.html

This document lists every `<a href>` in `public/index.html` that should be
updated to point to `/collections` or `/surfaces/:slug`.

## Nav Links

| Line | Current `href` | New `href` | Element |
|------|---------------|------------|---------|
| 174 | `#collections` | `/collections` | Nav link "Collections" |

## Hero Section

| Line | Current `href` | New `href` | Element |
|------|---------------|------------|---------|
| 188 | `#collections` | `/collections` | CTA button "Explore Collections" |

## Footer — Collections Column

| Line | Current `href` | New `href` | Element |
|------|---------------|------------|---------|
| 351 | `#` | `/collections#collection-01` | "Collection 01 — Calacatta" |
| 352 | `#` | `/collections#collection-02` | "Collection 02 — Prairie" |
| 353 | `#` | `/collections#collection-03` | "Collection 03 — Soapstone" |
| 354 | `#` | `/collections#collection-04` | "Collection 04 — Dramatic" |
| 355 | `#` | `/collections#collection-05` | "Collection 05 — Urban" |
| 356 | `#` | `/collections#original-alpha-zero` | "Original Alpha Zero" |

## Notes

- The `#collections` anchor in the nav and hero currently scrolls to the
  collections preview section on the homepage. Changing it to `/collections`
  will navigate to the full collections index page instead.
- Footer collection links currently point to `#` (placeholder). They should
  link to the collections page with anchor fragments matching each
  collection's `id` in `stones.json`.
- No stone-level links exist in index.html yet — those are handled by the
  collections page JS which links each card to `/surfaces/:slug`.
- The `#about` and `#contact` nav links should remain as-is (they anchor
  to sections within index.html).
