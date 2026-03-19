# Alpha Surfaces — Session 4 Handover Document
> **Generated:** 19 March 2026
> **Repo:** github.com/Cangaroo007/alpha-surfaces-site
> **Live:** https://alpha-surfaces-site-production.up.railway.app
> **Latest commit:** d820e4f

---

## 1. Everything Built & Live

### Core Pages
| Page | URL | Status |
|---|---|---|
| Homepage | `/` | Live — hero, statement, about, gallery, contact, locations, footer |
| Collections | `/collections.html` | Live — cycling hero (5 slides), intro, AlphaShield, accordion, quality assurance |
| About | `/about.html` | Live — 5 modules (brand statement, zero silica, indoor-outdoor, AlphaShield, FAQs) |
| Order A Sample | `/order-sample.html` | Live — form with stone pre-selection via `?stone=[slug]` |
| Kitchen Connection | `/kc.html` | Live — partner landing page |

### Stone Detail Pages (52 total)
- URL pattern: `/surfaces/[slug]`
- Dynamic template: reads from `/data/stones.json` via JS
- Shows: stone name, collection, tagline, description, specs, AlphaShield badge, EPD logo, gallery, collection grid
- "Order A Sample" button links to `/order-sample.html?stone=[slug]`

### Partner Pages (21 total)
- URL pattern: `/partners/[slug].html`
- 20 partner-specific pages + 1 co-branded template (`template.html`)
- All use same design system, noindex/nofollow

### Brand Documents (3 total)
- `/brand/brand-guidelines.html` — 12-page A4 print-ready brand guide
- `/brand/slab-stickers.html` — A4 slab identification labels with Code 128 barcodes + QR codes
- `/brand/partner-brochure.html` — 2-page A4 partner brochure (front + back)
- All use `@media print` with `print-color-adjust: exact`

### Shared Components
| File | Purpose | Cache Version |
|---|---|---|
| `nav.js` + `nav.css` | Mega menu with 6-collection dropdown + mobile slide-in | v6 |
| `animation.js` + `animation.css` | Scroll reveal, parallax, card hover, section transitions | v7 |
| `sample-modal.js` + `sample-modal.css` | Order A Sample popup on collections + index | v1 |

### Data
- `public/data/stones.json` — 6 collections, 52 stones, 39 with images, 10 with full enrichment

---

## 2. Known Issues & Status

### Resolved This Session
| Issue | Fix | Commit |
|---|---|---|
| `prefix` ReferenceError crashing surface pages | Replaced with literal `../` path | `3afbdb5` |
| nav.js `try/catch` wrapping entire script | Rewrote into 3 independent phases | `60c1ad6` |
| Mega menu stone links using `.html` extension | Removed `.html` for consistency | `c8b0265` |
| COLLECTIONS link blocked by `preventDefault` | Removed — click navigates, hover opens menu | `6d4f723` |
| Collection headings in mega menu not linked | Now link to `/collections.html#collection-XX` | `6d4f723` |
| Deep link accordion not opening target | Explicit hash→ID mapping + nav-height scroll offset | `7320bfb` |
| Animations not visible (instant reveal) | Separated above-fold/below-fold, threshold 0.2, rootMargin -80px | `d820e4f` |

### Outstanding
| Issue | Severity | Notes |
|---|---|---|
| 13 stones missing swatch images | Medium | Not in Figma Collections component or download source (see Section 3) |
| `public/calacatta-leggera.html` exists at root level | Low | Orphan file from early template work — can delete |
| 5 placeholder image files (0 bytes) in `public/images/` | Medium | `alphashield-hero.png`, `indoor-outdoor-hero.png`, `zero-silica-hero.png`, `epd-logo.png`, `instagram-grid.png` — need real files uploaded |
| `process_images.py` and `scrape-logos.js` in repo root | Low | Utility scripts — not served but add repo clutter |
| Partner template.html has old nav (not using shared nav.js) | Low | By design — has special partner logo nav |
| 42 stones have no tagline/description enrichment | Medium | Only 10 of 52 stones have full `tagline`, `description`, specs |

---

## 3. Waiting on Belinda / Kate

### Images Needed
- **13 stone swatches** not available from any source:
  - Collection 01: Calacatta Borghini, Acropolis, Statuario Venato, Unique Carrara, Mont Blanc
  - Collection 02: Santorini Gold, Travertino Classico
  - Collection 03: Elba, Viola Ligera
  - Original Alpha Zero: Alpha Zero Classic, Alpha Zero Pure, Serena, Glacier Grey

- **5 About page hero images** (currently 0-byte placeholders):
  - `alphashield-hero.png` — AlphaShield logo on stone benchtop
  - `indoor-outdoor-hero.png` — Coastal kitchen with ocean view
  - `zero-silica-hero.png` — Bathroom vanity with "ZERO SILICA" overlay
  - `epd-logo.png` — International EPD System logo (inverted greyscale)
  - `instagram-grid.png` — Instagram feed screenshot (4 posts)

### Content Confirmation
- Per-stone slab dimensions if any differ from 3200 × 1600 × 20mm standard
- Per-stone weight if any differ from 236kg
- Warranty period per collection (all currently "15-Year Limited Warranty")
- Taglines and descriptions for remaining 42 un-enriched stones
- 3 partner logos that failed scraping: Dream Doors, Harvey Norman, Flexi Renovation Group

### Collection Structure
- Confirm the 2026 collection numbering (01-05 + Alpha Zero) is final
- Confirm which stones belong to which collection (current mapping from `stones.json`)
- Confirm Indoor-Outdoor stones are only: Broome, Cabarita, Torquay, Whitehaven

---

## 4. Next Tasks (Priority Order)

1. **Upload real About page images** — replace 0-byte placeholders with actual files
2. **Source remaining 13 stone swatches** — may need photography or supplier assets
3. **Enrich remaining 42 stones** — add tagline, description, specs to `stones.json`
4. **Form backend** — wire up Order A Sample form and contact form to email/CRM
5. **SEO** — add meta descriptions, Open Graph tags, structured data to all pages
6. **Partner template rollout** — generate co-branded pages from `template.html` for all 20 partners
7. **Performance** — lazy load below-fold images, add `<link rel="preload">` for hero images
8. **Analytics** — add Google Analytics / Tag Manager
9. **Favicon** — add site favicon and apple-touch-icon from brand assets
10. **Mobile QA** — thorough testing on iOS Safari, Android Chrome across all pages

---

## 5. File Structure Overview

```
alpha-surfaces-site/
├── server.js                    # Express server (CMS, API, static serving)
├── package.json                 # Dependencies (express, helmet, puppeteer, etc.)
├── process_images.py            # Image processing script (Pillow)
├── scrape-logos.js              # Partner logo scraper (Puppeteer)
├── docs/                        # Documentation
├── data/                        # Server-side data (keys, versions)
├── lib/                         # Server libraries (versions.js)
├── config/                      # Server config (defaults.json)
├── public/                      # Static files served by Express
│   ├── index.html               # Homepage
│   ├── collections.html         # Collections page with cycling hero
│   ├── about.html               # About page (5 modules)
│   ├── order-sample.html        # Sample order form
│   ├── kc.html                  # Kitchen Connection partner page
│   ├── admin.html               # CMS admin panel
│   ├── nav.html                 # Nav HTML fragment (reference only)
│   ├── nav.js / nav.css         # Shared mega menu (v6)
│   ├── animation.js / .css      # Shared scroll animations (v7)
│   ├── sample-modal.js / .css   # Order A Sample popup (v1)
│   ├── data/
│   │   └── stones.json          # 52 stones across 6 collections
│   ├── fonts/
│   │   ├── Web/                 # Concrette S (.woff2/.woff)
│   │   └── Degular Normal/      # Degular (.woff2/.woff)
│   ├── logos/
│   │   ├── 01 Brandmark/        # Alpha Surfaces logo variants
│   │   ├── 03 Alpha Shield/     # AlphaShield badge variants
│   │   └── 04_Indoor-Outdoor/   # Indoor-Outdoor icon
│   ├── images/
│   │   ├── hero.jpg             # Homepage hero image
│   │   ├── about.jpg            # Kitchen lifestyle photo
│   │   ├── collection_*.jpg     # Collection hero images (5)
│   │   ├── stones/              # 78 stone swatch WebP images
│   │   │   ├── [slug].webp      # Hero (max 1920px)
│   │   │   ├── [slug]-thumb.webp # Thumbnail (max 600px)
│   │   │   └── gallery/         # 34 gallery images (1200px)
│   │   ├── alphashield-hero.png # PLACEHOLDER (0 bytes)
│   │   ├── indoor-outdoor-hero.png # PLACEHOLDER (0 bytes)
│   │   ├── zero-silica-hero.png # PLACEHOLDER (0 bytes)
│   │   ├── epd-logo.png         # PLACEHOLDER (0 bytes)
│   │   └── instagram-grid.png   # PLACEHOLDER (0 bytes)
│   ├── surfaces/                # 52 stone detail pages
│   │   └── [slug].html          # Dynamic template, reads stones.json
│   ├── partners/                # 21 partner landing pages
│   │   ├── template.html        # Co-branded template with config block
│   │   └── [slug].html          # 20 partner-specific pages
│   └── brand/
│       ├── brand-guidelines.html # 12-page A4 brand guide
│       ├── slab-stickers.html   # Slab ID labels with barcodes/QR
│       ├── partner-brochure.html # 2-page A4 brochure
│       └── logos/               # 17 scraped partner logos
```

---

## 6. Key URLs for Testing

### Production (Railway)
| Page | URL |
|---|---|
| Homepage | https://alpha-surfaces-site-production.up.railway.app/ |
| Collections | https://alpha-surfaces-site-production.up.railway.app/collections.html |
| Collections deep link | https://alpha-surfaces-site-production.up.railway.app/collections.html#collection-03 |
| About | https://alpha-surfaces-site-production.up.railway.app/about.html |
| Order Sample | https://alpha-surfaces-site-production.up.railway.app/order-sample.html?stone=calacatta-leggera |
| Stone detail | https://alpha-surfaces-site-production.up.railway.app/surfaces/calacatta-leggera |
| Stone detail (with images) | https://alpha-surfaces-site-production.up.railway.app/surfaces/jewel |
| KC Partner | https://alpha-surfaces-site-production.up.railway.app/kc |
| Partner page | https://alpha-surfaces-site-production.up.railway.app/partners/freedom-kitchens.html |
| Brand guidelines | https://alpha-surfaces-site-production.up.railway.app/brand/brand-guidelines.html |
| Slab stickers | https://alpha-surfaces-site-production.up.railway.app/brand/slab-stickers.html |
| Partner brochure | https://alpha-surfaces-site-production.up.railway.app/brand/partner-brochure.html |
| Admin CMS | https://alpha-surfaces-site-production.up.railway.app/admin |
| stones.json | https://alpha-surfaces-site-production.up.railway.app/data/stones.json |

### API Endpoints
| Endpoint | Auth | Purpose |
|---|---|---|
| GET /data/stones.json | Public | Stone collection data |
| GET /api/content | Public | CMS content |
| POST /api/login | Public | Admin login |
| PUT /api/content | Auth | Update CMS content |
| POST /api/upload | Auth | Image upload (Cloudinary) |
| POST /api/ai/chat | Auth | AI content generation |

---

## 7. Git & Deployment

- **Repo:** https://github.com/Cangaroo007/alpha-surfaces-site
- **Branch:** `main`
- **Deployment:** Railway auto-deploys on push to `main`
- **Latest commit:** `d820e4f` — Fix animation observer threshold and timing
- **Total commits this session:** ~30

### Cache Bust Versions (current)
| File | Version |
|---|---|
| `nav.js` / `nav.css` | `?v=6` |
| `animation.js` / `animation.css` | `?v=7` |
| `sample-modal.js` / `sample-modal.css` | `?v=1` |

---

## 8. Technical Debt & Things to Watch

### Architecture
- **No bundler/build step** — all files served as-is from `public/`. Works for current scale but will need a build pipeline if the site grows significantly.
- **Inline CSS in every HTML page** — the design system CSS is duplicated across 52 surface pages, 21 partner pages, etc. A shared `styles.css` would reduce this but wasn't done because each page was generated from templates.
- **Nav loaded via client-side JS** — if nav.js fails to load, pages have an empty `<nav>` element. The 3-phase architecture mitigates this but it's still a client-side dependency.

### Data
- **stones.json is the source of truth** — all page content for stones comes from this single file. If it becomes corrupt or is overwritten by the CMS, all 52 surface pages break simultaneously.
- **No database** — all content is file-based (`stones.json`, HTML files, `content.json`). Suitable for current scale.
- **Gallery images stored in git** — 34 gallery WebP files are committed to the repo. Large binary files in git are not ideal long-term.

### Performance
- **No image lazy loading on hero** — the collections cycling hero loads all 5 images immediately. Could use `loading="lazy"` on non-active slides.
- **No service worker** — no offline support or precaching.
- **Helmet CSP allows `cdn.jsdelivr.net`** — added for JsBarcode/QRCode on slab stickers page. Could be scoped to only that page.

### Security
- **Admin panel at `/admin`** — protected by bcrypt password. No rate limiting on content API beyond login.
- **Form `action="#"` placeholders** — contact form, order sample form, and partner enquiry forms all submit to `#`. Need backend processing.
- **No CSRF tokens** on forms.

### Monitoring
- **No error tracking** (Sentry, etc.)
- **No analytics** (GA, etc.)
- **No uptime monitoring** (Pingdom, etc.)
- **Console errors are the only debugging** — no structured logging on the server side for page-specific issues.

### Content
- **5 About page images are 0-byte placeholders** — the page will show broken images until real files are uploaded.
- **42 of 52 stones lack tagline/description** — enrichment was only done for the 10 stones that had photography from the initial approved batch.
- **Collection descriptions are hardcoded** in the cycling hero — if collection names change in `stones.json`, the hero descriptions won't update automatically.
