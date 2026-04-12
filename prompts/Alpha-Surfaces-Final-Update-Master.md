# Alpha Surfaces Website — Final Update Master Requirements

> **IMPORTANT — HOW TO USE THIS DOCUMENT:**
> This document is being managed through Claude Chat. Each numbered prompt (01–11) will be pasted into the conversation for Claude Code to execute.
> **Claude Code MUST run from `~/Downloads/alpha-surfaces-site/`** (HYPHENS, not underscores).
> All source assets (images, logos, documents) are in `assets/` within the repo.
> All prompt files and the reference stone list PDF are in `prompts/` within the repo.
> Every path in this document and the individual prompts is relative to the repo root — Claude Code should NOT need to reference `~/Downloads/` for anything other than `cd`-ing into the repo itself.

**Date:** 7 April 2026
**Purpose:** Single source of truth for all remaining website updates before launch. This document maps every outstanding item, its asset source, current status, and the Claude Code prompt that will execute it.
**Repo:** `~/Downloads/alpha-surfaces-site/` → GitHub `cangaroo007/alpha-surfaces-site` → Railway auto-deploy from `main`
**Live:** `https://alpha-surfaces-site-production.up.railway.app`
**Figma:** `https://www.figma.com/design/88KD34puTUAFmxuxM7k9rv/Alpha-Surfaces?node-id=963-13305`
**Session 4 Handover:** `alpha-surfaces-session4-handover.md` (April 2 meeting with Belinda + Jay)
**Fathom Recording:** `https://fathom.video/share/uvxzVZoJW5s66jUeeaTaV1ySRNBSVvmu`

### KEY DECISIONS FROM APRIL 2 MEETING
- **Transitions/animations: DEFERRED.** Not in launch scope. Current build goes live as-is.
- **Alpha Zero → "Discontinued AlphaZero"** — swatches click to full slab only, no detail pages.
- **CMS training:** Jess + Sam, with Belinda + Jay observing. Session recorded.
- **Feature tile "Craftsmanship":** Replace with "SUPERIOR QUALITY AND DURABILITY" (confirmed in Belinda's follow-up email).
- **Collection 5 additional colours:** Belinda to add up to 5 more colours to spreadsheet.
- **Privacy Policy:** Keep as inline page, ADD PDF download button.

### BELINDA'S FOLLOW-UP EMAIL (received after meeting)
1. Stone list and Finish Google doc — **UPDATED** (received)
2. Link to full set of close-up and slab images (including discontinued) — **RECEIVED** → `assets/slabs-closeups-2026/`
3. 5 x Certification logos attached — **3 folders RECEIVED** → `assets/certification-logos/` + EPD logo to download from https://www.environdec.com/resources/brand-assets
4. Change "CRAFTSMANSHIP" to "SUPERIOR QUALITY AND DURABILITY" — **CONFIRMED**
5. Care and Maintenance doc — **RECEIVED** → `assets/documents/`
6. Fabrication Guide — **RECEIVED** → `assets/documents/`
7. Warranty — **RECEIVED** → `assets/documents/`

---

## FILE LOCATIONS FOR CLAUDE CODE

All prompt files, reference PDF, and source assets are in `~/Downloads/alpha-surfaces-site/`:
- Prompts and reference PDF in `prompts/`:
- All source assets (images, logos, documents) in `assets/`

Prompt files:
- `Alpha-Surfaces-Final-Update-Master.md` — this file (master reference)
- `Claude-Code-Prompt-01-Stone-Data.md` through `Claude-Code-Prompt-11-Final-QA.md` — individual prompts
- `Stone List and Finish - Sheet1.pdf` — PDF export of Belinda's updated Google Sheet (reference only — all stone data is embedded inline in Prompt 01)

To read any prompt: `cat prompts/Claude-Code-Prompt-01-Stone-Data.md`

---

## IMPORTANT RULES FOR CLAUDE CODE

1. **Working directory:** Always verify you are in `~/Downloads/alpha-surfaces-site/` (HYPHENS, not underscores).
2. **Overlay rule:** Background images are CLEAN. All icons/text come from HTML overlays. The Alpha Shield logo PNG (3194×3738) includes "ALPHA SHIELD" text — NEVER add a separate `<span>`. Use `height:auto` on this logo, never a forced square.
3. **Atomic changes:** Never modify overlays and images separately. Changes to overlay+image pairs must be committed together.
4. **Cache busting:** After every CSS/JS change, increment `?v=N` query strings on the affected files in the HTML `<link>`/`<script>` tags.
5. **Verify before commit:** Always run `git diff` before committing. Cowork/local sync can be unreliable.
6. **stones.json** is at `public/data/stones.json` — this is the central data file for all 47 stone routes.
7. **Test after each prompt:** Open the site locally (`npm start` or `node server.js`) and verify changes in browser before committing.

---

## ASSET LOCATIONS (All inside this repo under `assets/`)

All source assets have been consolidated into `assets/` within this repo. No need to reference `~/Downloads/`.

### Certification Logos (4 logos — proceed with these)
| Logo | Source Location | Action |
|------|----------------|--------|
| Kosher | `assets/certification-logos/kosher/` (contains .ai and .png) | Convert to SVG/WebP, copy to `public/images/certifications/` |
| UL Greenguard | `assets/certification-logos/greenguard/` (contains .svg and .png) | Copy SVG to `public/images/certifications/` |
| NSF International | `assets/certification-logos/nsf/` (contains .ai and .png) | Convert to SVG/WebP, copy to `public/images/certifications/` |
| EPD (Environmental Product Declaration) | Download from https://www.environdec.com/resources/brand-assets → save to `assets/certification-logos/epd/` | Convert to WebP, copy to `public/images/certifications/` |

### Slab + Close-Up Images
| Source | Location |
|--------|----------|
| Final swatch & hi-res slab images (RGB) | `assets/slabs-closeups-2026/` (files named "Collection 0X-StoneName-SLAB.jpg" / "Collection 0X-StoneName-CLOSE UP.jpg") |
| Missing swatches | `assets/missing-swatches/` (acropolis.jpg, calacatta-borghini.jpg, elba.jpg, glacier-grey.jpg, mont-blanc.jpg, serena.jpg, unique-carrara.jpg) |
| Alpha Zero swatches | `assets/alpha-zero-swatches/` (Alpha Zero - Basaltina.png, Alpha Zero - Calacatta Oro.jpg, Alpha Zero - Carbon.jpg, Alpha Zero - Grande Glacier.jpg, Alpha Zero - Silver Travertine.jpg, + Acropolis, Glacier Grey, Serena) |
| Calacatta Borghini slab | `assets/slabs-closeups-2026/27.AU71149-SLABCALACATTA-BORGHINI-scaled.jpg` |

> **NOTE — NEW C05 STONES HAVE NO IMAGES YET:**
> The 5 brand new Collection 05 stones (Perla Mahal, Emerald Haze, Viola Ligerra, Crystal Mahal, Venato) do NOT have any images in the assets folders. They are not in `assets/slabs-closeups-2026/`. When adding them to `stones.json`, set `"images_pending": true` and use empty/placeholder image paths. Flag these with a `<!-- TODO: C05 images pending from Belinda -->` comment. Do NOT block other work on this — proceed with everything else.

### Documents (Care & Maintenance, Fabrication Guide, Warranty)
| File | Location |
|------|----------|
| Care & Maintenance | `assets/documents/Alpha Surfaces Care and Maintence document - BK.docx` |
| Fabrication Guide | `assets/documents/Alpha Surfaces Fabrication and Installation Guide - BK.docx` |
| Warranty | `assets/documents/Alpha Surfaces Warranty Download .docx` |

### Stone Finishes Spreadsheet (UPDATED by Belinda)
| File | Location |
|------|----------|
| Updated spreadsheet | `prompts/Stone List and Finish - Sheet1.pdf` (PDF export of Belinda's Google Sheet — this is the authoritative stone data source). NOTE: Any `.xlsx` file found elsewhere is STALE/OLD — do NOT use it. |

### Figma Images (to be exported)
| Image | Figma Node | Destination |
|-------|-----------|-------------|
| Collections page — correct kitchen image (replacing green kitchen) | From Figma file `88KD34puTUAFmxuxM7k9rv` | `public/images/` |
| About page — bathroom/lifestyle hero | Currently on Collections page in Figma, moving to About | `public/images/` |
| Home page feature tile images (if updated copy changes layout) | Various nodes under Frame 60 | `public/images/` |

---

## SPREADSHEET → stones.json MAPPING

**Source:** Belinda's updated Google Sheet (PDF export: `Stone List and Finish - Sheet1.pdf`, April 7 2026)
**Total stones: 47** (37 current across C01–C05 + 10 discontinued Alpha Zero)

### Collection 01 — 6 stones (ALL Polished Finish)
| # | Stone | Finish | Change vs Old Site |
|---|-------|--------|--------------------|
| 1 | Jewel | Polished Finish | No change |
| 2 | Crystal | Polished Finish | **CONFIRMED in C01** (was uncertain) |
| 3 | Fraser | Polished Finish | No change |
| 4 | Oyster | Polished Finish | **ADD** if not on site |
| 5 | Graphite | Polished Finish | No change |
| 6 | Brilliance | Polished Finish | No change |

> **Bondi** is NOT in the spreadsheet. If it exists on the site, REMOVE it.

### Collection 02 — 7 stones (no changes)
| # | Stone | Finish |
|---|-------|--------|
| 1 | Shell | Polished Finish |
| 2 | Carrara | Polished Finish |
| 3 | Oyster Grey | Matte Finish |
| 4 | Earthy Concrete | Matte Finish |
| 5 | Ash | Polished Finish |
| 6 | Arctic | Polished Finish |
| 7 | Pearl | Polished Finish |

### Collection 03 — 8 stones (no changes)
| # | Stone | Finish | Notes |
|---|-------|--------|-------|
| 1 | Salt Stone | Polished Finish | |
| 2 | Davinci Gris | Polished Finish | |
| 3 | Desert Dune | Polished Finish | |
| 4 | Davinci Oro | Polished Finish | |
| 5 | Whitehaven | Polished Finish | UV Stable — Indoor/Outdoor |
| 6 | Cabarita | Matte Finish | UV Stable — Indoor/Outdoor |
| 7 | Torquay | Matte Finish | UV Stable — Indoor/Outdoor |
| 8 | Broome | Matte Finish | UV Stable — Indoor/Outdoor |

### Collection 04 — 8 stones (was 7)
| # | Stone | Finish | Change vs Old Site |
|---|-------|--------|--------------------|
| 1 | Opal Mist | Matte Finish | No change |
| 2 | Calacatta Leggera | Polished Finish | No change |
| 3 | Metallic Grey | Matte Finish | No change |
| 4 | Statuario Gold | Polished Finish | No change |
| 5 | Eternity | Polished Finish | No change |
| 6 | Glacier | Polished Finish | No change |
| 7 | White Cloud | Matte Finish | No change |
| 8 | Arabescato | Polished Finish | **MOVED from C05 to C04** |

### Collection 05 — 8 stones (was 3 — MAJOR CHANGES)
| # | Stone | Finish | Change vs Old Site |
|---|-------|--------|--------------------|
| 1 | Taj Mahal | Polished Finish | **MOVED from Alpha Zero to C05** (no longer discontinued) |
| 2 | Perla Mahal | Polished Finish | **BRAND NEW** |
| 3 | Calacatta Viola | Polished Finish | No change |
| 4 | Autumn Gold | Polished Finish | No change |
| 5 | Emerald Haze | Polished Finish | **BRAND NEW** |
| 6 | Viola Ligerra | Polished Finish | **BRAND NEW** |
| 7 | Crystal Mahal | Polished Finish | **BRAND NEW** |
| 8 | Venato | Polished Finish | **BRAND NEW** |

> Arabescato REMOVED from C05 (moved to C04). 5 brand new stones added. Taj Mahal moved from discontinued Alpha Zero — it is now a current product.

### Original Alpha Zero — 10 stones (DISCONTINUED)
| # | Stone | Finish |
|---|-------|--------|
| 1 | Silver Travertine | Matt Finish |
| 2 | Crystello | Matt Finish |
| 3 | Grande Glacier | Matt Finish |
| 4 | Basaltina | Matt Finish |
| 5 | Carbon | Matt Finish |
| 6 | Acropolis | Matt Finish |
| 7 | Glacier Grey | Polished Finish |
| 8 | Noosa | Matte Finish |
| 9 | Calacatta Oro | Polished Finish |
| 10 | Serena | Matte Finish |

> **REMOVED from site entirely (not in spreadsheet at all):** Venatino, Patagonia, Calacatta Borghini, Biscotti, Infinity Gris (5 stones removed). Taj Mahal moved to C05 (no longer here).

### Summary of All Changes
| Change | Stone(s) |
|--------|----------|
| **Added to C01** | Crystal (confirmed), Oyster (if not present) |
| **Removed from C01** | Bondi |
| **Moved C05 → C04** | Arabescato |
| **Moved Alpha Zero → C05** | Taj Mahal |
| **Brand new C05 stones** | Perla Mahal, Emerald Haze, Viola Ligerra, Crystal Mahal, Venato |
| **Removed entirely** | Bondi, Venatino, Patagonia, Calacatta Borghini, Biscotti, Infinity Gris |
| **Total** | Old site: 52 → New: **47** |

### Finish Shield/Badge Mapping
| Finish | Badge to Display |
|--------|-----------------|
| Polished Finish | Polished finish shield/icon |
| Matte Finish / Matt Finish | Matte finish shield/icon |
| UV Stable — Indoor/Outdoor (Notes column) | Indoor-Outdoor range starburst icon |

---

## TASK BREAKDOWN — ALL OUTSTANDING ITEMS

### PROMPT 01: Stone Data & Finishes Update
**Priority: HIGH — Foundation for everything else**
**Depends on:** Updated Google Sheet (RECEIVED — PDF export in uploads folder)

Tasks:
1. Read `public/data/stones.json` and cross-reference against the updated Google Sheet (47 stones)
2. Update `stones.json` to match the spreadsheet exactly:
   - Crystal confirmed in C01; add Oyster if missing; REMOVE Bondi
   - Move Arabescato from C05 to C04
   - Move Taj Mahal from Alpha Zero to C05 (no longer discontinued)
   - Add 5 brand new C05 stones: Perla Mahal, Emerald Haze, Viola Ligerra, Crystal Mahal, Venato
   - REMOVE 5 stones entirely: Venatino, Patagonia, Calacatta Borghini, Biscotti, Infinity Gris
   - Correct the `finish` field for every stone to match the spreadsheet
   - Ensure Collection 01 matches (Oyster in, Bondi/Crystal status TBD)
4. Ensure the `finish` field drives which shield/badge icon appears on each stone detail page
5. Add a `uv_stable` or `indoor_outdoor` boolean for the 4 C03 stones flagged as UV Stable
6. Update the total stone count wherever it appears in the codebase

### PROMPT 02: Certification Logos
**Priority: HIGH**
**Depends on:** Logo files in `assets/certification-logos/` (RECEIVED — 3 folders + EPD download)

Tasks:
1. Use the 3 certification logo folders already in the repo:
   - `assets/certification-logos/kosher/`
   - `assets/certification-logos/greenguard/`
   - `assets/certification-logos/nsf/`
2. Download the EPD logo from https://www.environdec.com/resources/brand-assets → save to `assets/certification-logos/epd/`
4. Create directory `public/images/certifications/` if it doesn't exist
5. Convert all logos to optimised WebP format, maintaining transparency
6. Determine where certification logos should appear:
   - On every stone detail page (in the certifications/shields area)
   - On the About page quality assurance section
   - On the Collections page quality assurance section
7. Add the logos to the HTML templates with proper sizing and alt text
8. Apply consistently across ALL stone detail pages

### PROMPT 03: Slab & Swatch Image Overhaul
**Priority: HIGH**
**Depends on:** `assets/slabs-closeups-2026/` folder (RECEIVED — already in repo)

Tasks:
1. Audit the contents of `assets/slabs-closeups-2026/` — list every file with dimensions
2. For each stone in Collections 01–05:
   - Check if a hi-res slab image exists in the assets folder
   - If yes: convert to WebP at ~1579×789, save as `{slug}-slab.webp` in `public/images/stones/`
   - If a better close-up/swatch exists: convert to WebP at ~800×571, save as `{slug}-swatch.webp`
3. For Alpha Zero stones still on the site:
   - Process available swatches from `assets/missing-swatches/` (acropolis, calacatta-borghini, elba, glacier-grey, mont-blanc, serena, unique-carrara)
   - Process swatches from `assets/alpha-zero-swatches/` (Basaltina, Calacatta Oro, Carbon, Grande Glacier, Silver Travertine, etc.)
   - Process the Calacatta Borghini slab from `assets/slabs-closeups-2026/27.AU71149-SLABCALACATTA-BORGHINI-scaled.jpg`
4. Update `stones.json` to point swatch fields to actual swatch files (not hero images)
5. For any Alpha Zero stones where slab images don't exist, either:
   - Hide the slab view toggle on that stone's detail page, OR
   - Show swatch-only with a "Full slab image unavailable" message
6. Verify every image loads correctly at all responsive breakpoints

### PROMPT 04: Homepage Updates
**Priority: HIGH**
**Depends on:** Figma exports, feature tile copy from Belinda/Jay

Tasks:
1. **"A" logo behaviour:**
   - Round the bottom of the "A" watermark SVG/image
   - Implement sticky behaviour: locks at base of hero images section
   - Implement fade-out: fades out as user scrolls below the hero section
   - Reference: current implementation uses `position: fixed` with parallax JS at 0.4× speed — adjust to new sticky+fade behaviour
2. **Intro/quote swap:**
   - On the homepage, swap the order so the intro paragraph comes FIRST, quote section comes SECOND
3. **Feature tiles copy:**
   - Update the copy on the homepage feature tiles (awaiting confirmed wording from Belinda/Jay)
   - If wording not yet received, leave a placeholder comment in code: `<!-- TODO: Update feature tile copy per Belinda/Jay confirmation -->`
4. **Text change:**
   - Find and replace the word "CRAFTSMANSHIP" with "SUPERIOR QUALITY AND DURABILITY" everywhere it appears on the site (Belinda's specific request from her follow-up email)
5. **Previously identified fixes (verify if already done):**
   - "Stone. Life. Style." spacing fix (space after "Stone.")
   - Autumn Gold duplicate label removal
   - "Click images to show full slabs" hint text on collection pages

### PROMPT 05: Collections Page Updates
**Priority: HIGH**
**Depends on:** Figma exports for correct kitchen image

Tasks:
1. **Hero image:** Keep the current hero image on the Collections page (confirmed)
2. **Kitchen image:** Replace the green kitchen image with the correct image from Figma
   - Export the correct image from Figma file `88KD34puTUAFmxuxM7k9rv`
   - Convert to WebP, optimise
   - Replace in the HTML
3. **Instagram section:**
   - Implement a live carousel pulling the latest 4 posts from `@alpha.surfaces` Instagram
   - This requires Instagram Basic Display API or Instagram Graph API credentials
   - **BLOCKED ON:** Belinda sending Instagram page link/handle and API access
   - Interim: build the carousel component with placeholder/static images and a clear integration point for when API credentials arrive
4. **Collection hero images:**
   - Verify C01, C04, C05 collection hero images are correct (these were committed in `f899227`)
   - Fix any remaining incorrect hero images per Belinda's feedback
5. **Navigation:**
   - Collections nav item should link directly to the collections page (remove or simplify the mega-dropdown that lists all stone names)
6. **Quality Assurance section:**
   - This section lives on collections.html — ensure certification logos from Prompt 02 are applied here

### PROMPT 06: About Page Updates
**Priority: HIGH**
**Depends on:** Figma export of bathroom/lifestyle image

Tasks:
1. **Hero image:** Replace the About page hero with the bathroom/lifestyle image that is currently on the Collections page in Figma
   - Export from Figma, convert to WebP
   - This is the image swap: bathroom image moves FROM Collections TO About
2. **Module layout:** Verify the about page module changes from the handoff update are committed:
   - Grid: `min(525px, 45%) 1fr` with `clamp(60px, 12vw, 174px)` gap
   - Images: `aspect-ratio: 1/1` (square per Figma 525×525)
   - Overlay: `padding-bottom: 35%`
   - ZERO SILICA: `.about-module-overlay-label` class, 26px font
   - Mobile: `aspect-ratio: 4/3`, single column
3. **Feature section icons:** Verify the overlay fixes are deployed:
   - Alpha Shield: shield logo only (no separate text span), `height: auto`
   - Indoor-Outdoor: starburst icon scaled to 160–220px
   - Zero Silica: text overlay only
4. **Emerald Haze label:** Verify the label fix (Carrara → Emerald Haze / Collection 05) on the kitchen image is done

### PROMPT 07: Alpha Zero / Discontinued Page
**Priority: MEDIUM-HIGH**
**Depends on:** Confirmed stone list (from updated spreadsheet), swatch images

Tasks:
1. **Rename section:** Rename from "Original Alpha Zero" to "Alpha Zero — Discontinued" (or similar approved naming)
2. **Discount messaging:** Add clear, prominent messaging:
   - "These colours are discontinued and available as run-out stock at significantly reduced prices"
   - "Contact Alpha Surfaces for current availability and pricing"
   - Add a CTA button/link to contact page or phone number
3. **Stone list:** Update to match the spreadsheet (10 stones, removing the 6 that are no longer listed — pending confirmation)
4. **Image behaviour:** Swatches click through to full slab view ONLY (no hero/detail page for discontinued stones)
5. **Discontinued swatch images from Belinda:** Process and apply any Alpha Zero swatch images received from Belinda
6. **Missing images decision:**
   - For stones with no images at all (Biscotti, Infinity Gris if they remain): remove from site
   - For stones with hero but no swatch: use hero as swatch with visual indicator that it's a close-up approximation

### PROMPT 08: Downloads Section & Documents
**Priority: MEDIUM-HIGH**
**Depends on:** All 3 documents RECEIVED — already in `assets/documents/`

Tasks:
1. **Create a Downloads section** with individual pages for each document, handled the same way as the Privacy Policy page:
   - Fabrication Guide page (`/fabrication-guide`)
   - Warranty page (`/warranty`)
   - Care & Maintenance page (`/care-and-maintenance`)
2. **Each page should have:**
   - The document content rendered as HTML (readable on-page)
   - A "Download PDF" button that serves the original PDF file
   - Consistent styling matching the Privacy Policy page
3. **Process the Care & Maintenance document:**
   - Source: `assets/documents/Alpha Surfaces Care and Maintence document - BK.docx`
   - Convert to both HTML (for on-page display) and PDF for download
   - Place PDF in `public/downloads/` directory
4. **Process the Fabrication Guide:**
   - Source: `assets/documents/Alpha Surfaces Fabrication and Installation Guide - BK.docx`
   - Same treatment as above
5. **Process the Warranty:**
   - Source: `assets/documents/Alpha Surfaces Warranty Download .docx`
   - Same treatment as above
5. **Add FAQ warranty button:** In the "What warranty is provided?" FAQ answer, add a direct link to the new Warranty page
6. **Footer update:** Replace "Product info" link with "DOWNLOADS" sub-header linking to a downloads index or the individual pages

### PROMPT 09: Social Links & Instagram
**Priority: MEDIUM**
**Depends on:** Instagram and Facebook page links from Belinda (STILL PENDING)

Tasks:
1. **Social links in footer/header:** Add Instagram and Facebook icon links
   - **BLOCKED ON:** Belinda sending the actual page URLs/handles
   - Build the HTML/CSS for the social links with placeholder `href="#"` values
   - Add a comment: `<!-- TODO: Replace with actual Instagram/Facebook URLs from Belinda -->`
2. **Instagram carousel on Collections page:** (see Prompt 05 task 3)
   - Build the UI component
   - Integration point for Instagram API when credentials arrive

### PROMPT 10: Cache Busting & Preview URL
**Priority: MEDIUM**
**Depends on:** Nothing — can be done anytime

Tasks:
1. **Cache busting:**
   - Increment all `?v=N` query strings on CSS and JS file references across all HTML files
   - Consider implementing an automated version string (e.g., based on git commit hash or build timestamp)
2. **Preview URL:**
   - Set up a `/preview` route that serves the site for shared review purposes
   - This could be as simple as a password-protected staging view or a specific URL path
   - Consider: Railway preview deployments from a `preview` branch

### PROMPT 11: Final QA & Verification
**Priority: CRITICAL — Run last**
**Depends on:** All other prompts completed

Tasks:
1. **Full site crawl:** Visit every page and verify:
   - All images load (no broken images, no placeholder text showing)
   - All links work (no 404s)
   - All stone detail pages render correctly with correct finish badges
   - Responsive layout works at mobile (375px), tablet (768px), desktop (1440px)
2. **stones.json audit:** Verify every stone in the JSON has:
   - Correct collection assignment
   - Correct finish value matching the spreadsheet
   - Valid image paths (hero, thumb, swatch, slab) that resolve to actual files
   - Correct certification/shield icons displaying
3. **Cross-page consistency:**
   - Navigation works on every page
   - Footer is consistent across all pages
   - Social links appear everywhere they should
   - Downloads section is accessible from footer and relevant FAQ answers
4. **Performance:**
   - All images are WebP format and appropriately sized
   - No oversized assets (check for any raw JPGs accidentally served)
   - CSS/JS files have cache-bust query strings
5. **Content accuracy:**
   - "SUPERIOR QUALITY AND DURABILITY" appears where "CRAFTSMANSHIP" was
   - All FAQ answers are current (slab size 3220 x 1620, mention local stone masons)
   - Alpha Zero section has discontinued messaging
   - No duplicate labels or text

---

## BLOCKING DEPENDENCIES — STATUS TRACKER

### RECEIVED / UNBLOCKED
| Item | Status | Location |
|------|--------|----------|
| Updated stone finishes spreadsheet | **RECEIVED** | PDF export: `prompts/Stone List and Finish - Sheet1.pdf` (in this repo). NOTE: Any .xlsx in workspace is STALE. |
| Certification logo files (3 of 4) | **RECEIVED** | `assets/certification-logos/kosher/`, `assets/certification-logos/greenguard/`, `assets/certification-logos/nsf/` |
| EPD logo | **AVAILABLE** | Download from https://www.environdec.com/resources/brand-assets → save to `assets/certification-logos/epd/` |
| Care & Maintenance document | **RECEIVED** | `assets/documents/Alpha Surfaces Care and Maintence document - BK.docx` |
| Fabrication Guide | **RECEIVED** | `assets/documents/Alpha Surfaces Fabrication and Installation Guide - BK.docx` |
| Warranty | **RECEIVED** | `assets/documents/Alpha Surfaces Warranty Download .docx` |
| Feature tile wording | **CONFIRMED** | "CRAFTSMANSHIP" → "SUPERIOR QUALITY AND DURABILITY" (Belinda's email) |
| Slab + Close-up images | **RECEIVED** | `assets/slabs-closeups-2026/` (RGB versions) |
| Alpha Zero partial swatches | **RECEIVED** | `assets/missing-swatches/` + `assets/alpha-zero-swatches/` |

### STILL PENDING FROM BELINDA
| Item | Impact | Action |
|------|--------|--------|
| Instagram page link/handle (`@alpha.surfaces` unconfirmed) | Blocks: live Instagram carousel, social links | Build shell/placeholder; connect when received |
| Facebook page link | Blocks: social links in footer | Build placeholder; connect when received |
| ~~Confirmation: C01 composition~~ | **RESOLVED** | C01 = 6 stones. Crystal CONFIRMED. Bondi REMOVED. Oyster IN. |
| ~~Confirmation: Alpha Zero removals~~ | **RESOLVED** | 5 removed entirely (Venatino, Patagonia, Calacatta Borghini, Biscotti, Infinity Gris). Taj Mahal moved to C05. Alpha Zero = 10 stones. |
| ~~Confirmation: C04 missing colour~~ | **RESOLVED** | C04 = 8 stones. Arabescato moved from C05 to C04. |
| ~~Confirmation: C05 additional colours~~ | **RESOLVED** | C05 = 8 stones. 5 brand new: Perla Mahal, Emerald Haze, Viola Ligerra, Crystal Mahal, Venato. Taj Mahal moved from Alpha Zero. |
| ~~5th certification logo~~ | **DROPPED** | Only 4 confirmed (Kosher, Greenguard, NSF, EPD). Proceed with 4 — if a 5th surfaces later it can be added post-launch. |
| ~~Fabrication Guide document~~ | **RECEIVED** | `assets/documents/Alpha Surfaces Fabrication and Installation Guide - BK.docx` |
| ~~Warranty document~~ | **RECEIVED** | `assets/documents/Alpha Surfaces Warranty Download .docx` |
| Discontinued Alpha Zero swatch images (remaining) | Blocks: full Alpha Zero visual coverage | Some received, some stones still have no swatch |
| Domain registrar / DNS access | Blocks: domain migration (post-launch task) | Not needed for preview/launch on Railway subdomain |

---

## EXECUTION ORDER

The prompts should be run in this order for maximum efficiency (dependencies flow downward):

```
PHASE 1 — DATA FOUNDATION (do first, everything depends on this)
  └─ Prompt 01: Stone Data & Finishes Update

PHASE 2 — ASSETS (can run in parallel after Phase 1)
  ├─ Prompt 02: Certification Logos
  └─ Prompt 03: Slab & Swatch Image Overhaul

PHASE 3 — PAGE UPDATES (can run in parallel after Phase 2)
  ├─ Prompt 04: Homepage Updates
  ├─ Prompt 05: Collections Page Updates
  ├─ Prompt 06: About Page Updates
  └─ Prompt 07: Alpha Zero / Discontinued Page

PHASE 4 — NEW FEATURES (after Phase 3)
  ├─ Prompt 08: Downloads Section & Documents
  └─ Prompt 09: Social Links & Instagram

PHASE 5 — DEPLOYMENT (after everything)
  ├─ Prompt 10: Cache Busting & Preview URL
  └─ Prompt 11: Final QA & Verification
```

---

## COMMIT STRATEGY

Each prompt should result in ONE clean commit with a descriptive message:
- `feat: update stones.json to match Belinda's updated finishes spreadsheet (47 stones, 6 collections)`
- `feat: add certification logos across all stone detail pages`
- `feat: replace slab/swatch images with hi-res versions from Dropbox`
- `feat: homepage — A logo sticky behaviour, intro/quote swap, text updates`
- `feat: collections — replace kitchen image, build Instagram carousel shell`
- `feat: about page — swap hero image, verify module layout`
- `feat: alpha zero — rename, add discontinued messaging, update stone list`
- `feat: add downloads section with Care & Maintenance, Warranty, Fabrication Guide pages`
- `feat: add social link placeholders for Instagram and Facebook`
- `chore: cache bust all CSS/JS references, add /preview route`
- `test: full site QA pass — fix any remaining issues`

After each commit: `git pull --rebase origin main && git push`

