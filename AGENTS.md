# Alpha Surfaces Agent Notes

## Public slab pages must not depend only on the CMS API

The surface detail pages under `public/surfaces/*.html` are static shells that
hydrate product content in the browser. In production, `/api/public/stones` can
hang or return incomplete CMS data during database/CMS trouble. When that
happens, pages such as `/surfaces/calacatta-leggera` show only the nav, blank
body bands, and footer.

Keep these protections in place:

- Surface pages load `public/public-stones-loader.js` before their inline render
  script and call `window.loadPublicStones('../data/stones.json', slug)`.
- `public/collections.html` calls `window.loadPublicStones('/data/stones.json')`.
- The loader aborts the managed API after a short timeout and falls back to the
  checked-in `public/data/stones.json`.
- `cms-core.js` also falls back to static stone data when CMS data is empty,
  stale, slow, or unavailable.
- `db.js` has PostgreSQL timeout settings so public endpoints are not pinned
  indefinitely by database connection/query waits.

If a future update regenerates the surface HTML files, reapply the loader script
tag and `window.loadPublicStones(...)` call across all generated pages.

## Branching and deployment
- main is STAGING (review.alphasurfaces.com.au). production is LIVE
  (alphasurfaces.com.au). This is the opposite of the usual convention and is
  the most likely operator error.
- Workflow: commit to main, verify on staging, then checkout production,
  merge main, push, then purge Cloudflare.
- Agents must NOT create branches or open PRs. Commit to the checked-out branch.
  Work split across branches has to be manually reassembled and has previously
  come close to reverting production-only fixes.

## Files that must never be replaced wholesale
server.js, db.js, cms-core.js, projects-routes.js, nav.js,
public-stones-loader.js, form-rescue.js, form-fallback-queue.js
These carry outage-hardening and CMS-fallback logic. Targeted line edits only.
Never use `git checkout <branch> -- <file>` on them.

## Deleted on purpose — do not reinstate
- public/surfaces/oyster.html and the Oyster entry in stones.json
- public/forms.html (superseded by the projects portal)

## Local development
node server.js works against whatever DATABASE_URL points at; SSL is applied for
remote hosts and skipped for localhost. Do NOT use `railway run node server.js`
— it injects DATA_DIR=/app/data, a container path that doesn't exist locally,
and the server exits immediately.

## Deployment timing
Railway takes 5-8 minutes to build and release. Checking sooner returns the
previous build and looks like a failed deploy. Purge Cloudflare only AFTER
confirming the new build is live, or the purge runs against old files.

## Image assets
Belinda supplies two files per stone: CLOSE UP (the swatch photo) and SLAB.
- CLOSE UP -> {slug}-swatch.webp at 800x571 (7:5), grid tile
- CLOSE UP -> {slug}-thumb.webp at 400x286 (7:5), tile fallback
- CLOSE UP -> {slug}.webp at 1800w, product hero
- SLAB -> {slug}-slab.webp at 2400w, lightbox and full-bleed band
.stone-card-image is aspect-ratio 7/5, matching the close-ups so swatches are
not cropped. The full-bleed band must use (stone.slab || stone.image) — using
the close-up there magnifies the stone about 10x and looks like gravel.

## FlippingBook brochure
The embed script redirects to d33i2vgywgme2s.cloudfront.net, which must remain
in the CSP scriptSrc in server.js. Without it the script is silently blocked and
the brochure page renders blank. If FlippingBook migrates CDN this host changes;
the symptom is a blank brochure with a CSP error in the console.
