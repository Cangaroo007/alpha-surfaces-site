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
