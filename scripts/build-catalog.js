#!/usr/bin/env node
/**
 * scripts/build-catalog.js
 *
 * Renders a PDF into per-page WebP images and a manifest.json suitable for
 * the Alpha Surfaces flipbook viewer (public/catalog/viewer.html).
 *
 * Usage:
 *   node scripts/build-catalog.js <pdf> <slug> "<title>"
 *
 * Example:
 *   node scripts/build-catalog.js ./Alpha_Surfaces_Brochure.pdf brochure "Alpha Surfaces Brochure"
 *
 * Output:
 *   public/catalogs/<slug>/pages/001.webp ... NNN.webp
 *   public/catalogs/<slug>/manifest.json
 *
 * Requires (system tools — install via Homebrew on macOS):
 *   brew install poppler imagemagick
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

// ── Args ───────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
if (args.length < 3) {
  console.error('Usage: node scripts/build-catalog.js <pdf> <slug> "<title>"');
  process.exit(1);
}
const [pdfArg, slug, title] = args;

const pdfPath = path.resolve(pdfArg);
if (!fs.existsSync(pdfPath)) {
  console.error(`PDF not found: ${pdfPath}`);
  process.exit(1);
}
if (!/^[a-z0-9][a-z0-9-]*$/.test(slug)) {
  console.error(`Invalid slug: ${slug} (lowercase letters, digits, hyphens)`);
  process.exit(1);
}

// ── Paths ──────────────────────────────────────────────────────────────────
const REPO_ROOT = path.resolve(__dirname, '..');
const OUT_DIR = path.join(REPO_ROOT, 'public', 'catalogs', slug);
const PAGES_DIR = path.join(OUT_DIR, 'pages');
fs.mkdirSync(PAGES_DIR, { recursive: true });

// Clear any previous pages so a re-build is clean
for (const f of fs.readdirSync(PAGES_DIR)) {
  if (/\.(webp|png|jpg|jpeg)$/i.test(f)) fs.unlinkSync(path.join(PAGES_DIR, f));
}

// ── Render PDF → temporary JPEGs via pdftoppm ──────────────────────────────
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `catalog-${slug}-`));
const tmpPrefix = path.join(tmpDir, 'page');

console.log(`→ Rendering ${path.basename(pdfPath)} at 300 DPI…`);
try {
  execFileSync(
    'pdftoppm',
    ['-r', '300', '-jpeg', '-jpegopt', 'quality=95', pdfPath, tmpPrefix],
    { stdio: ['ignore', 'inherit', 'inherit'] }
  );
} catch (err) {
  console.error('pdftoppm failed. Install via: brew install poppler');
  process.exit(1);
}

const rendered = fs
  .readdirSync(tmpDir)
  .filter((f) => /^page-\d+\.jpg$/.test(f))
  .sort((a, b) => {
    const an = parseInt(a.match(/(\d+)/)[1], 10);
    const bn = parseInt(b.match(/(\d+)/)[1], 10);
    return an - bn;
  });
console.log(`  rendered ${rendered.length} pages`);

// ── Convert to WebP at ≤2400px wide via ImageMagick ────────────────────────
// 2400w handles retina at ~1200px CSS spreads; q88 is visually lossless for text/photos.
console.log(`→ Encoding to WebP (max 2400w, q88)…`);
const pages = [];
rendered.forEach((file, i) => {
  const num = String(i + 1).padStart(3, '0');
  const src = path.join(tmpDir, file);
  const dest = path.join(PAGES_DIR, `${num}.webp`);
  try {
    execFileSync(
      'convert',
      [
        src,
        '-resize', '2400x>',
        '-define', 'webp:method=6',     // slowest/best compression
        '-define', 'webp:image-hint=photo',
        '-quality', '88',
        '-strip',
        `webp:${dest}`,
      ],
      { stdio: ['ignore', 'pipe', 'inherit'] }
    );
  } catch (err) {
    console.error(`convert failed on page ${num}. Install via: brew install imagemagick`);
    process.exit(1);
  }
  const dim = execFileSync('identify', ['-format', '%w %h', dest], { encoding: 'utf8' }).trim();
  const [w, h] = dim.split(/\s+/).map(Number);
  const bytes = fs.statSync(dest).size;
  pages.push({ src: `pages/${num}.webp`, w, h, bytes });
});

// ── Cleanup tmp ────────────────────────────────────────────────────────────
for (const f of fs.readdirSync(tmpDir)) fs.unlinkSync(path.join(tmpDir, f));
fs.rmdirSync(tmpDir);

// ── Write manifest ─────────────────────────────────────────────────────────
const totalBytes = pages.reduce((s, p) => s + p.bytes, 0);
const baseWidth = pages[0]?.w || 0;
const baseHeight = pages[0]?.h || 0;

const manifest = {
  slug,
  title,
  pageCount: pages.length,
  baseWidth,
  baseHeight,
  aspectRatio: baseHeight > 0 ? +(baseWidth / baseHeight).toFixed(4) : 1,
  pdfDownload: `/downloads/${slug}.pdf`,
  pages: pages.map(({ src, w, h }) => ({ src, w, h })),
  totalImageBytes: totalBytes,
  generatedAt: new Date().toISOString(),
};

fs.writeFileSync(
  path.join(OUT_DIR, 'manifest.json'),
  JSON.stringify(manifest, null, 2) + '\n'
);

console.log(
  `✓ ${slug}: ${pages.length} pages, ${(totalBytes / 1024 / 1024).toFixed(2)} MB total → public/catalogs/${slug}/`
);
