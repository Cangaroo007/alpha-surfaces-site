#!/usr/bin/env node
//
// One-time migration: replace the canonical 4-column <footer class="footer">…</footer>
// block in every page with a `<!-- FOOTER -->` marker. server.js injects
// views/partials/footer.html at request time.
//
// Idempotent — running twice is a no-op.
// Skips: any footer that doesn't contain `footer-inner` (e.g. partner pages
// with the "PRIVATE PARTNER PROPOSAL" footer, or any other non-canonical
// footer markup).

'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', 'public');
// Match the canonical 4-column footer block, optionally preceded by an
// existing `<!-- FOOTER -->` section comment (so we collapse both into a
// single marker rather than producing two).
const FOOTER_RE = /(?:<!--\s*FOOTER\s*-->\s*\n\s*)?<footer class="footer">[\s\S]*?<\/footer>/;
const MARKER = '<!-- FOOTER -->';

function walk(dir, out) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, out);
    } else if (entry.isFile() && entry.name.endsWith('.html')) {
      out.push(full);
    }
  }
  return out;
}

// `<!-- FOOTER -->` was historically used as a documentary section comment on
// many pages (right above the <footer> tag). After migration we want the
// marker to mean *exactly one thing*: "inject the canonical footer here".
// So on non-canonical pages we strip any orphan marker that's followed by a
// real <footer> block — otherwise the server-side injector would render the
// canonical footer ABOVE the page's own footer.
const ORPHAN_RE = /<!--\s*FOOTER\s*-->\s*\n\s*(?=<footer\b)/;

const stats = {
  migrated: [],
  skippedAlreadyMigrated: [],
  skippedNoFooter: [],
  skippedNonCanonical: [],
  orphansStripped: [],
};

for (const file of walk(ROOT, [])) {
  const rel = path.relative(ROOT, file);
  let html = fs.readFileSync(file, 'utf8');
  let changed = false;

  const match = html.match(FOOTER_RE);
  if (match && match[0].includes('footer-inner')) {
    html = html.replace(FOOTER_RE, MARKER);
    stats.migrated.push(rel);
    changed = true;
  } else if (match) {
    // Non-canonical footer (e.g. minimal partner copyright). Strip orphan
    // marker so injector doesn't fire on this page.
    if (ORPHAN_RE.test(html)) {
      html = html.replace(ORPHAN_RE, '');
      stats.orphansStripped.push(rel);
      changed = true;
    } else {
      stats.skippedNonCanonical.push(rel);
    }
  } else if (html.includes(MARKER)) {
    stats.skippedAlreadyMigrated.push(rel);
  } else {
    stats.skippedNoFooter.push(rel);
  }

  if (changed) fs.writeFileSync(file, html);
}

console.log(`Migrated:               ${stats.migrated.length}`);
console.log(`Already migrated:       ${stats.skippedAlreadyMigrated.length}`);
console.log(`Orphans stripped:       ${stats.orphansStripped.length}`);
console.log(`No footer (skipped):    ${stats.skippedNoFooter.length}`);
console.log(`Non-canonical (kept):   ${stats.skippedNonCanonical.length}`);

if (process.argv.includes('--verbose')) {
  console.log('\n--- Migrated ---');             stats.migrated.forEach(f => console.log('  ' + f));
  console.log('\n--- Already migrated ---');     stats.skippedAlreadyMigrated.forEach(f => console.log('  ' + f));
  console.log('\n--- Orphans stripped ---');     stats.orphansStripped.forEach(f => console.log('  ' + f));
  console.log('\n--- No footer ---');            stats.skippedNoFooter.forEach(f => console.log('  ' + f));
  console.log('\n--- Non-canonical (kept) ---'); stats.skippedNonCanonical.forEach(f => console.log('  ' + f));
}
