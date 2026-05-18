#!/usr/bin/env node
/* eslint-disable no-console */
// Batch-injects GA4 + Microsoft Clarity into all public-facing HTML
// pages, and injects the landing-page-tracker on partner pages + kc.
//
// Idempotent: each injection is keyed on a marker comment, so re-running
// the script is a no-op. CMS/admin/forms pages are skipped — those are
// internal tools, not customer-facing.
//
// Usage:  node scripts/inject-analytics.js

const fs = require('fs');
const path = require('path');

const PUBLIC_DIR = path.resolve(__dirname, '..', 'public');
const GA_MEASUREMENT_ID = 'G-W0841557EV';
const CLARITY_PROJECT_ID = 'wsphsnhr52';

// Pages that get analytics but NOT the landing-page tracker.
const SKIP_PAGES = new Set([
  'admin.html',
  'forms.html',
  'nav.html', // dynamic nav partial — loaded into other pages
]);

// Pages that get the landing-page-tracker.js include in addition to analytics.
// Tracker self-disables without ?pid=, so it's safe on every partner page.
const TRACKER_PAGES = new Set();
fs.readdirSync(path.join(PUBLIC_DIR, 'partners'))
  .filter(f => f.endsWith('.html'))
  .forEach(f => TRACKER_PAGES.add(path.join('partners', f)));
TRACKER_PAGES.add('kc.html');

const ANALYTICS_MARKER = '<!-- ALPHA_ANALYTICS_V1 -->';
const TRACKER_MARKER = '<!-- ALPHA_LP_TRACKER_V1 -->';

const ANALYTICS_BLOCK = `${ANALYTICS_MARKER}
<!-- Google Analytics 4 -->
<script async src="https://www.googletagmanager.com/gtag/js?id=${GA_MEASUREMENT_ID}"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', '${GA_MEASUREMENT_ID}');
</script>
<!-- Microsoft Clarity -->
<script type="text/javascript">
  (function(c,l,a,r,i,t,y){
    c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)};
    t=l.createElement(r);t.async=1;t.src="https://www.clarity.ms/tag/"+i;
    y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y);
  })(window, document, "clarity", "script", "${CLARITY_PROJECT_ID}");
</script>
`;

const TRACKER_BLOCK = `${TRACKER_MARKER}
<script src="/landing-page-tracker.js"></script>
`;

function listHtmlFiles() {
  const out = [];
  fs.readdirSync(PUBLIC_DIR)
    .filter(f => f.endsWith('.html'))
    .forEach(f => out.push(f));
  const partnersDir = path.join(PUBLIC_DIR, 'partners');
  if (fs.existsSync(partnersDir)) {
    fs.readdirSync(partnersDir)
      .filter(f => f.endsWith('.html'))
      .forEach(f => out.push(path.join('partners', f)));
  }
  return out;
}

function injectInto(relPath) {
  const full = path.join(PUBLIC_DIR, relPath);
  const fileName = path.basename(relPath);
  let html = fs.readFileSync(full, 'utf8');
  let changed = false;

  if (SKIP_PAGES.has(fileName)) {
    return { relPath, skipped: 'internal page' };
  }

  // Analytics — only when </head> exists and marker not already there.
  if (html.indexOf(ANALYTICS_MARKER) === -1) {
    if (html.indexOf('</head>') === -1) {
      return { relPath, skipped: 'no </head>' };
    }
    html = html.replace('</head>', ANALYTICS_BLOCK + '</head>');
    changed = true;
  }

  // Landing-page tracker — only on partner pages + kc, only when </body>
  // exists and marker not already there.
  if (TRACKER_PAGES.has(relPath) && html.indexOf(TRACKER_MARKER) === -1) {
    if (html.indexOf('</body>') === -1) {
      return { relPath, skipped: 'no </body>' };
    }
    html = html.replace('</body>', TRACKER_BLOCK + '</body>');
    changed = true;
  }

  if (!changed) return { relPath, skipped: 'already injected' };
  fs.writeFileSync(full, html, 'utf8');
  return { relPath, written: true };
}

function main() {
  const files = listHtmlFiles();
  let wrote = 0, skipped = 0;
  for (const rel of files) {
    const r = injectInto(rel);
    if (r.written) {
      console.log(`  wrote   ${rel}`);
      wrote++;
    } else {
      console.log(`  skip    ${rel}  (${r.skipped})`);
      skipped++;
    }
  }
  console.log(`\nDone. ${wrote} updated, ${skipped} skipped, ${files.length} total.`);
}

main();
