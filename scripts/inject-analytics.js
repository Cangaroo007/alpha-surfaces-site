#!/usr/bin/env node
/* eslint-disable no-console */
// Batch-injects analytics into all public-facing HTML pages, and injects the
// landing-page-tracker on partner pages + kc.
//
// V2 (sprintrep, 26 Oct 2026): every page gets the sprintrep cookie notice and
// first-party tracker, and Google Analytics 4 + Microsoft Clarity load ONLY
// after the visitor allows analytics. V1 blocks (GA4 + Clarity loaded for
// everyone) are replaced in place. Campaign pages' CP_ANALYTICS block is
// replaced the same way. A "Cookie settings" link is added to page footers.
//
// Idempotent: each injection is keyed on a marker comment, so re-running
// the script is a no-op. CMS/admin/forms pages are skipped - those are
// internal tools, not customer-facing.
//
// The sprintrep tracker line itself (<script src=".../t.js?site=...">) is NOT
// written into the files: server.js adds it to every page carrying the V2
// marker when SPRINTREP_TRACKER_ORIGIN and SPRINTREP_SITE_ID are set on the
// host. Until then no consent is ever given, so nothing optional loads.
//
// Pages without a V1 block (internal agendas, training pages) are left alone,
// except the colour pages (public/surfaces), which get the V2 block.
//
// GA4 and Clarity: if sprintrep already loaded them (their ids are set in
// sprintrep's Website traffic settings), this block does not load them again.
//
// Usage:
//   node scripts/inject-analytics.js            # dry run: lists what would change
//   node scripts/inject-analytics.js --apply    # writes the files

const fs = require('fs');
const path = require('path');

const PUBLIC_DIR = path.resolve(__dirname, '..', 'public');
const GA_MEASUREMENT_ID = 'G-W0841557EV';
const CLARITY_PROJECT_ID = 'wsphsnhr52';
const APPLY = process.argv.includes('--apply');

// Pages that get analytics but NOT the landing-page tracker.
const SKIP_PAGES = new Set([
  'admin.html',
  'forms.html',
  'nav.html', // dynamic nav partial — loaded into other pages
  'projects.html', // staff project tracker: no cookie notice, no visitor tracking
]);

// Pages that get the landing-page-tracker.js include in addition to analytics.
// Tracker self-disables without ?pid=, so it's safe on every partner page.
const TRACKER_PAGES = new Set();
fs.readdirSync(path.join(PUBLIC_DIR, 'partners'))
  .filter(f => f.endsWith('.html'))
  .forEach(f => TRACKER_PAGES.add(path.join('partners', f)));
TRACKER_PAGES.add('kc.html');

const V1_MARKER = '<!-- ALPHA_ANALYTICS_V1 -->';
const ANALYTICS_MARKER = '<!-- ALPHA_ANALYTICS_V2 -->';
const TRACKER_MARKER = '<!-- ALPHA_LP_TRACKER_V1 -->';
const COOKIE_LINK_MARKER = '<!-- ALPHA_COOKIE_LINK_V1 -->';
const CP_START = '<!-- CP_ANALYTICS_START -->';
const CP_END = '<!-- CP_ANALYTICS_END -->';

// Client code: string concatenation only, no template literals.
const ANALYTICS_BLOCK = `${ANALYTICS_MARKER}
<!-- Google Analytics 4 + Microsoft Clarity: loaded only after analytics consent (sprintrep cookie notice) -->
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('consent', 'default', { analytics_storage: 'denied', ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied' });
  (function () {
    var loaded = false;
    function has(part) { return !!document.querySelector('script[src*="' + part + '"]'); }
    function load() {
      if (loaded) { return; }
      loaded = true;
      gtag('consent', 'update', { analytics_storage: 'granted' });
      if (!has('googletagmanager.com/gtag/js')) {
        var g = document.createElement('script');
        g.async = true;
        g.src = 'https://www.googletagmanager.com/gtag/js?id=${GA_MEASUREMENT_ID}';
        document.head.appendChild(g);
        gtag('js', new Date());
        gtag('config', '${GA_MEASUREMENT_ID}');
      }
      if (!has('clarity.ms/tag/')) (function(c,l,a,r,i,t,y){
        c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)};
        t=l.createElement(r);t.async=1;t.src="https://www.clarity.ms/tag/"+i;
        y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y);
      })(window, document, "clarity", "script", "${CLARITY_PROJECT_ID}");
    }
    // The sprintrep tracker decides (saved choice, region, Global Privacy
    // Control) and announces it on load and on every change.
    if (window.sprintrepConsent && window.sprintrepConsent.analytics) { load(); }
    document.addEventListener('sprintrep:consent', function (e) {
      if (e.detail && e.detail.analytics) { load(); }
    });
  })();
</script>
`;

const TRACKER_BLOCK = `${TRACKER_MARKER}
<script src="/landing-page-tracker.js"></script>
`;

const COOKIE_LINK = `${COOKIE_LINK_MARKER}<p class="alpha-cookie-link"><a href="#cookie-settings" data-sr-consent style="text-decoration:underline;text-underline-offset:2px;">Cookie settings</a></p>
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
  // Colour pages never had the V1 block; they get the consent-gated block too.
  const surfacesDir = path.join(PUBLIC_DIR, 'surfaces');
  if (fs.existsSync(surfacesDir)) {
    fs.readdirSync(surfacesDir)
      .filter(f => f.endsWith('.html'))
      .forEach(f => out.push(path.join('surfaces', f)));
  }
  return out;
}

// The V1 block: from its marker to the end of the Clarity <script>.
function removeV1(html) {
  const start = html.indexOf(V1_MARKER);
  if (start === -1) return html;
  const clarity = html.indexOf('"clarity"', start);
  const end = clarity === -1 ? -1 : html.indexOf('</script>', clarity);
  if (end === -1) return html;
  let stop = end + '</script>'.length;
  if (html[stop] === '\n') stop += 1;
  // Keep the site's own scripts that sit inside the old block (order-sample
  // loads /meta-pixel.js there; the pixel itself now waits for consent).
  const kept = html.slice(start, stop).split('\n').filter((line, i, lines) =>
    /^<script src="\/[^"]+"><\/script>$/.test(line.trim()) ||
    (/^<!--/.test(line.trim()) && lines[i + 1] && /^<script src="\/[^"]+"><\/script>$/.test(lines[i + 1].trim()))
  );
  return html.slice(0, start) + (kept.length ? kept.join('\n') + '\n' : '') + html.slice(stop);
}

function injectInto(relPath) {
  const full = path.join(PUBLIC_DIR, relPath);
  const fileName = path.basename(relPath);
  let html = fs.readFileSync(full, 'utf8');
  const before = html;

  if (SKIP_PAGES.has(fileName)) {
    return { relPath, skipped: 'internal page' };
  }

  // Campaign page template: its own analytics block becomes the consent-gated one.
  if (html.indexOf(CP_START) !== -1 && html.indexOf(CP_END) !== -1 && html.indexOf(ANALYTICS_MARKER) === -1) {
    const a = html.indexOf(CP_START) + CP_START.length;
    const b = html.indexOf(CP_END);
    html = html.slice(0, a) + '\n' + ANALYTICS_BLOCK + '<script src="/meta-pixel.js"></script>\n' + html.slice(b);
  }

  // Analytics: V1 replaced by V2, only on pages that had V1 (customer-facing).
  const colourPage = relPath.indexOf('surfaces' + path.sep) === 0;
  if (html.indexOf(ANALYTICS_MARKER) === -1 && (html.indexOf(V1_MARKER) !== -1 || colourPage)) {
    if (html.indexOf('</head>') === -1) {
      return { relPath, skipped: 'no </head>' };
    }
    html = removeV1(html);
    html = html.replace('</head>', ANALYTICS_BLOCK + '</head>');
  }

  // "Cookie settings" in the page's own footer (the shared footer partial has its own).
  if (html.indexOf(COOKIE_LINK_MARKER) === -1 && html.indexOf('</footer>') !== -1) {
    html = html.replace('</footer>', COOKIE_LINK + '</footer>');
  }

  // Landing-page tracker — only on partner pages + kc, only when </body>
  // exists and marker not already there.
  if (TRACKER_PAGES.has(relPath) && html.indexOf(TRACKER_MARKER) === -1) {
    if (html.indexOf('</body>') === -1) {
      return { relPath, skipped: 'no </body>' };
    }
    html = html.replace('</body>', TRACKER_BLOCK + '</body>');
  }

  if (html === before) return { relPath, skipped: 'already injected' };
  if (APPLY) fs.writeFileSync(full, html, 'utf8');
  return { relPath, written: true };
}

function main() {
  const files = listHtmlFiles();
  let wrote = 0, skipped = 0;
  for (const rel of files) {
    const r = injectInto(rel);
    if (r.written) {
      console.log(`  ${APPLY ? 'wrote ' : 'would write'}   ${rel}`);
      wrote++;
    } else {
      console.log(`  skip    ${rel}  (${r.skipped})`);
      skipped++;
    }
  }
  console.log(`\nDone${APPLY ? '' : ' (dry run; add --apply to write)'}. ${wrote} ${APPLY ? 'updated' : 'to update'}, ${skipped} skipped, ${files.length} total.`);
}

main();
