#!/usr/bin/env node
/**
 * Scrape partner logos using Puppeteer.
 * Usage: node scrape-logos.js
 */

const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const { URL } = require('url');

const OUT_DIR = path.join(__dirname, 'public', 'brand', 'logos');

const PARTNERS = [
  { slug: 'freedom-kitchens',    url: 'https://freedomkitchens.com.au' },
  { slug: 'kinsman-kitchens',    url: 'https://kinsman.com.au' },
  { slug: 'dream-doors',         url: 'https://dreamdoorskitchens.com.au' },
  { slug: 'kaboodle',            url: 'https://kaboodle.com.au' },
  { slug: 'harvey-norman-kitchens', url: 'https://harveynorman.com.au' },
  { slug: 'ikea-kitchens',       url: 'https://ikea.com/au' },
  { slug: 'hacker-australia',    url: 'https://hackeraustralia.com.au' },
  { slug: 'imperial-kitchens',   url: 'https://imperialkitchens.com.au' },
  { slug: 'craftbuilt-kitchens', url: 'https://craftbuilt.com.au' },
  { slug: 'damco-kitchens',      url: 'https://damcokitchens.com.au' },
  { slug: 'rods-kitchens',       url: 'https://rodskitchens.com.au' },
  { slug: 'align-kitchens',      url: 'https://alignkitchens.com.au' },
  { slug: 'kitchenu',            url: 'https://kitchenu.com.au' },
  { slug: 'mccoll-cabinetmakers', url: 'https://mccollcabinets.com.au' },
  { slug: 'qld-kitchen-centre',  url: 'https://qldkitchencentre.com.au' },
  { slug: 'wallspan',            url: 'https://wallspan.com.au' },
  { slug: 'flexi-renovation',    url: 'https://flexirenovationgroup.com.au' },
  { slug: 'designer-stone-qld',  url: 'https://designerstoneqld.com.au' },
  { slug: 'banks-benchtops',     url: 'https://banksbenchtops.com.au' },
  { slug: 'nv-stone',            url: 'https://nvstone.com.au' },
];

function extFromUrl(urlStr) {
  try {
    const p = new URL(urlStr).pathname.toLowerCase();
    if (p.endsWith('.svg')) return '.svg';
    if (p.endsWith('.png')) return '.png';
    if (p.endsWith('.webp')) return '.webp';
    if (p.endsWith('.jpg') || p.endsWith('.jpeg')) return '.jpg';
    if (p.endsWith('.gif')) return '.gif';
    if (p.endsWith('.ico')) return '.ico';
    return '.png'; // default
  } catch { return '.png'; }
}

function extFromContentType(ct) {
  if (!ct) return null;
  ct = ct.toLowerCase();
  if (ct.includes('svg')) return '.svg';
  if (ct.includes('png')) return '.png';
  if (ct.includes('webp')) return '.webp';
  if (ct.includes('jpeg') || ct.includes('jpg')) return '.jpg';
  if (ct.includes('gif')) return '.gif';
  if (ct.includes('icon')) return '.ico';
  return null;
}

function downloadFile(urlStr, destPath) {
  return new Promise((resolve, reject) => {
    const get = urlStr.startsWith('https') ? https.get : http.get;
    const doRequest = (u, redirects) => {
      if (redirects > 5) return reject(new Error('Too many redirects'));
      get(u, { headers: { 'User-Agent': 'Mozilla/5.0' } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          let loc = res.headers.location;
          if (loc.startsWith('/')) loc = new URL(loc, u).href;
          const getter = loc.startsWith('https') ? https.get : http.get;
          return doRequest(loc, redirects + 1);
        }
        if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));

        // Detect extension from content-type
        const ctExt = extFromContentType(res.headers['content-type']);
        if (ctExt) {
          const base = destPath.replace(/\.[^.]+$/, '');
          destPath = base + ctExt;
        }

        const ws = fs.createWriteStream(destPath);
        res.pipe(ws);
        ws.on('finish', () => {
          ws.close();
          // Check file is not empty / too small
          const stat = fs.statSync(destPath);
          if (stat.size < 100) {
            fs.unlinkSync(destPath);
            return reject(new Error('File too small'));
          }
          resolve(destPath);
        });
        ws.on('error', reject);
      }).on('error', reject);
    };
    doRequest(urlStr, 0);
  });
}

async function findLogo(page, baseUrl) {
  // Strategy: try multiple selectors, score them, pick the best
  const candidates = await page.evaluate((base) => {
    const results = [];
    const seen = new Set();

    function addCandidate(el, source, priority) {
      let src = '';
      if (el.tagName === 'IMG') {
        src = el.src || el.getAttribute('data-src') || el.getAttribute('data-lazy-src') || '';
      } else if (el.tagName === 'SOURCE') {
        src = el.srcset ? el.srcset.split(',')[0].trim().split(' ')[0] : '';
      }
      if (!src || seen.has(src)) return;
      // Skip tiny tracking pixels and data URIs
      if (src.startsWith('data:') && src.length < 200) return;
      if (el.naturalWidth && el.naturalWidth < 10) return;
      seen.add(src);
      results.push({ src, source, priority });
    }

    // 1. Header logo images (highest priority)
    document.querySelectorAll('header img, .header img, #header img, [role="banner"] img').forEach(el => {
      addCandidate(el, 'header img', 10);
    });

    // 2. Elements with "logo" in class/id
    document.querySelectorAll('[class*="logo" i] img, [id*="logo" i] img, img[class*="logo" i], img[id*="logo" i]').forEach(el => {
      addCandidate(el, 'logo class/id', 9);
    });

    // 3. Link to homepage containing an image
    document.querySelectorAll('a[href="/"] img, a[href="' + base + '"] img').forEach(el => {
      addCandidate(el, 'home link img', 8);
    });

    // 4. Alt text containing "logo"
    document.querySelectorAll('img[alt*="logo" i], img[alt*="Logo" i]').forEach(el => {
      addCandidate(el, 'alt=logo', 7);
    });

    // 5. SVG elements in header (inline logos)
    document.querySelectorAll('header svg, .header svg, [class*="logo" i] svg').forEach(el => {
      // Can't easily download inline SVGs, skip for now
    });

    // 6. First img in the first nav or top of page
    const firstNav = document.querySelector('nav img');
    if (firstNav) addCandidate(firstNav, 'nav img', 6);

    // 7. OG image as fallback
    const ogImage = document.querySelector('meta[property="og:image"]');
    if (ogImage && ogImage.content) {
      results.push({ src: ogImage.content, source: 'og:image', priority: 3 });
    }

    // 8. Apple touch icon
    const touchIcon = document.querySelector('link[rel="apple-touch-icon"]');
    if (touchIcon && touchIcon.href) {
      results.push({ src: touchIcon.href, source: 'apple-touch-icon', priority: 2 });
    }

    // 9. Favicon as last resort
    const favicon = document.querySelector('link[rel="icon"], link[rel="shortcut icon"]');
    if (favicon && favicon.href) {
      results.push({ src: favicon.href, source: 'favicon', priority: 1 });
    }

    // Prefer SVG, then PNG, then others
    results.forEach(r => {
      const lsrc = r.src.toLowerCase();
      if (lsrc.includes('.svg')) r.priority += 5;
      else if (lsrc.includes('.png')) r.priority += 2;
      else if (lsrc.includes('.webp')) r.priority += 1;
    });

    results.sort((a, b) => b.priority - a.priority);
    return results.slice(0, 5);
  }, baseUrl);

  return candidates;
}

(async () => {
  if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });

  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });

  const results = [];

  for (const partner of PARTNERS) {
    process.stdout.write(`\n${partner.slug} (${partner.url}) ... `);

    let page;
    try {
      page = await browser.newPage();
      await page.setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
      await page.setViewport({ width: 1440, height: 900 });

      await page.goto(partner.url, { waitUntil: 'networkidle2', timeout: 20000 });

      const candidates = await findLogo(page, partner.url);

      if (candidates.length === 0) {
        process.stdout.write('NO CANDIDATES');
        results.push({ slug: partner.slug, status: 'FAILED', reason: 'No logo found' });
        await page.close();
        continue;
      }

      // Try downloading candidates in priority order
      let downloaded = false;
      for (const cand of candidates) {
        try {
          let logoUrl = cand.src;
          // Make relative URLs absolute
          if (logoUrl.startsWith('/')) {
            const u = new URL(partner.url);
            logoUrl = u.origin + logoUrl;
          } else if (!logoUrl.startsWith('http')) {
            logoUrl = partner.url + '/' + logoUrl;
          }

          const ext = extFromUrl(logoUrl);
          const destPath = path.join(OUT_DIR, partner.slug + ext);

          const savedPath = await downloadFile(logoUrl, destPath);
          const savedExt = path.extname(savedPath);
          const size = fs.statSync(savedPath).size;

          process.stdout.write(`OK (${cand.source}, ${savedExt}, ${(size / 1024).toFixed(1)}KB)`);
          results.push({
            slug: partner.slug,
            status: 'OK',
            source: cand.source,
            file: path.basename(savedPath),
            size: `${(size / 1024).toFixed(1)}KB`,
          });
          downloaded = true;
          break;
        } catch (e) {
          // Try next candidate
          continue;
        }
      }

      if (!downloaded) {
        process.stdout.write('DOWNLOAD FAILED');
        results.push({ slug: partner.slug, status: 'FAILED', reason: 'All downloads failed', candidates: candidates.length });
      }

      await page.close();
    } catch (err) {
      process.stdout.write(`ERROR: ${err.message}`);
      results.push({ slug: partner.slug, status: 'FAILED', reason: err.message });
      if (page) await page.close().catch(() => {});
    }
  }

  await browser.close();

  // Summary
  console.log('\n\n' + '='.repeat(60));
  console.log('LOGO SCRAPING SUMMARY');
  console.log('='.repeat(60));

  const ok = results.filter(r => r.status === 'OK');
  const failed = results.filter(r => r.status !== 'OK');

  console.log(`\nFound: ${ok.length}/${results.length}`);
  console.log('');

  ok.forEach(r => {
    console.log(`  ✓ ${r.slug.padEnd(25)} ${r.file.padEnd(35)} ${r.size.padStart(8)}  (${r.source})`);
  });

  if (failed.length > 0) {
    console.log(`\nFailed: ${failed.length}`);
    failed.forEach(r => {
      console.log(`  ✗ ${r.slug.padEnd(25)} ${r.reason}`);
    });
  }

  console.log('');
})();
