/* Campaign builder renderer: turns a campaign spec (made in RoadRunner,
 * /campaigns) into the landing page. The spec arrives in
 * <script id="cp-spec" type="application/json">, injected by server.js.
 *
 * Everything in the spec is TEXT. It is escaped here; the only markup allowed
 * is **bold** and [link](/path or https://...). Nothing typed in the builder
 * can put HTML on the website.
 */
(function () {
  'use strict';
  var C = window.AlphaCampaign;
  var el = document.getElementById('cp-spec');
  if (!C || !el) return;
  var payload = JSON.parse(el.textContent || '{}');
  var spec = payload.spec || {}, slug = payload.slug, preview = !!payload.preview, base = '/c/' + slug;
  var root = document.getElementById('cp-root');
  var BG = { cream: ' cream', paper: ' paper', white: '' };

  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
  function md(s) {
    return esc(s).replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>').replace(/\[([^\]]+)\]\(((?:\/|https:\/\/)[^\s)]*)\)/g, function (_m, t, u) {
      return '<a href="' + u + '"' + (u.charAt(0) === '/' ? ' data-keep' : ' target="_blank" rel="noopener"') + '>' + t + '</a>';
    }).replace(/\n/g, '<br>');
  }
  var stonesId = null;
  (spec.sections || []).forEach(function (s, i) { if (s.type === 'stones' && !stonesId) stonesId = s.id || ('stones-' + i); });
  function href(target) {
    if (target === 'order') return '#' + (stonesId || '');
    if (target === 'enquire') return base + '/enquire';
    return target;
  }
  function buttons(list) {
    if (!list || !list.length) return '';
    return '<div class="cp-btns">' + list.map(function (b) {
      var h = href(b.target), keep = h.charAt(0) === '/' ? ' data-keep' : '';
      return '<a class="cp-btn' + (b.style === 'ghost' ? ' ghost' : '') + '" href="' + esc(h) + '"' + keep + '>' + esc(b.label) + '</a>';
    }).join('') + '</div>';
  }
  function sec(s, i, inner) {
    var id = s.id || (s.type === 'stones' ? 'stones-' + i : '');
    return '<section class="cp-section' + (BG[s.background] || '') + '"' + (id ? ' id="' + esc(id) + '"' : '') + '><div class="cp-wrap">' + inner + '</div></section>';
  }
  function heading(s, tag) { return (s.eyebrow ? '<p class="cp-eyebrow">' + esc(s.eyebrow) + '</p>' : '') + (s.heading ? '<' + (tag || 'h2') + ' class="cp-h2">' + esc(s.heading) + '</' + (tag || 'h2') + '>' : ''); }

  var h = spec.hero || {}, html = [];
  if (preview) html.push('<div style="position:sticky;top:0;z-index:50;background:#564d22;color:#fff;text-align:center;padding:8px 12px;font:600 13px/1.4 Degular,sans-serif">Preview of a draft campaign. Not live, not tracked.</div>');
  if (payload.status === 'ended') html.push('<div style="background:#f3f1e6;text-align:center;padding:14px 16px;font:500 15px/1.5 Degular,sans-serif">This offer has ended, but samples are still free. Pick up to three below.</div>');
  html.push('<header class="cp-hero"><div class="cp-hero-media">' +
    (h.stoneTiles && h.stoneTiles.length ? '<div class="cp-hero-tiles" id="cp-tiles"></div>' : '<img src="' + esc(h.image || '') + '" alt="' + esc(h.imageAlt || '') + '">') +
    '</div><div class="cp-hero-copy">' + (h.eyebrow ? '<p class="cp-eyebrow">' + esc(h.eyebrow) + '</p>' : '') +
    '<h1 class="cp-h1">' + esc(h.heading) + '</h1>' + (h.text ? '<p class="cp-lede" style="margin-top:18px">' + md(h.text) + '</p>' : '') +
    buttons(h.buttons) + (h.note ? '<p class="cp-sub" style="margin-top:18px;font-size:14px">' + md(h.note) + '</p>' : '') + '</div></header>');

  var mounts = [];
  (spec.sections || []).forEach(function (s, i) {
    if (s.type === 'points') {
      html.push(sec(s, i, '<div class="cp-points">' + s.items.map(function (p) { return '<div class="cp-point"><b>' + esc(p.title) + '</b><span>' + esc(p.text) + '</span></div>'; }).join('') + '</div>'));
    } else if (s.type === 'certifications') {
      html.push(sec(s, i, (s.text ? '<p class="cp-sub">' + md(s.text) + '</p>' : '') + '<div class="cp-certs">' +
        [['nsf', 'NSF International Certified'], ['greenguard', 'UL Greenguard Certified'], ['greenguard-gold', 'UL Greenguard Gold Certified'], ['kosher', 'Kosher Certified'], ['epd', 'International EPD System']]
          .map(function (c) { return '<img src="/images/certifications/' + c[0] + '.webp" alt="' + c[1] + '" loading="lazy">'; }).join('') + '</div>'));
    } else if (s.type === 'feature') {
      var media = s.video ? '<div class="cp-split-media"><video src="' + esc(s.video) + '" autoplay muted loop playsinline preload="metadata"></video></div>'
        : s.image ? '<div class="cp-split-media"><img src="' + esc(s.image) + '" alt="' + esc(s.imageAlt || '') + '" loading="lazy"></div>' : '';
      var copy = '<div>' + heading(s) + (s.text ? '<p class="cp-sub">' + md(s.text) + '</p>' : '') +
        (s.bullets && s.bullets.length ? '<ul class="cp-reasons">' + s.bullets.map(function (b) { return '<li>' + md(b) + '</li>'; }).join('') + '</ul>' : '') + '</div>';
      html.push('<section class="cp-section' + (BG[s.background] || '') + '"' + (s.id ? ' id="' + esc(s.id) + '"' : '') + '><div class="cp-wrap' + (media ? ' cp-split' : '') + '">' +
        (s.imageSide === 'left' ? media + copy : copy + media) + '</div></section>');
    } else if (s.type === 'stones') {
      html.push(sec(s, i, heading(s) + '<div id="cp-grid-' + i + '" style="margin-top:26px"></div>'));
      mounts.push(function () {
        C.mountGrid(document.getElementById('cp-grid-' + i), { page: 'c-' + slug, orderPath: base + '/order', howto: s.howto, cta: s.cta,
          groupBy: s.groupBy === 'direction' ? 'direction' : undefined, filters: s.filters === false ? false : undefined, include: s.include, exclude: s.exclude });
      });
    } else if (s.type === 'directions') {
      html.push(sec(s, i, heading(s) + (s.text ? '<p class="cp-sub">' + md(s.text) + '</p>' : '') + '<div class="cp-dirs" id="cp-dirs-' + i + '"></div>'));
      mounts.push(function () {
        C.mountDirections(document.getElementById('cp-dirs-' + i), function (dir) {
          var g = document.querySelector('[id^="cp-grid-"]'); if (g && g._grid) g._grid.showDirection(dir);
        });
      });
    } else if (s.type === 'faq') {
      html.push(sec(s, i, heading(s) + '<div class="cp-faq" id="cp-faq-' + i + '">' + s.items.map(function (q) {
        return '<details' + (q.set ? ' data-set="' + esc(q.set) + '"' : '') + '><summary>' + esc(q.q) + '</summary><div class="a">' + md(q.a) + '</div></details>';
      }).join('') + '</div>'));
      mounts.push(function () { C.orderFaq(document.getElementById('cp-faq-' + i)); });
    } else if (s.type === 'showrooms') {
      html.push(sec(s, i, heading(s) + (s.text ? '<p class="cp-sub">' + md(s.text) + '</p>' : '') + '<div class="cp-rooms" id="cp-rooms-' + i + '"></div>'));
      mounts.push(function () { C.mountShowrooms(document.getElementById('cp-rooms-' + i), s.only); });
    } else if (s.type === 'text') {
      html.push(sec(s, i, heading(s) + '<p class="cp-sub" style="max-width:760px">' + md(s.text) + '</p>'));
    } else if (s.type === 'close') {
      html.push('<section class="cp-close"' + (s.id ? ' id="' + esc(s.id) + '"' : '') + '><div class="cp-wrap"><h2 class="cp-h2">' + esc(s.heading) + '</h2>' +
        (s.text ? '<p class="cp-sub" style="color:inherit;opacity:.85">' + md(s.text) + '</p>' : '') + buttons(s.buttons) + '</div></section>');
    }
  });
  root.innerHTML = html.join('');
  mounts.forEach(function (f) { f(); });
  C.wireLinks(root);
  if (h.stoneTiles && h.stoneTiles.length) {
    C.loadStones().then(function (d) {
      document.getElementById('cp-tiles').innerHTML = h.stoneTiles.map(function (sl) {
        var s = d.stones.filter(function (x) { return x.slug === sl; })[0];
        return s ? '<img src="' + esc(s.img) + '" alt="' + esc(s.name) + ' sample">' : '';
      }).join('');
    });
  }
  if (!preview) C.track('ViewContent', { content_name: 'campaign_' + slug });
})();
