/* Meta campaign landing pages — shared behaviour.
 *
 * Every step of the campaign journey is its own page with its own URL (no
 * pop-ups), so Meta and GA4 can measure each one:
 *   /free-samples          → /free-samples/order?stones=a,b,c
 *   /discover              → /discover/order?stones=…   and   /discover/enquire
 * The order pages are the existing /order-sample form, unchanged.
 *
 * Campaign parameters (utm_*, fbclid) on the landing URL are carried onto
 * every link this script builds, so the lead that lands in Pipedrive keeps
 * its Campaign / UTM value.
 */
(function () {
  'use strict';
  var MAX = 3;
  var KEEP = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term', 'fbclid', 'faq'];
  var here = new URLSearchParams(location.search);

  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
  function track(name, params) { try { if (window.alphaTrack) window.alphaTrack(name, params || {}); } catch (e) {} }

  function withParams(href, extra) {
    var u = new URL(href, location.origin);
    KEEP.forEach(function (k) { var v = here.get(k); if (v && !u.searchParams.has(k)) u.searchParams.set(k, v); });
    Object.keys(extra || {}).forEach(function (k) { if (extra[k]) u.searchParams.set(k, extra[k]); else u.searchParams.delete(k); });
    return u.pathname + u.search + u.hash;
  }
  // Static links marked data-keep carry the campaign parameters too.
  function wireLinks(root) {
    Array.prototype.forEach.call((root || document).querySelectorAll('a[data-keep]'), function (a) {
      a.setAttribute('href', withParams(a.getAttribute('href')));
    });
  }

  var stonesPromise = null;
  function loadStones() {
    if (stonesPromise) return stonesPromise;
    stonesPromise = Promise.all([
      fetch('/data/stones.json').then(function (r) { return r.json(); }),
      fetch('/data/stone-looks.json').then(function (r) { return r.json(); })
    ]).then(function (res) {
      var data = res[0], looks = res[1].stones || {}, out = [];
      (data.collections || []).forEach(function (c) {
        (c.stones || []).forEach(function (s) {
          var t = looks[s.slug];
          if (s.discontinued || !t) return;   // campaign pages show the current range only
          out.push({ slug: s.slug, name: s.name, collection: c.name, img: s.thumbnail || s.swatch || s.image,
            tone: t.tone, pattern: t.pattern, direction: t.direction });
        });
      });
      return { stones: out, showrooms: res[1].showrooms || [] };
    });
    return stonesPromise;
  }

  var DIRS = [
    { id: 'warm-natural',  name: 'Warm + Natural',  line: 'Warm tones. Natural movement.' },
    { id: 'clean-minimal', name: 'Clean + Minimal', line: 'Quiet, uniform, refined.' },
    { id: 'classic',       name: 'Classic Stone',   line: 'Timeless veining. The look that never dates.' },
    { id: 'bold',          name: 'Bold + Dramatic', line: 'Deep tones. Striking contrast.' }
  ];

  /* The surface grid. Tick up to three, then the button below takes you to
   * the order page with those stones already ticked. */
  function mountGrid(el, opts) {
    opts = opts || {};
    var state = { tone: '', pattern: '', dir: '', picked: [] };
    loadStones().then(function (d) {
      var stones = d.stones;
      var filters = opts.filters === false ? '' :
        '<div class="cp-filters">' +
          row('Colour', 'tone', [['', 'All'], ['light', 'Light'], ['warm', 'Warm'], ['dark', 'Dark']]) +
          row('Look', 'pattern', [['', 'All'], ['subtle', 'Subtle'], ['veined', 'Veined'], ['statement', 'Statement']]) +
        '</div>';
      el.innerHTML =
        '<div class="cp-grid-head">' + filters +
          '<p class="cp-howto">' + esc(opts.howto || 'Tap up to three surfaces, then order. Samples are free.') + '</p>' +
        '</div>' +
        '<div class="cp-grid-body"></div>' +
        '<p class="cp-empty" hidden>No surfaces match those filters.</p>' +
        '<div class="cp-selbar" aria-live="polite">' +
          '<div class="picked"><span class="count">0 of ' + MAX + ' selected</span><span class="thumbs"></span></div>' +
          '<a class="cp-btn order" href="#" aria-disabled="true">' + esc(opts.cta || 'Order free samples') + '</a>' +
          '<p class="limit">You can order up to three free samples. Untick one to choose a different surface.</p>' +
        '</div>';
      var body = el.querySelector('.cp-grid-body');
      if (opts.groupBy === 'direction') {
        body.innerHTML = DIRS.map(function (g) {
          var list = stones.filter(function (s) { return s.direction === g.id; });
          return '<div class="cp-group" data-dir="' + g.id + '" id="style-' + g.id + '"><h3 class="cp-group-h">' + esc(g.name) + '</h3>' +
            '<p class="cp-group-p">' + esc(g.line) + '</p><div class="cp-grid">' + list.map(tile).join('') + '</div></div>';
        }).join('');
      } else {
        body.innerHTML = '<div class="cp-grid">' + stones.map(tile).join('') + '</div>';
      }
      el.addEventListener('click', function (e) {
        var chip = e.target.closest('.cp-chip');
        if (!chip) return;
        var key = chip.getAttribute('data-k');
        state[key] = chip.getAttribute('data-v');
        Array.prototype.forEach.call(el.querySelectorAll('.cp-chip[data-k="' + key + '"]'), function (c) {
          c.setAttribute('aria-pressed', c === chip ? 'true' : 'false');
        });
        applyFilters();
        track('FilterSurfaces', { filter: key, value: state[key] || 'all', page: opts.page });
      });
      el.addEventListener('change', function (e) {
        if (!e.target.matches('input[type=checkbox]')) return;
        var slug = e.target.value;
        if (e.target.checked) { if (state.picked.indexOf(slug) < 0) state.picked.push(slug); }
        else state.picked = state.picked.filter(function (x) { return x !== slug; });
        // The same stone can appear twice when grouped; keep both in step.
        Array.prototype.forEach.call(el.querySelectorAll('input[value="' + slug + '"]'), function (cb) { cb.checked = e.target.checked; });
        refresh();
        if (e.target.checked) track('SelectSample', { content_name: slug, page: opts.page });
      });
      el.querySelector('.order').addEventListener('click', function () {
        track('InitiateCheckout', { content_ids: state.picked, num_items: state.picked.length, page: opts.page });
      });
      if (opts.preset) { state.dir = opts.preset; }
      applyFilters(); refresh();
      if (opts.onReady) opts.onReady(api);

      function refresh() {
        var n = state.picked.length;
        el.querySelector('.count').textContent = n + ' of ' + MAX + ' selected';
        el.querySelector('.thumbs').innerHTML = state.picked.map(function (slug) {
          var s = stones.filter(function (x) { return x.slug === slug; })[0];
          return s ? '<img src="' + esc(s.img) + '" alt="' + esc(s.name) + '" title="' + esc(s.name) + '">' : '';
        }).join('');
        el.querySelector('.cp-selbar').classList.toggle('at-limit', n >= MAX);
        Array.prototype.forEach.call(el.querySelectorAll('.cp-tile'), function (t) {
          var cb = t.querySelector('input');
          var off = n >= MAX && !cb.checked;
          cb.disabled = off; t.classList.toggle('is-disabled', off);
        });
        var a = el.querySelector('.order');
        a.setAttribute('href', withParams(opts.orderPath || '/free-samples/order', { stones: state.picked.join(',') }));
        a.setAttribute('aria-disabled', n ? 'false' : 'true');
        a.textContent = n ? (opts.cta || 'Order free samples') + ' (' + n + ')' : (opts.cta || 'Order free samples');
      }
      function applyFilters() {
        var shown = 0;
        Array.prototype.forEach.call(el.querySelectorAll('.cp-tile'), function (t) {
          var ok = (!state.tone || t.getAttribute('data-tone') === state.tone) &&
                   (!state.pattern || t.getAttribute('data-pattern') === state.pattern) &&
                   (!state.dir || t.getAttribute('data-dir') === state.dir);
          t.hidden = !ok; if (ok) shown++;
        });
        Array.prototype.forEach.call(el.querySelectorAll('.cp-group'), function (g) {
          g.hidden = !g.querySelector('.cp-tile:not([hidden])');
        });
        el.querySelector('.cp-empty').hidden = shown > 0;
      }
      var api = {
        showDirection: function (dir) { state.dir = dir || ''; applyFilters(); el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
      };
      el._grid = api;
    });
    function row(label, key, opts2) {
      return '<div class="cp-filter-row" role="group" aria-label="' + esc(label) + '"><span class="lbl">' + esc(label) + '</span>' +
        opts2.map(function (o, i) {
          return '<button type="button" class="cp-chip" data-k="' + key + '" data-v="' + o[0] + '" aria-pressed="' + (i === 0) + '">' + esc(o[1]) + '</button>';
        }).join('') + '</div>';
    }
    function tile(s) {
      return '<label class="cp-tile" data-tone="' + s.tone + '" data-pattern="' + s.pattern + '" data-dir="' + s.direction + '">' +
        '<input type="checkbox" value="' + esc(s.slug) + '" aria-label="' + esc(s.name) + '">' +
        '<div class="img"><img src="' + esc(s.img) + '" alt="' + esc(s.name) + '" loading="lazy"></div>' +
        '<span class="tick" aria-hidden="true">&#10003;</span>' +
        '<div class="name">' + esc(s.name) + '</div><div class="coll">' + esc(s.collection) + '</div></label>';
    }
  }

  /* "Need help choosing?" — four design directions, each with three swatches. */
  function mountDirections(el, onPick) {
    loadStones().then(function (d) {
      el.innerHTML = DIRS.map(function (g) {
        var three = d.stones.filter(function (s) { return s.direction === g.id; }).slice(0, 3);
        return '<a class="cp-dir" href="#surfaces" data-dir="' + g.id + '"><div class="sw">' +
          three.map(function (s) { return '<img src="' + esc(s.img) + '" alt="" loading="lazy">'; }).join('') +
          '</div><div class="t"><b>' + esc(g.name) + '</b><span>' + esc(g.line) + '</span></div></a>';
      }).join('');
      el.addEventListener('click', function (e) {
        var a = e.target.closest('.cp-dir'); if (!a) return;
        e.preventDefault(); onPick(a.getAttribute('data-dir'));
        track('ViewDesignDirection', { content_name: a.getAttribute('data-dir') });
      });
    });
  }

  function mountShowrooms(el) {
    loadStones().then(function (d) {
      el.innerHTML = d.showrooms.map(function (r) {
        return '<div class="cp-room"><b>' + esc(r.name) + '</b><p>' + esc(r.address) + '</p>' +
          (r.phone ? '<p><a href="tel:' + esc(r.phone.replace(/\s/g, '')) + '">' + esc(r.phone) + '</a></p>' : '') +
          (r.hours ? '<p>' + esc(r.hours) + '</p>' : '') +
          (r.contacts ? '<p>' + esc(r.contacts) + '</p>' : '') +
          (r.maps ? '<p><a href="' + esc(r.maps) + '" target="_blank" rel="noopener">Get directions</a></p>' : '') + '</div>';
      }).join('') +
      '<div class="cp-room"><b>Near you</b><p>Our stonemason partners across Queensland can show you samples and full slabs.</p>' +
      '<p><a href="tel:1300257420">Call 1300 257 420</a> and we will point you to the nearest one.</p></div>';
    });
  }

  /* Discover FAQ: the questions that matter most for the ad that brought
   * someone here go first. Set by ?faq=performance|design, or inferred from
   * utm_content / utm_campaign (anything mentioning AlphaShield or stains →
   * performance; product, carousel, design or hero → design). */
  function orderFaq(el) {
    var v = (here.get('faq') || '').toLowerCase();
    if (!v) {
      var hint = ((here.get('utm_content') || '') + ' ' + (here.get('utm_campaign') || '')).toLowerCase();
      if (/shield|stain|perform|durab/.test(hint)) v = 'performance';
      else if (/product|carousel|design|hero|style|why/.test(hint)) v = 'design';
    }
    if (!v) return;
    var first = Array.prototype.slice.call(el.querySelectorAll('details[data-set="' + v + '"]'));
    first.reverse().forEach(function (d) { el.insertBefore(d, el.firstChild); });
    if (first.length) first[first.length - 1].open = true;
    el.setAttribute('data-variant', v);
  }

  window.AlphaCampaign = { mountGrid: mountGrid, mountDirections: mountDirections, mountShowrooms: mountShowrooms,
    orderFaq: orderFaq, withParams: withParams, wireLinks: wireLinks, track: track, loadStones: loadStones };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { wireLinks(); });
  else wireLinks();
})();
