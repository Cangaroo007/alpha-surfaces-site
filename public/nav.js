(function () {
  'use strict';

  /* ── Path detection ── */
  var pathname = window.location.pathname;
  var segments = pathname.replace(/\/+$/, '').split('/').filter(Boolean);
  var depth = 0;
  if (segments.length >= 2) {
    var dir = segments[segments.length - 2];
    if (dir === 'surfaces' || dir === 'partners' || dir === 'brand') depth = 1;
  } else if (segments.length === 1) {
    var seg = segments[0];
    if (seg === 'surfaces' || seg === 'partners' || seg === 'brand') depth = 1;
  }

  var prefix = depth > 0 ? '../' : '';
  var logoSrc = prefix + 'logos/01 Brandmark/Inverse_white/Alpha Surfaces_Brandmark_Inverse.png';
  var dataUrl = prefix + 'data/stones.json';

  /* ══════════════════════════════════════════════════
     PHASE 1 — Render nav immediately (synchronous)
     ══════════════════════════════════════════════════ */
  var navEl = document.getElementById('main-nav');
  if (!navEl) return;

  navEl.innerHTML =
    '<a href="/" class="nav-logo">' +
      '<img src="' + logoSrc + '" alt="Alpha Surfaces">' +
    '</a>' +
    '<div class="nav-menu" id="nav-menu">' +
      '<a href="/collections.html" class="nav-link nav-collections-trigger" id="collections-trigger">COLLECTIONS</a>' +
      '<a href="/about.html" class="nav-link">ABOUT</a>' +
      '<a href="/#contact" class="nav-link">CONTACT</a>' +
    '</div>' +
    '<button class="nav-hamburger" id="nav-hamburger" aria-label="Menu">' +
      '<span></span><span></span><span></span>' +
    '</button>' +
    '<div class="mega-menu" id="mega-menu"></div>' +
    '<div class="mobile-menu" id="mobile-menu"></div>';

  /* ══════════════════════════════════════════════════
     PHASE 2 — Wire interactions (synchronous, safe)
     ══════════════════════════════════════════════════ */
  var trigger = document.getElementById('collections-trigger');
  var megaMenu = document.getElementById('mega-menu');
  var hamburger = document.getElementById('nav-hamburger');
  var mobileMenu = document.getElementById('mobile-menu');

  if (!trigger || !megaMenu || !hamburger || !mobileMenu) return;

  // COLLECTIONS click: navigate to /collections.html
  // Hover opens mega menu; click navigates
  trigger.addEventListener('click', function () {
    closeMegaMenu();
    // Let the default href="/collections.html" navigate
  });

  // Hover open on desktop
  var hoverTimeout;
  trigger.addEventListener('mouseenter', function () {
    if (window.innerWidth >= 1024) {
      clearTimeout(hoverTimeout);
      megaMenu.classList.add('open');
    }
  });
  megaMenu.addEventListener('mouseenter', function () {
    if (window.innerWidth >= 1024) clearTimeout(hoverTimeout);
  });
  trigger.addEventListener('mouseleave', function () {
    if (window.innerWidth >= 1024) {
      hoverTimeout = setTimeout(function () {
        if (!megaMenu.matches(':hover')) closeMegaMenu();
      }, 200);
    }
  });
  megaMenu.addEventListener('mouseleave', function () {
    if (window.innerWidth >= 1024) hoverTimeout = setTimeout(closeMegaMenu, 200);
  });

  // Close on click outside
  document.addEventListener('click', function (e) {
    if (megaMenu.classList.contains('open') && !megaMenu.contains(e.target) && !trigger.contains(e.target)) {
      closeMegaMenu();
    }
  });

  // Close on Escape
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') { closeMegaMenu(); closeMobileMenu(); }
  });

  // Close mega when clicking ABOUT or CONTACT
  var navLinks = document.querySelectorAll('#nav-menu .nav-link:not(.nav-collections-trigger)');
  for (var i = 0; i < navLinks.length; i++) {
    navLinks[i].addEventListener('click', closeMegaMenu);
  }

  // Hamburger
  hamburger.addEventListener('click', function (e) {
    e.stopPropagation();
    toggleMobileMenu();
  });

  function toggleMegaMenu() {
    megaMenu.classList.toggle('open');
  }
  function closeMegaMenu() {
    megaMenu.classList.remove('open');
  }
  function toggleMobileMenu() {
    if (mobileMenu.classList.contains('open')) {
      closeMobileMenu();
    } else {
      mobileMenu.classList.add('open');
      document.body.style.overflow = 'hidden';
    }
  }
  function closeMobileMenu() {
    mobileMenu.classList.remove('open');
    document.body.style.overflow = '';
  }

  /* ══════════════════════════════════════════════════
     PHASE 3 — Load collection data (async, independent)
     Failure here does NOT break page rendering.
     ══════════════════════════════════════════════════ */
  var indoorOutdoorSlugs = ['broome', 'cabarita', 'torquay', 'whitehaven'];

  fetch(dataUrl)
    .then(function (res) {
      if (!res.ok) throw new Error('HTTP ' + res.status);
      return res.json();
    })
    .then(function (data) {
      buildMegaMenu(data.collections);
      buildMobileMenu(data.collections);
    })
    .catch(function (err) {
      console.warn('Nav: stones.json load failed —', err.message);
      // Mega menu stays empty but nav still works
    });

  function buildMegaMenu(collections) {
    var html = '<div class="mega-menu-inner">';
    collections.forEach(function (col) {
      html += '<div class="mega-menu-col">';
      var anchor = col.id === 'original-alpha-zero' ? 'alpha-zero' : col.id;
      html += '<a href="/collections.html#' + anchor + '" class="mega-menu-col-heading">' + esc(col.name) + '</a>';
      if (col.id === 'collection-03') {
        var reg = [], out = [];
        col.stones.forEach(function (s) {
          (indoorOutdoorSlugs.indexOf(s.slug) !== -1 ? out : reg).push(s);
        });
        html += stoneList(reg);
        html += '<div class="mega-menu-col-subheading">Indoor-Outdoor</div>';
        html += stoneList(out);
      } else {
        html += stoneList(col.stones);
      }
      html += '</div>';
    });
    html += '</div>';
    megaMenu.innerHTML = html;
  }

  function buildMobileMenu(collections) {
    var html = '<div class="mobile-collections-row"><a href="/collections.html" class="mobile-menu-link" style="flex:1;" data-close-mobile>COLLECTIONS</a><button class="mobile-collections-toggle-btn" id="mobile-collections-trigger" style="background:none;border:none;padding:8px 12px;cursor:pointer;"><span class="toggle-icon" style="color:#fff;font-size:20px;">+</span></button></div>';
    html += '<div class="mobile-collections-panel" id="mobile-collections-panel">';
    collections.forEach(function (col) {
      html += '<div class="mobile-collection-group">';
      var mAnchor = col.id === 'original-alpha-zero' ? 'alpha-zero' : col.id;
      html += '<div class="mobile-collection-header" data-collection="' + col.id + '"><a href="/collections.html#' + mAnchor + '" class="mobile-collection-name" data-close-mobile>' + esc(col.name) + '</a><button class="mobile-collection-toggle-btn" style="background:none;border:none;padding:4px 8px;cursor:pointer;"><span class="mobile-collection-toggle" style="color:#fff;">+</span></button></div>';
      html += '<div class="mobile-collection-stones" data-panel="' + col.id + '">';
      if (col.id === 'collection-03') {
        var reg = [], out = [];
        col.stones.forEach(function (s) {
          (indoorOutdoorSlugs.indexOf(s.slug) !== -1 ? out : reg).push(s);
        });
        html += stoneList(reg);
        if (out.length) {
          html += '<div class="mega-menu-col-subheading" style="color:var(--white);opacity:0.6;">Indoor-Outdoor</div>';
          html += stoneList(out);
        }
      } else {
        html += stoneList(col.stones);
      }
      html += '</div></div>';
    });
    html += '</div>';
    html += '<a href="/about.html" class="mobile-menu-link" data-close-mobile>ABOUT</a>';
    html += '<a href="/#contact" class="mobile-menu-link" data-close-mobile>CONTACT</a>';
    mobileMenu.innerHTML = html;
    bindMobileAccordion();
  }

  function bindMobileAccordion() {
    var ct = document.getElementById('mobile-collections-trigger');
    var cp = document.getElementById('mobile-collections-panel');
    if (ct && cp) {
      ct.addEventListener('click', function () {
        var icon = ct.querySelector('.toggle-icon');
        cp.classList.toggle('open');
        if (icon) icon.textContent = cp.classList.contains('open') ? '\u2013' : '+';
      });
    }
    var toggleBtns = mobileMenu.querySelectorAll('.mobile-collection-toggle-btn');
    for (var h = 0; h < toggleBtns.length; h++) {
      toggleBtns[h].addEventListener('click', function (e) {
        e.stopPropagation();
        var header = this.closest('.mobile-collection-header');
        if (!header) return;
        var colId = header.getAttribute('data-collection');
        var panel = mobileMenu.querySelector('[data-panel="' + colId + '"]');
        var tog = this.querySelector('.mobile-collection-toggle');
        if (panel) {
          panel.classList.toggle('open');
          if (tog) tog.textContent = panel.classList.contains('open') ? '\u2013' : '+';
        }
      });
    }
    var allClose = mobileMenu.querySelectorAll('[data-close-mobile], .mobile-collection-stones a');
    for (var c = 0; c < allClose.length; c++) {
      allClose[c].addEventListener('click', closeMobileMenu);
    }
  }

  function stoneList(stones) {
    var h = '<ul>';
    stones.forEach(function (s) { h += '<li><a href="/surfaces/' + s.slug + '">' + esc(s.name) + '</a></li>'; });
    return h + '</ul>';
  }

  function esc(str) {
    var d = document.createElement('div');
    d.appendChild(document.createTextNode(str));
    return d.innerHTML;
  }

})();
