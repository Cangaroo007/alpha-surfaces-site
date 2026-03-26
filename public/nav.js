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
    var s0 = segments[0];
    if (s0 === 'surfaces' || s0 === 'partners' || s0 === 'brand') depth = 1;
  }
  var prefix = depth > 0 ? '../' : '';
  var logoSrc = prefix + 'logos/01 Brandmark/Inverse_white/Alpha Surfaces_Brandmark_Inverse.png';

  /* ── Hardcoded collection/stone data ── */
  var COLLECTIONS = [
    { id: 'collection-01', label: 'Collection 01', name: 'Calacatta & Statuario',
      stones: ['Brilliance','Crystal','Jewel','Graphite','Bondi','Fraser'] },
    { id: 'collection-02', label: 'Collection 02', name: 'Prairie & Sage',
      stones: ['Arctic','Pearl','Ash','Shell','Carrara','Oyster Grey','Earthy Concrete'] },
    { id: 'collection-03', label: 'Collection 03', name: 'Soapstone & Verde',
      stones: ['Salt Stone','Davinci Gris','Davinci Oro','Desert Dune'],
      indoorOutdoor: ['Broome','Cabarita','Torquay','Whitehaven'] },
    { id: 'collection-04', label: 'Collection 04', name: 'Dramatic & Noir',
      stones: ['Opal Mist','Calacatta Leggera','Metallic Grey','Statuario Gold','Eternity','White Cloud','Glacier'] },
    { id: 'collection-05', label: 'Collection 05', name: 'Urban & Minimal',
      stones: ['Calacatta Viola','Arabescato','Autumn Gold'] },
    { id: 'original-alpha-zero', label: 'Original Alpha Zero', name: '',
      stones: ['Carbon','Venatino','Noosa','Glacier Grey','Infinity Gris','Calacatta Oro','Acropolis','Serena','Basaltina','Silver Trav','Biscotti','Grande Glacier','Taj Mahal','Patagonia','Calacatta Borghini'] }
  ];

  function slug(name) { return name.toLowerCase().replace(/\s+/g, '-'); }

  /* ══════════════════════════════════════════════════
     PHASE 1 — Render nav bar immediately
     ══════════════════════════════════════════════════ */
  var navEl = document.getElementById('main-nav');
  if (!navEl) return;

  navEl.innerHTML =
    '<a href="/" class="nav-logo"><img src="' + logoSrc + '" alt="Alpha Surfaces"></a>' +
    '<div class="nav-menu" id="nav-menu">' +
      '<a href="/collections.html" class="nav-link nav-collections-trigger" id="collections-trigger">COLLECTIONS</a>' +
      '<a href="/about.html" class="nav-link">ABOUT</a>' +
      '<a href="/#contact" class="nav-link">CONTACT</a>' +
    '</div>' +
    '<button class="nav-hamburger" id="nav-hamburger" aria-label="Menu"><span></span><span></span><span></span></button>' +
    '<div class="mega-menu" id="mega-menu"></div>' +
    '<div class="mobile-menu" id="mobile-menu"></div>';

  /* ══════════════════════════════════════════════════
     PHASE 2 — Build mega menu content
     ══════════════════════════════════════════════════ */
  var megaMenu = document.getElementById('mega-menu');
  var mobileMenu = document.getElementById('mobile-menu');
  var trigger = document.getElementById('collections-trigger');
  var hamburger = document.getElementById('nav-hamburger');

  // Desktop mega menu
  var dHtml = '<div class="mega-menu-inner">';
  COLLECTIONS.forEach(function(col, ci) {
    var anchor = col.id === 'original-alpha-zero' ? 'alpha-zero' : col.id;
    dHtml += '<div class="mega-menu-col">';
    dHtml += '<a href="/collections.html#' + anchor + '" class="mega-menu-col-heading">';
    dHtml += '<span class="mm-col-num">' + col.label + '</span>';
    dHtml += '</a>';
    dHtml += '<ul>';
    col.stones.forEach(function(s) {
      dHtml += '<li><a href="/surfaces/' + slug(s) + '">' + s + '</a></li>';
    });
    dHtml += '</ul>';
    if (col.indoorOutdoor) {
      dHtml += '<div class="mm-indoor-outdoor-label">Indoor-Outdoor</div>';
      dHtml += '<ul>';
      col.indoorOutdoor.forEach(function(s) {
        dHtml += '<li><a href="/surfaces/' + slug(s) + '">' + s + '</a></li>';
      });
      dHtml += '</ul>';
    }
    dHtml += '</div>';
    if (ci < COLLECTIONS.length - 1) dHtml += '<div class="mega-menu-divider"></div>';
  });
  dHtml += '</div>';
  megaMenu.innerHTML = dHtml;

  // Mobile menu
  var mHtml = '<div class="mobile-collections-row">' +
    '<a href="/collections.html" class="mobile-menu-link" style="flex:1;">COLLECTIONS</a>' +
    '<button class="mobile-toggle-btn" id="mobile-coll-toggle"><span class="toggle-icon">+</span></button></div>' +
    '<div class="mobile-collections-panel" id="mobile-coll-panel">';
  COLLECTIONS.forEach(function(col) {
    var anchor = col.id === 'original-alpha-zero' ? 'alpha-zero' : col.id;
    mHtml += '<div class="mobile-coll-group">';
    mHtml += '<div class="mobile-coll-header">';
    mHtml += '<a href="/collections.html#' + anchor + '" class="mobile-coll-name">' + col.label + '</a>';
    mHtml += '<button class="mobile-toggle-btn" data-coll="' + col.id + '"><span class="toggle-icon">+</span></button>';
    mHtml += '</div>';
    mHtml += '<div class="mobile-coll-stones" data-panel="' + col.id + '"><ul>';
    col.stones.forEach(function(s) {
      mHtml += '<li><a href="/surfaces/' + slug(s) + '">' + s + '</a></li>';
    });
    if (col.indoorOutdoor) {
      mHtml += '</ul><div class="mm-indoor-outdoor-label" style="color:rgba(255,255,255,0.5);">Indoor-Outdoor</div><ul>';
      col.indoorOutdoor.forEach(function(s) {
        mHtml += '<li><a href="/surfaces/' + slug(s) + '">' + s + '</a></li>';
      });
    }
    mHtml += '</ul></div></div>';
  });
  mHtml += '</div>';
  mHtml += '<a href="/about.html" class="mobile-menu-link">ABOUT</a>';
  mHtml += '<a href="/#contact" class="mobile-menu-link">CONTACT</a>';
  mobileMenu.innerHTML = mHtml;

  /* ══════════════════════════════════════════════════
     PHASE 3 — Interactions
     ══════════════════════════════════════════════════ */

  // Desktop: hover to open mega menu
  var hoverTimer;
  trigger.addEventListener('mouseenter', function() {
    if (window.innerWidth >= 1024) { clearTimeout(hoverTimer); megaMenu.classList.add('open'); }
  });
  megaMenu.addEventListener('mouseenter', function() {
    if (window.innerWidth >= 1024) clearTimeout(hoverTimer);
  });
  trigger.addEventListener('mouseleave', function() {
    if (window.innerWidth >= 1024) hoverTimer = setTimeout(function() { if (!megaMenu.matches(':hover')) megaMenu.classList.remove('open'); }, 350);
  });
  megaMenu.addEventListener('mouseleave', function() {
    if (window.innerWidth >= 1024) hoverTimer = setTimeout(function() { if (!trigger.matches(':hover')) megaMenu.classList.remove('open'); }, 350);
  });

  // Click outside closes
  document.addEventListener('click', function(e) {
    if (megaMenu.classList.contains('open') && !megaMenu.contains(e.target) && !trigger.contains(e.target)) megaMenu.classList.remove('open');
  });

  // Escape closes everything
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') { megaMenu.classList.remove('open'); closeMobile(); }
  });

  // Close mega on ABOUT/CONTACT click
  var otherLinks = document.querySelectorAll('#nav-menu .nav-link:not(.nav-collections-trigger)');
  for (var i = 0; i < otherLinks.length; i++) otherLinks[i].addEventListener('click', function() { megaMenu.classList.remove('open'); });

  // Hamburger
  hamburger.addEventListener('click', function(e) { e.stopPropagation(); toggleMobile(); });

  function toggleMobile() {
    if (mobileMenu.classList.contains('open')) closeMobile();
    else { mobileMenu.classList.add('open'); document.body.style.overflow = 'hidden'; }
  }
  function closeMobile() { mobileMenu.classList.remove('open'); document.body.style.overflow = ''; }

  // Mobile accordion: top-level collections toggle
  var collToggle = document.getElementById('mobile-coll-toggle');
  var collPanel = document.getElementById('mobile-coll-panel');
  if (collToggle && collPanel) {
    collToggle.addEventListener('click', function() {
      collPanel.classList.toggle('open');
      collToggle.querySelector('.toggle-icon').textContent = collPanel.classList.contains('open') ? '\u2013' : '+';
    });
  }

  // Mobile accordion: individual collection toggles
  var collBtns = mobileMenu.querySelectorAll('.mobile-toggle-btn[data-coll]');
  for (var b = 0; b < collBtns.length; b++) {
    collBtns[b].addEventListener('click', function() {
      var panel = mobileMenu.querySelector('[data-panel="' + this.getAttribute('data-coll') + '"]');
      if (panel) {
        panel.classList.toggle('open');
        this.querySelector('.toggle-icon').textContent = panel.classList.contains('open') ? '\u2013' : '+';
      }
    });
  }

  // Close mobile on any stone/page link click
  var allMobileLinks = mobileMenu.querySelectorAll('a');
  for (var l = 0; l < allMobileLinks.length; l++) allMobileLinks[l].addEventListener('click', closeMobile);

})();
