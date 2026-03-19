(function () {
  'use strict';

  /* ── Path detection ── */
  var path = window.location.pathname;
  var segments = path.replace(/\/+$/, '').split('/').filter(Boolean);
  // Depth: 0 for root pages, 1 for /surfaces/xxx or /partners/xxx or /brand/xxx
  var depth = 0;
  if (segments.length >= 2) {
    var dir = segments[segments.length - 2];
    if (dir === 'surfaces' || dir === 'partners' || dir === 'brand') {
      depth = 1;
    }
  } else if (segments.length === 1) {
    // Could be /surfaces/ (directory index) or /index.html (root)
    var seg = segments[0];
    if (seg === 'surfaces' || seg === 'partners' || seg === 'brand') {
      depth = 1;
    }
  }

  var prefix = depth > 0 ? '../' : '';
  var logoSrc = prefix + 'logos/01 Brandmark/Inverse_white/Alpha Surfaces_Brandmark_Inverse.png';
  var dataUrl = prefix + 'data/stones.json';

  /* ── Inject nav HTML ── */
  var navEl = document.getElementById('main-nav');
  if (!navEl) return;

  navEl.innerHTML = '\
    <a href="/" class="nav-logo">\
      <img src="' + logoSrc + '" alt="Alpha Surfaces" id="nav-logo-img">\
    </a>\
    <div class="nav-menu" id="nav-menu">\
      <a href="#" class="nav-link nav-collections-trigger" id="collections-trigger">COLLECTIONS</a>\
      <a href="/about.html" class="nav-link">ABOUT</a>\
      <a href="/#contact" class="nav-link">CONTACT</a>\
    </div>\
    <button class="nav-hamburger" id="nav-hamburger" aria-label="Menu">\
      <span></span><span></span><span></span>\
    </button>\
    <div class="mega-menu" id="mega-menu"></div>\
    <div class="mobile-menu" id="mobile-menu"></div>\
  ';

  /* ── DOM references ── */
  var trigger = document.getElementById('collections-trigger');
  var megaMenu = document.getElementById('mega-menu');
  var hamburger = document.getElementById('nav-hamburger');
  var mobileMenu = document.getElementById('mobile-menu');

  /* ── Indoor-Outdoor stones in Collection 03 ── */
  var indoorOutdoorSlugs = ['broome', 'cabarita', 'torquay', 'whitehaven'];

  /* ── Fetch stone data and build menus ── */
  fetch(dataUrl)
    .then(function (res) { return res.json(); })
    .then(function (data) {
      buildMegaMenu(data.collections);
      buildMobileMenu(data.collections);
    })
    .catch(function (err) {
      console.warn('Nav: Could not load stones data', err);
    });

  /* ── Build mega menu dropdown ── */
  function buildMegaMenu(collections) {
    var html = '<div class="mega-menu-inner">';
    collections.forEach(function (col) {
      html += '<div class="mega-menu-col">';
      html += '<div class="mega-menu-col-heading">' + escHtml(col.name) + '</div>';

      if (col.id === 'collection-03') {
        // Split into regular and indoor-outdoor
        var regular = [];
        var outdoor = [];
        col.stones.forEach(function (s) {
          if (indoorOutdoorSlugs.indexOf(s.slug) !== -1) {
            outdoor.push(s);
          } else {
            regular.push(s);
          }
        });
        html += '<ul>';
        regular.forEach(function (s) {
          html += '<li><a href="/surfaces/' + s.slug + '">' + escHtml(s.name) + '</a></li>';
        });
        html += '</ul>';
        html += '<div class="mega-menu-col-subheading">Indoor-Outdoor</div>';
        html += '<ul>';
        outdoor.forEach(function (s) {
          html += '<li><a href="/surfaces/' + s.slug + '">' + escHtml(s.name) + '</a></li>';
        });
        html += '</ul>';
      } else {
        html += '<ul>';
        col.stones.forEach(function (s) {
          html += '<li><a href="/surfaces/' + s.slug + '">' + escHtml(s.name) + '</a></li>';
        });
        html += '</ul>';
      }

      html += '</div>';
    });
    html += '</div>';
    megaMenu.innerHTML = html;
  }

  /* ── Build mobile menu ── */
  function buildMobileMenu(collections) {
    var html = '';
    // Collections accordion
    html += '<button class="mobile-collections-trigger" id="mobile-collections-trigger">';
    html += 'COLLECTIONS <span class="toggle-icon">+</span>';
    html += '</button>';
    html += '<div class="mobile-collections-panel" id="mobile-collections-panel">';

    collections.forEach(function (col) {
      html += '<div class="mobile-collection-group">';
      html += '<button class="mobile-collection-header" data-collection="' + col.id + '">';
      html += '<span class="mobile-collection-name">' + escHtml(col.name) + '</span>';
      html += '<span class="mobile-collection-toggle">+</span>';
      html += '</button>';
      html += '<div class="mobile-collection-stones" data-panel="' + col.id + '">';

      if (col.id === 'collection-03') {
        var regular = [];
        var outdoor = [];
        col.stones.forEach(function (s) {
          if (indoorOutdoorSlugs.indexOf(s.slug) !== -1) {
            outdoor.push(s);
          } else {
            regular.push(s);
          }
        });
        html += '<ul>';
        regular.forEach(function (s) {
          html += '<li><a href="/surfaces/' + s.slug + '">' + escHtml(s.name) + '</a></li>';
        });
        html += '</ul>';
        if (outdoor.length > 0) {
          html += '<div class="mega-menu-col-subheading" style="color:var(--white);opacity:0.6;margin-left:0;padding-left:0;">Indoor-Outdoor</div>';
          html += '<ul>';
          outdoor.forEach(function (s) {
            html += '<li><a href="/surfaces/' + s.slug + '">' + escHtml(s.name) + '</a></li>';
          });
          html += '</ul>';
        }
      } else {
        html += '<ul>';
        col.stones.forEach(function (s) {
          html += '<li><a href="/surfaces/' + s.slug + '">' + escHtml(s.name) + '</a></li>';
        });
        html += '</ul>';
      }

      html += '</div>';
      html += '</div>';
    });

    html += '</div>';

    // Other links
    html += '<a href="/about.html" class="mobile-menu-link" data-close-mobile>ABOUT</a>';
    html += '<a href="/#contact" class="mobile-menu-link" data-close-mobile>CONTACT</a>';

    mobileMenu.innerHTML = html;

    // Bind mobile accordion events
    bindMobileAccordion();
  }

  /* ── Desktop mega menu interactions ── */
  trigger.addEventListener('click', function (e) {
    e.preventDefault();
    e.stopPropagation();
    toggleMegaMenu();
  });

  // Hover to open on desktop (with delay to prevent flickering)
  var hoverTimeout;
  trigger.addEventListener('mouseenter', function () {
    if (window.innerWidth >= 1024) {
      clearTimeout(hoverTimeout);
      megaMenu.classList.add('open');
    }
  });
  megaMenu.addEventListener('mouseenter', function () {
    if (window.innerWidth >= 1024) {
      clearTimeout(hoverTimeout);
    }
  });
  trigger.addEventListener('mouseleave', function () {
    if (window.innerWidth >= 1024) {
      hoverTimeout = setTimeout(function () {
        if (!megaMenu.matches(':hover')) closeMegaMenu();
      }, 200);
    }
  });
  megaMenu.addEventListener('mouseleave', function () {
    if (window.innerWidth >= 1024) {
      hoverTimeout = setTimeout(closeMegaMenu, 200);
    }
  });

  // Close on click outside
  document.addEventListener('click', function (e) {
    if (megaMenu.classList.contains('open') &&
        !megaMenu.contains(e.target) &&
        !trigger.contains(e.target)) {
      closeMegaMenu();
    }
  });

  // Close on Escape
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      closeMegaMenu();
      closeMobileMenu();
    }
  });

  // Close mega menu when clicking ABOUT or CONTACT
  var navLinks = document.querySelectorAll('#nav-menu .nav-link:not(.nav-collections-trigger)');
  for (var i = 0; i < navLinks.length; i++) {
    navLinks[i].addEventListener('click', function () {
      closeMegaMenu();
    });
  }

  function toggleMegaMenu() {
    if (megaMenu.classList.contains('open')) {
      closeMegaMenu();
    } else {
      megaMenu.classList.add('open');
    }
  }

  function closeMegaMenu() {
    megaMenu.classList.remove('open');
  }

  /* ── Hamburger / Mobile menu ── */
  hamburger.addEventListener('click', function (e) {
    e.stopPropagation();
    toggleMobileMenu();
  });

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

  /* ── Mobile accordion binding ── */
  function bindMobileAccordion() {
    // Top-level collections toggle
    var collTrigger = document.getElementById('mobile-collections-trigger');
    var collPanel = document.getElementById('mobile-collections-panel');
    if (collTrigger && collPanel) {
      collTrigger.addEventListener('click', function () {
        var icon = collTrigger.querySelector('.toggle-icon');
        if (collPanel.classList.contains('open')) {
          collPanel.classList.remove('open');
          if (icon) icon.textContent = '+';
        } else {
          collPanel.classList.add('open');
          if (icon) icon.textContent = '\u2013';
        }
      });
    }

    // Individual collection toggles
    var headers = mobileMenu.querySelectorAll('.mobile-collection-header');
    for (var i = 0; i < headers.length; i++) {
      headers[i].addEventListener('click', function () {
        var id = this.getAttribute('data-collection');
        var panel = mobileMenu.querySelector('[data-panel="' + id + '"]');
        var toggle = this.querySelector('.mobile-collection-toggle');
        if (panel) {
          if (panel.classList.contains('open')) {
            panel.classList.remove('open');
            if (toggle) toggle.textContent = '+';
          } else {
            panel.classList.add('open');
            if (toggle) toggle.textContent = '\u2013';
          }
        }
      });
    }

    // Close mobile menu on link clicks
    var closeLinks = mobileMenu.querySelectorAll('[data-close-mobile]');
    for (var j = 0; j < closeLinks.length; j++) {
      closeLinks[j].addEventListener('click', function () {
        closeMobileMenu();
      });
    }

    // Also close on stone link clicks
    var stoneLinks = mobileMenu.querySelectorAll('.mobile-collection-stones a');
    for (var k = 0; k < stoneLinks.length; k++) {
      stoneLinks[k].addEventListener('click', function () {
        closeMobileMenu();
      });
    }
  }

  /* ── Utility ── */
  function escHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }

})();
