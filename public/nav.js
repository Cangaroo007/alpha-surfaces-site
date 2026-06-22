(function () {
  'use strict';

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

  var FALLBACK_COLLECTIONS = [
    { id: 'collection-01', label: 'Collection 01', stones: [{ name: 'Brilliance' }, { name: 'Crystal' }, { name: 'Jewel' }, { name: 'Graphite' }, { name: 'Bondi' }, { name: 'Fraser' }] },
    { id: 'collection-02', label: 'Collection 02', stones: [{ name: 'Arctic' }, { name: 'Pearl' }, { name: 'Ash' }, { name: 'Shell' }, { name: 'Carrara' }, { name: 'Oyster Grey' }, { name: 'Earthy Concrete' }] },
    { id: 'collection-03', label: 'Collection 03', stones: [{ name: 'Salt Stone' }, { name: 'Davinci Gris' }, { name: 'Davinci Oro' }, { name: 'Desert Dune' }], indoorOutdoor: [{ name: 'Broome' }, { name: 'Cabarita' }, { name: 'Torquay' }, { name: 'Whitehaven' }] },
    { id: 'collection-04', label: 'Collection 04', stones: [{ name: 'Opal Mist' }, { name: 'Calacatta Leggera' }, { name: 'Metallic Grey' }, { name: 'Statuario Gold' }, { name: 'Eternity' }, { name: 'White Cloud' }, { name: 'Glacier' }, { name: 'Arabescato' }] },
    { id: 'collection-05', label: 'Collection 05', stones: [{ name: 'Taj Mahal' }, { name: 'Perla Mahal' }, { name: 'Calacatta Viola' }, { name: 'Autumn Gold' }, { name: 'Emerald Haze' }, { name: 'Crystal Mahal' }, { name: 'Venato' }, { name: 'Viola Ligera' }] },
    { id: 'alpha-zero', label: 'Alpha Zero', stones: [{ name: 'Silver Travertine', discontinued: true }, { name: 'Grande Glacier', discontinued: true }, { name: 'Basaltina', discontinued: true }, { name: 'Carbon', discontinued: true }, { name: 'Acropolis', discontinued: true }, { name: 'Glacier Grey', discontinued: true }, { name: 'Noosa', discontinued: true }, { name: 'Calacatta Oro', discontinued: true }, { name: 'Serena', discontinued: true }, { name: 'Venatino', discontinued: true }, { name: 'Crystello', discontinued: true }, { name: 'Travertino Classico', discontinued: true }, { name: 'Dolomite', discontinued: true }, { name: 'Infinity Gris', discontinued: true }, { name: 'Statuario Grigio', discontinued: true }] }
  ];

  function slug(name) {
    return String(name || '').toLowerCase().trim().replace(/&/g, 'and').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  }

  function escapeHtml(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function collectionLabel(collection) {
    if (collection.label) return collection.label;
    if (collection.id === 'alpha-zero') return 'Alpha Zero';
    var match = String(collection.name || '').match(/Collection\s+\d+/i);
    return match ? match[0] : collection.name;
  }

  function isRemovedPublicStone(stone, collection) {
    var stoneSlug = slug(stone && (stone.slug || stone.name));
    var collectionId = collection && (collection.id || slug(collection.name || collection.label));
    return collectionId === 'collection-01' && stoneSlug === 'oyster';
  }

  function normalizeCollections(data) {
    if (!data || !Array.isArray(data.collections)) return FALLBACK_COLLECTIONS;
    return data.collections.map(function(collection) {
      var normal = {
        id: collection.id || slug(collection.name),
        label: collectionLabel(collection),
        stones: [],
        indoorOutdoor: []
      };
      (collection.stones || []).forEach(function(stone) {
        if (isRemovedPublicStone(stone, collection)) return;
        var item = {
          name: stone.name,
          slug: stone.slug || slug(stone.name),
          discontinued: !!stone.discontinued
        };
        if (stone.indoor_outdoor || stone.uv_stable) normal.indoorOutdoor.push(item);
        else normal.stones.push(item);
      });
      return normal;
    }).filter(function(collection) {
      return collection.id && collection.label && (collection.stones.length || collection.indoorOutdoor.length);
    });
  }

  function stoneHref(stone, collection) {
    if (stone.discontinued || collection.id === 'alpha-zero') return '/collections.html#alpha-zero';
    return '/surfaces/' + (stone.slug || slug(stone.name));
  }

  function renderStoneList(stones, collection) {
    var html = '';
    stones.forEach(function(stone) {
      html += '<li><a href="' + stoneHref(stone, collection) + '">' + escapeHtml(stone.name) + '</a></li>';
    });
    return html;
  }

  var navEl = document.getElementById('main-nav');
  if (!navEl) return;

  navEl.innerHTML =
    '<a href="/" class="nav-logo"><img src="' + logoSrc + '" alt="Alpha Surfaces"></a>' +
    '<div class="nav-menu" id="nav-menu">' +
      '<a href="/collections.html" class="nav-link nav-collections-trigger" id="collections-trigger">COLLECTIONS</a>' +
      '<a href="/about.html" class="nav-link">ABOUT</a>' +
      '<a href="/brochure" class="nav-link">BROCHURE</a>' +
      '<div class="nav-dropdown" id="contact-dropdown">' +
        '<a href="/#contact" class="nav-link nav-dropdown-trigger" id="contact-trigger">CONTACT US</a>' +
        '<div class="nav-dropdown-menu" id="contact-dropdown-menu">' +
          '<a href="/#contact" class="nav-dropdown-item">Contact Us</a>' +
          '<a href="/enquiry" class="nav-dropdown-item">General Enquiry</a>' +
          '<a href="/warranty" class="nav-dropdown-item">Activate Warranty</a>' +
        '</div>' +
      '</div>' +
    '</div>' +
    '<button class="nav-hamburger" id="nav-hamburger" aria-label="Menu"><span></span><span></span><span></span></button>' +
    '<div class="mega-menu" id="mega-menu"></div>' +
    '<div class="mobile-menu" id="mobile-menu"></div>';

  var navLogo = navEl.querySelector('.nav-logo');
  if (navLogo) {
    navLogo.addEventListener('click', function(e) {
      var p = window.location.pathname;
      if (p === '/' || p === '/index.html' || p === '') {
        e.preventDefault();
        window.scrollTo({ top: 0, behavior: 'smooth' });
      }
    });
  }

  function loadCollections() {
    var controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var timeoutId = setTimeout(function() { if (controller) controller.abort(); }, 4000);
    var opts = controller ? { signal: controller.signal } : {};
    return fetch('/api/public/stones', opts)
      .then(function(res) {
        clearTimeout(timeoutId);
        if (!res.ok) throw new Error('Managed collections unavailable');
        return res.json();
      })
      .then(normalizeCollections)
      .catch(function() {
        clearTimeout(timeoutId);
        return FALLBACK_COLLECTIONS;
      });
  }

  function renderMenus(collections) {
    var megaMenu = document.getElementById('mega-menu');
    var mobileMenu = document.getElementById('mobile-menu');
    if (!megaMenu || !mobileMenu) return;

    var dHtml = '<div class="mega-menu-inner">';
    collections.forEach(function(col, ci) {
      dHtml += '<div class="mega-menu-col">';
      dHtml += '<a href="/collections.html#' + encodeURIComponent(col.id) + '" class="mega-menu-col-heading">';
      dHtml += '<span class="mm-col-num">' + escapeHtml(col.label) + '</span>';
      dHtml += '</a>';
      dHtml += '<ul>' + renderStoneList(col.stones, col) + '</ul>';
      if (col.indoorOutdoor && col.indoorOutdoor.length) {
        dHtml += '<div class="mm-indoor-outdoor-label">Indoor-Outdoor</div>';
        dHtml += '<ul>' + renderStoneList(col.indoorOutdoor, col) + '</ul>';
      }
      dHtml += '</div>';
      if (ci < collections.length - 1) dHtml += '<div class="mega-menu-divider"></div>';
    });
    dHtml += '</div>';
    megaMenu.innerHTML = dHtml;

    var mHtml = '<div class="mobile-collections-row">' +
      '<a href="/collections.html" class="mobile-menu-link" style="flex:1;">COLLECTIONS</a>' +
      '<button class="mobile-toggle-btn" id="mobile-coll-toggle"><span class="toggle-icon">+</span></button></div>' +
      '<div class="mobile-collections-panel" id="mobile-coll-panel">';
    collections.forEach(function(col) {
      mHtml += '<div class="mobile-coll-group">';
      mHtml += '<div class="mobile-coll-header">';
      mHtml += '<a href="/collections.html#' + encodeURIComponent(col.id) + '" class="mobile-coll-name">' + escapeHtml(col.label) + '</a>';
      mHtml += '<button class="mobile-toggle-btn" data-coll="' + escapeHtml(col.id) + '"><span class="toggle-icon">+</span></button>';
      mHtml += '</div>';
      mHtml += '<div class="mobile-coll-stones" data-panel="' + escapeHtml(col.id) + '"><ul>';
      mHtml += renderStoneList(col.stones, col);
      if (col.indoorOutdoor && col.indoorOutdoor.length) {
        mHtml += '</ul><div class="mm-indoor-outdoor-label" style="color:rgba(255,255,255,0.5);">Indoor-Outdoor</div><ul>';
        mHtml += renderStoneList(col.indoorOutdoor, col);
      }
      mHtml += '</ul></div></div>';
    });
    mHtml += '</div>';
    mHtml += '<a href="/about.html" class="mobile-menu-link">ABOUT</a>';
    mHtml += '<a href="/brochure" class="mobile-menu-link">BROCHURE</a>';
    mHtml += '<div class="mobile-collections-row">' +
      '<a href="/#contact" class="mobile-menu-link" style="flex:1;">CONTACT US</a>' +
      '<button class="mobile-toggle-btn" id="mobile-contact-toggle"><span class="toggle-icon">+</span></button></div>' +
      '<div class="mobile-contact-panel" id="mobile-contact-panel">' +
        '<a href="/#contact" class="mobile-sub-link">Contact Us</a>' +
        '<a href="/enquiry" class="mobile-sub-link">General Enquiry</a>' +
        '<a href="/warranty" class="mobile-sub-link">Activate Warranty</a>' +
      '</div>';
    mobileMenu.innerHTML = mHtml;
  }

  function closeMobile() {
    var mobileMenu = document.getElementById('mobile-menu');
    if (!mobileMenu) return;
    mobileMenu.classList.remove('open');
    document.body.style.overflow = '';
  }

  // Bound ONCE. These elements (hamburger, COLLECTIONS trigger, CONTACT US
  // dropdown, document-level listeners) live outside the mobile-menu/mega-menu
  // content that renderMenus replaces, so re-binding them would attach duplicate
  // handlers \u2014 the bug that broke the hamburger toggle.
  function bindNavControls() {
    var megaMenu = document.getElementById('mega-menu');
    var mobileMenu = document.getElementById('mobile-menu');
    var trigger = document.getElementById('collections-trigger');
    var hamburger = document.getElementById('nav-hamburger');
    if (!megaMenu || !mobileMenu || !trigger || !hamburger) return;

    var hoverTimer;
    trigger.addEventListener('mouseenter', function() {
      if (window.innerWidth >= 1024) {
        clearTimeout(hoverTimer);
        megaMenu.classList.add('open');
      }
    });
    megaMenu.addEventListener('mouseenter', function() {
      if (window.innerWidth >= 1024) clearTimeout(hoverTimer);
    });
    trigger.addEventListener('mouseleave', function() {
      if (window.innerWidth >= 1024) {
        hoverTimer = setTimeout(function() {
          if (!megaMenu.matches(':hover')) megaMenu.classList.remove('open');
        }, 350);
      }
    });
    megaMenu.addEventListener('mouseleave', function() {
      if (window.innerWidth >= 1024) {
        hoverTimer = setTimeout(function() {
          if (!trigger.matches(':hover')) megaMenu.classList.remove('open');
        }, 350);
      }
    });

    document.addEventListener('click', function(e) {
      if (megaMenu.classList.contains('open') && !megaMenu.contains(e.target) && !trigger.contains(e.target)) {
        megaMenu.classList.remove('open');
      }
    });

    document.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') {
        megaMenu.classList.remove('open');
        closeMobile();
      }
    });

    var otherLinks = document.querySelectorAll('#nav-menu .nav-link:not(.nav-collections-trigger)');
    for (var i = 0; i < otherLinks.length; i++) {
      otherLinks[i].addEventListener('click', function() { megaMenu.classList.remove('open'); });
    }

    var contactDropdown = document.getElementById('contact-dropdown');
    var contactMenuEl = document.getElementById('contact-dropdown-menu');
    if (contactDropdown && contactMenuEl) {
      var contactTimer;
      contactDropdown.addEventListener('mouseenter', function() {
        if (window.innerWidth >= 1024) {
          clearTimeout(contactTimer);
          contactDropdown.classList.add('open');
        }
      });
      contactDropdown.addEventListener('mouseleave', function() {
        if (window.innerWidth >= 1024) {
          contactTimer = setTimeout(function() { contactDropdown.classList.remove('open'); }, 250);
        }
      });
      document.addEventListener('click', function(e) {
        if (contactDropdown.classList.contains('open') && !contactDropdown.contains(e.target)) {
          contactDropdown.classList.remove('open');
        }
      });
    }

    hamburger.addEventListener('click', function(e) {
      e.stopPropagation();
      if (mobileMenu.classList.contains('open')) closeMobile();
      else {
        mobileMenu.classList.add('open');
        document.body.style.overflow = 'hidden';
      }
    });
  }

  // Bound after EVERY renderMenus. These elements live inside the mobile-menu
  // content that renderMenus rebuilds, so they must be re-bound each time.
  function bindMenuInteractions() {
    var mobileMenu = document.getElementById('mobile-menu');
    if (!mobileMenu) return;

    var collToggle = document.getElementById('mobile-coll-toggle');
    var collPanel = document.getElementById('mobile-coll-panel');
    if (collToggle && collPanel) {
      collToggle.addEventListener('click', function() {
        collPanel.classList.toggle('open');
        collToggle.querySelector('.toggle-icon').textContent = collPanel.classList.contains('open') ? '\u2013' : '+';
      });
    }

    var contactToggle = document.getElementById('mobile-contact-toggle');
    var contactPanel = document.getElementById('mobile-contact-panel');
    if (contactToggle && contactPanel) {
      contactToggle.addEventListener('click', function(e) {
        e.stopPropagation();
        contactPanel.classList.toggle('open');
        contactToggle.querySelector('.toggle-icon').textContent = contactPanel.classList.contains('open') ? '\u2013' : '+';
      });
    }

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

    var allMobileLinks = mobileMenu.querySelectorAll('a');
    for (var l = 0; l < allMobileLinks.length; l++) {
      allMobileLinks[l].addEventListener('click', closeMobile);
    }
  }

  renderMenus(FALLBACK_COLLECTIONS);
  bindNavControls();
  bindMenuInteractions();

  loadCollections().then(function(collections) {
    if (collections && collections.length) {
      renderMenus(collections);
      bindMenuInteractions();
    }
  });
})();
