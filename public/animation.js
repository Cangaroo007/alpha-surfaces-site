/* ═══════════════════════════════════════════════════════════════
   ALPHA SURFACES — Shared Animation Controller v3
   Fixed element targeting — explicit broad selectors
   ═══════════════════════════════════════════════════════════════ */

(function() {
  'use strict';

  var prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function tag(el, cls) {
    if (!el || el.classList.contains(cls)) return;
    el.classList.add(cls);
  }

  /* ─── 1. SCROLL REVEAL ─── */
  function initReveal() {
    // Broad explicit targeting — tag all major content elements
    var revealSelectors = [
      // Sections and their direct children
      '.statement > *',
      '.about > *, .about-inner, .about-top, .about-bottom, .about-quote, .about-author, .about-body',
      '.gallery > *, .gallery-grid, .gallery-left, .gallery-right, .gallery-left-inner, .gallery-right-inner',
      '.contact > *, .contact-inner, .contact-left, .contact-form',
      '.locations > *, .locations-columns',
      '.intro > *, .intro-inner, .intro-top, .intro-bottom',
      '.quality > *, .quality-inner, .quality-text, .quality-img-wrap',
      // Cards
      '.stone-card, .col-card, .value-card, .showcase-card, .location-card, .back-benefit',
      // Partner pages
      '.about-partner-inner, .about-partner-brand, .about-partner-text',
      // Contact elements
      '.contact-heading, .contact-person, .contact-details, .contact-links, .contact-block',
      // Generic content blocks
      '.collection-group, .collection-header, .collection-desc',
      '.btn-order, .btn-contact, .btn-submit',
      // Collection page intro
      '.intro-heading, .intro-body, .intro-shield, .intro-advantage',
      // Misc
      '.resources-section, .hero-caption'
    ].join(', ');

    document.querySelectorAll(revealSelectors).forEach(function(el) {
      if (el.closest('nav') || el.closest('footer')) return;
      tag(el, 'anim-reveal');
    });

    // Headings — X+Y reveal
    document.querySelectorAll('h1, h2, h3').forEach(function(el) {
      if (el.closest('nav') || el.closest('footer') || el.closest('.hero')) return;
      el.classList.remove('anim-reveal');
      tag(el, 'anim-reveal-heading');
    });
    // Also tag specific heading-like elements
    document.querySelectorAll('.value-heading, .showcase-heading, .locations-title, .resources-title, .collections-heading, .quality-heading, .about-partner-heading, .ch-bold, .back-main-heading').forEach(function(el) {
      el.classList.remove('anim-reveal');
      tag(el, 'anim-reveal-heading');
    });

    // Section labels — slide from left
    document.querySelectorAll('.value-label, .showcase-label, .page-hero-label, .collection-label, .back-header-label, .resources-label').forEach(function(el) {
      el.classList.remove('anim-reveal');
      tag(el, 'anim-reveal-label');
    });

    // Stagger grid children at 120ms
    document.querySelectorAll('.value-grid, .showcase-grid, .stones-grid, .location-cards, .back-benefits, .gallery-grid, .back-collections-row').forEach(function(grid) {
      grid.classList.add('anim-stagger');
      var children = grid.children;
      for (var i = 0; i < children.length; i++) {
        tag(children[i], 'anim-reveal');
        children[i].style.setProperty('--anim-delay', (i * 0.12) + 's');
      }
    });

    // Images in content areas — clip-path wipe
    document.querySelectorAll('.gallery-left-inner img, .gallery-right-inner img, .quality-img-wrap img, .intro-swatch img, .full-swatch img, .showcase-card img, .about-img, .swatch img').forEach(function(img) {
      if (img.classList.contains('anim-parallax-hero')) return;
      tag(img, 'anim-img-reveal');
    });

    // Observe everything
    var allAnimated = document.querySelectorAll('.anim-reveal, .anim-reveal-heading, .anim-reveal-label, .anim-img-reveal');
    var io = new IntersectionObserver(function(entries) {
      entries.forEach(function(e) {
        if (e.isIntersecting) {
          e.target.classList.add('anim-visible');
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.15 });

    allAnimated.forEach(function(el) { io.observe(el); });
  }

  /* ─── 2. PARALLAX HERO ─── */
  function initParallax() {
    if (prefersReduced) return;
    if (window.innerWidth < 768) return;

    var heroImg = document.querySelector('.hero > img, .hero .hero-video, .hero-img');
    if (!heroImg) return;

    heroImg.classList.add('anim-parallax-hero');
    var heroSection = heroImg.closest('.hero') || heroImg.parentElement;
    var heroHeight = heroSection ? heroSection.offsetHeight : 900;

    heroImg.style.transform = 'scale(1.08)';

    var ticking = false;
    window.addEventListener('scroll', function() {
      if (!ticking) {
        requestAnimationFrame(function() {
          var scrollY = window.pageYOffset;
          if (scrollY < heroHeight) {
            var scrollProgress = scrollY / heroHeight;
            var scale = 1.08 - (scrollProgress * 0.08);
            heroImg.style.transform = 'translateY(' + (scrollY * 0.55) + 'px) scale(' + Math.max(scale, 1.0) + ')';
          }
          ticking = false;
        });
        ticking = true;
      }
    }, { passive: true });
  }

  /* ─── 3. STONE CARD HOVER ─── */
  function initCardHover() {
    document.querySelectorAll('.stone-card, .showcase-card, .col-card').forEach(function(card) {
      card.classList.add('anim-card');
    });
  }

  /* ─── 4. SECTION TRANSITIONS (scale 0.98 → 1.0) ─── */
  function initSectionTransitions() {
    document.querySelectorAll('.statement, .about, .gallery, .value, .showcase, .contact, .locations, .collections-section, .quality, .about-partner, .intro, .swatch, .full-swatch').forEach(function(el) {
      tag(el, 'anim-section');
    });

    var io = new IntersectionObserver(function(entries) {
      entries.forEach(function(e) {
        if (e.isIntersecting) {
          e.target.classList.add('anim-visible');
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.05 });

    document.querySelectorAll('.anim-section').forEach(function(el) { io.observe(el); });
  }

  /* ─── 5. NAV SCROLL BEHAVIOUR ─── */
  function initNavScroll() {
    var nav = document.querySelector('.nav');
    if (!nav) return;

    var ticking = false;
    window.addEventListener('scroll', function() {
      if (!ticking) {
        requestAnimationFrame(function() {
          if (window.pageYOffset > 80) {
            nav.classList.add('nav-scrolled');
          } else {
            nav.classList.remove('nav-scrolled');
          }
          ticking = false;
        });
        ticking = true;
      }
    }, { passive: true });
  }

  /* ─── 6. SWATCH PARALLAX (stone detail pages) ─── */
  function initSwatchParallax() {
    if (prefersReduced) return;
    if (window.innerWidth < 768) return;

    var swatch = document.querySelector('.full-swatch');
    if (!swatch) return;
    var swatchImg = swatch.querySelector('img');
    if (!swatchImg) return;

    swatch.classList.add('anim-parallax-swatch');
    swatchImg.style.transform = 'scale(1.15)';

    var ticking = false;
    window.addEventListener('scroll', function() {
      if (!ticking) {
        requestAnimationFrame(function() {
          var rect = swatch.getBoundingClientRect();
          var windowH = window.innerHeight;
          if (rect.top < windowH && rect.bottom > 0) {
            var progress = (windowH - rect.top) / (windowH + rect.height);
            var offset = (progress - 0.5) * rect.height * 0.4;
            swatchImg.style.transform = 'translateY(' + offset + 'px) scale(1.15)';
          }
          ticking = false;
        });
        ticking = true;
      }
    }, { passive: true });
  }

  /* ─── 7. COUNT-UP STATS ─── */
  function initCountUp() {
    var statValues = document.querySelectorAll('.hero-stat-value, .front-stat-number');
    if (statValues.length === 0) return;

    statValues.forEach(function(el, idx) {
      var text = el.textContent.trim();
      var match = text.match(/^(\d+)(.*)/);
      if (!match) return;
      el.setAttribute('data-count-target', parseInt(match[1], 10));
      el.setAttribute('data-count-suffix', match[2]);
      el.setAttribute('data-count-index', idx);
      el.textContent = '0' + match[2];
    });

    var io = new IntersectionObserver(function(entries) {
      entries.forEach(function(e) {
        if (!e.isIntersecting) return;
        io.unobserve(e.target);

        var target = parseInt(e.target.getAttribute('data-count-target'), 10);
        var suffix = e.target.getAttribute('data-count-suffix') || '';
        var index = parseInt(e.target.getAttribute('data-count-index') || '0', 10);
        var delay = 400 + (index * 200);

        setTimeout(function() {
          var start = performance.now();
          var duration = 1500;
          function step(now) {
            var elapsed = now - start;
            var progress = Math.min(elapsed / duration, 1);
            var eased = progress < 0.7
              ? 1.08 * (1 - Math.pow(1 - progress / 0.7, 3))
              : 1.08 - (0.08 * ((progress - 0.7) / 0.3));
            e.target.textContent = Math.round(eased * target) + suffix;
            if (progress < 1) requestAnimationFrame(step);
            else e.target.textContent = target + suffix;
          }
          requestAnimationFrame(step);
        }, delay);
      });
    }, { threshold: 0.5 });

    statValues.forEach(function(el) {
      if (el.hasAttribute('data-count-target')) io.observe(el);
    });
  }

  /* ─── 8. HORIZONTAL SCROLL (mobile collections) ─── */
  function initHScroll() {
    if (window.innerWidth >= 768) return;
    document.querySelectorAll('.stones-grid').forEach(function(grid) {
      grid.classList.add('anim-hscroll');
      var parent = grid.parentElement;
      if (parent && !parent.classList.contains('anim-hscroll-wrap')) {
        parent.classList.add('anim-hscroll-wrap');
      }
      grid.addEventListener('scroll', function() {
        var atEnd = grid.scrollLeft + grid.clientWidth >= grid.scrollWidth - 10;
        if (parent) parent.classList.toggle('scrolled-end', atEnd);
      }, { passive: true });
    });
  }

  /* ─── INIT ─── */
  function init() {
    // Delay to let dynamic content (stones.json) render
    setTimeout(function() {
      initReveal();
      initCardHover();
      initSectionTransitions();
      initCountUp();
      initHScroll();
    }, 400);

    // Immediate — no DOM dependency
    initNavScroll();
    initParallax();
    initSwatchParallax();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
