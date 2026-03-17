/* ═══════════════════════════════════════════════════════════════
   ALPHA SURFACES — Shared Animation Controller v2
   Increased impact — editorial energy, refined not gimmicky
   ═══════════════════════════════════════════════════════════════ */

(function() {
  'use strict';

  var prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ─── 1. SCROLL REVEAL (increased drama) ─── */
  function initReveal() {
    // General reveal elements
    var selectors = [
      'section > *:not(img):not(.hero-overlay):not(.hero-content)',
      '.intro-container > *',
      '.about-inner > *',
      '.about-top, .about-bottom',
      '.value-card',
      '.showcase-card',
      '.gallery-left, .gallery-right',
      '.contact-left, .contact-form',
      '.quality-text, .quality-img-wrap',
      '.collection-group',
      '.location-card',
      '.intro-heading, .intro-body, .intro-bottom',
      '.back-benefit',
      '.contact-heading, .contact-person, .contact-details',
      '.statement p',
      '.about-partner-inner'
    ];

    var elements = document.querySelectorAll(selectors.join(', '));
    elements.forEach(function(el) {
      if (el.classList.contains('anim-reveal') || el.classList.contains('anim-reveal-heading')) return;
      if (el.closest('nav') || el.closest('footer')) return;
      if (el.closest('.hero') && !el.classList.contains('hero-content')) return;
      el.classList.add('anim-reveal');
    });

    // Headings get special X+Y reveal
    var headingSelectors = 'h1, h2, .page-hero h1, .value-heading, .showcase-heading, .collections-heading, .contact-heading .ch-bold, .about-partner-heading, .quality-heading';
    document.querySelectorAll(headingSelectors).forEach(function(el) {
      if (el.classList.contains('anim-reveal-heading')) return;
      if (el.closest('nav') || el.closest('footer')) return;
      // Remove generic reveal if applied, use heading reveal instead
      el.classList.remove('anim-reveal');
      el.classList.add('anim-reveal-heading');
    });

    // Section labels slide from left with 200ms delay
    var labelSelectors = '.value-label, .showcase-label, .page-hero-label, .collection-label';
    document.querySelectorAll(labelSelectors).forEach(function(el) {
      if (el.classList.contains('anim-reveal-label')) return;
      el.classList.remove('anim-reveal');
      el.classList.add('anim-reveal-label');
    });

    // Stagger grid children at 120ms
    document.querySelectorAll('.value-grid, .showcase-grid, .stones-grid, .location-cards, .back-benefits').forEach(function(grid) {
      grid.classList.add('anim-stagger');
      var children = grid.children;
      for (var i = 0; i < children.length; i++) {
        if (!children[i].classList.contains('anim-reveal')) {
          children[i].classList.add('anim-reveal');
        }
        children[i].style.setProperty('--anim-delay', (i * 0.12) + 's');
      }
    });

    // Observe all animated elements
    var allAnimated = document.querySelectorAll('.anim-reveal, .anim-reveal-heading, .anim-reveal-label');
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

  /* ─── 2. PARALLAX HERO (increased depth) ─── */
  function initParallax() {
    if (prefersReduced) return;
    if (window.innerWidth < 768) return;

    var heroImg = document.querySelector('.hero > img, .hero .hero-video, .hero-img');
    if (!heroImg) return;

    heroImg.classList.add('anim-parallax-hero');
    var heroSection = heroImg.closest('.hero') || heroImg.parentElement;
    var heroHeight = heroSection ? heroSection.offsetHeight : 900;

    // Start at 1.08 scale, settle toward 1.0 as you scroll
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

  /* ─── 3. STONE CARD HOVER (more presence) ─── */
  function initCardHover() {
    var cards = document.querySelectorAll('.stone-card, .showcase-card, .col-card');
    cards.forEach(function(card) {
      card.classList.add('anim-card');
    });
  }

  /* ─── 4. SECTION TRANSITIONS (scale 0.98 → 1.0) ─── */
  function initSectionTransitions() {
    var sectionSelectors = '.statement, .about, .gallery, .value, .showcase, .contact, .collections-section, .quality, .about-partner';
    var sections = document.querySelectorAll(sectionSelectors);

    sections.forEach(function(el) {
      el.classList.add('anim-section');
    });

    var io = new IntersectionObserver(function(entries) {
      entries.forEach(function(e) {
        if (e.isIntersecting) {
          e.target.classList.add('anim-visible');
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.05 });

    sections.forEach(function(el) { io.observe(el); });
  }

  /* ─── 5. IMAGE REVEAL (clip-path wipe) ─── */
  function initImageReveal() {
    var imgSelectors = '.hero > img, .hero .hero-video, .stone-card-image img, .showcase-card img, .gallery-grid img, .intro-swatch img, .full-swatch img, .quality-img-wrap img';
    var images = document.querySelectorAll(imgSelectors);

    images.forEach(function(img) {
      // Don't apply to parallax hero (it has its own animation)
      if (img.classList.contains('anim-parallax-hero')) return;
      img.classList.add('anim-img-reveal');
    });

    var io = new IntersectionObserver(function(entries) {
      entries.forEach(function(e) {
        if (e.isIntersecting) {
          e.target.classList.add('anim-visible');
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.1 });

    images.forEach(function(img) {
      if (img.classList.contains('anim-img-reveal')) io.observe(img);
    });
  }

  /* ─── 6. NAV SCROLL BEHAVIOUR (more responsive) ─── */
  function initNavScroll() {
    var nav = document.querySelector('.nav');
    if (!nav) return;

    var scrollThreshold = 80;
    var ticking = false;

    window.addEventListener('scroll', function() {
      if (!ticking) {
        requestAnimationFrame(function() {
          if (window.pageYOffset > scrollThreshold) {
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

  /* ─── 7. IMAGE PARALLAX (stone detail swatch) ─── */
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

  /* ─── 8. COUNT-UP ANIMATION (more theatrical) ─── */
  function initCountUp() {
    var statValues = document.querySelectorAll('.hero-stat-value, .front-stat-number');
    if (statValues.length === 0) return;

    statValues.forEach(function(el, idx) {
      var text = el.textContent.trim();
      var match = text.match(/^(\d+)(.*)/);
      if (!match) return;

      var targetNum = parseInt(match[1], 10);
      var suffix = match[2];
      el.setAttribute('data-count-target', targetNum);
      el.setAttribute('data-count-suffix', suffix);
      el.setAttribute('data-count-index', idx);
      el.textContent = '0' + suffix;
    });

    var io = new IntersectionObserver(function(entries) {
      entries.forEach(function(e) {
        if (!e.isIntersecting) return;
        io.unobserve(e.target);

        var target = parseInt(e.target.getAttribute('data-count-target'), 10);
        var suffix = e.target.getAttribute('data-count-suffix') || '';
        var index = parseInt(e.target.getAttribute('data-count-index') || '0', 10);
        var duration = 1500;

        // Staggered start: 400ms base delay + 200ms per stat
        var startDelay = 400 + (index * 200);

        setTimeout(function() {
          var start = performance.now();

          function step(now) {
            var elapsed = now - start;
            var progress = Math.min(elapsed / duration, 1);
            // Spring-like overshoot: overshoots to ~108% then settles
            var eased;
            if (progress < 0.7) {
              // Ease to 108%
              var p = progress / 0.7;
              eased = 1.08 * (1 - Math.pow(1 - p, 3));
            } else {
              // Settle from 108% to 100%
              var p2 = (progress - 0.7) / 0.3;
              eased = 1.08 - (0.08 * p2);
            }
            var current = Math.round(eased * target);
            e.target.textContent = current + suffix;
            if (progress < 1) requestAnimationFrame(step);
            else e.target.textContent = target + suffix; // Ensure exact final value
          }
          requestAnimationFrame(step);
        }, startDelay);
      });
    }, { threshold: 0.5 });

    statValues.forEach(function(el) {
      if (el.hasAttribute('data-count-target')) io.observe(el);
    });
  }

  /* ─── 9. HORIZONTAL COLLECTION SCROLL (mobile) ─── */
  function initHScroll() {
    if (window.innerWidth >= 768) return;

    var grids = document.querySelectorAll('.stones-grid');
    grids.forEach(function(grid) {
      grid.classList.add('anim-hscroll');

      var parent = grid.parentElement;
      if (parent && !parent.classList.contains('anim-hscroll-wrap')) {
        parent.classList.add('anim-hscroll-wrap');
      }

      grid.addEventListener('scroll', function() {
        var atEnd = grid.scrollLeft + grid.clientWidth >= grid.scrollWidth - 10;
        if (parent) {
          parent.classList.toggle('scrolled-end', atEnd);
        }
      }, { passive: true });
    });
  }

  /* ─── INIT ─── */
  function init() {
    // Wait a tick so dynamically generated content (stones.json) is ready
    setTimeout(function() {
      initReveal();
      initCardHover();
      initSectionTransitions();
      initImageReveal();
      initCountUp();
      initHScroll();
    }, 300);

    // These can run immediately
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
