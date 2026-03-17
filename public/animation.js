/* ═══════════════════════════════════════════════════════════════
   ALPHA SURFACES — Shared Animation Controller
   Pure JS + Intersection Observer — no external libraries
   ═══════════════════════════════════════════════════════════════ */

(function() {
  'use strict';

  // Bail out entirely if user prefers reduced motion
  var prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ─── 1. SCROLL REVEAL ─── */
  function initReveal() {
    // Auto-tag revealable elements
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
      'h1, h2, .page-hero h1, .page-hero p',
      '.statement p',
      '.value-heading, .value-label',
      '.showcase-heading, .showcase-label',
      '.collections-heading, .about-partner-inner'
    ];

    var elements = document.querySelectorAll(selectors.join(', '));
    elements.forEach(function(el) {
      // Don't double-tag or tag nav/footer
      if (el.classList.contains('anim-reveal')) return;
      if (el.closest('nav') || el.closest('footer')) return;
      if (el.closest('.hero') && !el.classList.contains('hero-content')) return;
      el.classList.add('anim-reveal');
    });

    // Apply stagger delays to grid children
    document.querySelectorAll('.value-grid, .showcase-grid, .stones-grid, .location-cards, .back-benefits').forEach(function(grid) {
      grid.classList.add('anim-stagger');
      var children = grid.children;
      for (var i = 0; i < children.length; i++) {
        children[i].classList.add('anim-reveal');
        children[i].style.setProperty('--anim-delay', (i * 0.08) + 's');
      }
    });

    // Observe
    var io = new IntersectionObserver(function(entries) {
      entries.forEach(function(e) {
        if (e.isIntersecting) {
          e.target.classList.add('anim-visible');
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.15 });

    document.querySelectorAll('.anim-reveal').forEach(function(el) {
      io.observe(el);
    });
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

    var ticking = false;
    window.addEventListener('scroll', function() {
      if (!ticking) {
        requestAnimationFrame(function() {
          var scrollY = window.pageYOffset;
          if (scrollY < heroHeight) {
            heroImg.style.transform = 'translateY(' + (scrollY * 0.4) + 'px) scale(1.1)';
          }
          ticking = false;
        });
        ticking = true;
      }
    }, { passive: true });

    // Initial scale to prevent gap at bottom
    heroImg.style.transform = 'scale(1.1)';
  }

  /* ─── 3. STONE CARD HOVER ─── */
  function initCardHover() {
    var cards = document.querySelectorAll('.stone-card, .showcase-card, .col-card');
    cards.forEach(function(card) {
      card.classList.add('anim-card');
    });
  }

  /* ─── 4. NAV SCROLL BEHAVIOUR ─── */
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

  /* ─── 5. IMAGE PARALLAX (stone detail swatch) ─── */
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

  /* ─── 6. COUNT-UP ANIMATION (index.html stats) ─── */
  function initCountUp() {
    var statValues = document.querySelectorAll('.hero-stat-value, .front-stat-number');
    if (statValues.length === 0) return;

    statValues.forEach(function(el) {
      var text = el.textContent.trim();
      // Extract numeric part and suffix
      var match = text.match(/^(\d+)(.*)/);
      if (!match) return;

      var targetNum = parseInt(match[1], 10);
      var suffix = match[2]; // e.g. "+", "%", "yr"
      el.setAttribute('data-count-target', targetNum);
      el.setAttribute('data-count-suffix', suffix);
      el.textContent = '0' + suffix;
    });

    var io = new IntersectionObserver(function(entries) {
      entries.forEach(function(e) {
        if (!e.isIntersecting) return;
        io.unobserve(e.target);

        var target = parseInt(e.target.getAttribute('data-count-target'), 10);
        var suffix = e.target.getAttribute('data-count-suffix') || '';
        var duration = 1500;
        var start = performance.now();

        function step(now) {
          var elapsed = now - start;
          var progress = Math.min(elapsed / duration, 1);
          // Ease-out: 1 - (1 - t)^3
          var eased = 1 - Math.pow(1 - progress, 3);
          var current = Math.round(eased * target);
          e.target.textContent = current + suffix;
          if (progress < 1) requestAnimationFrame(step);
        }
        requestAnimationFrame(step);
      });
    }, { threshold: 0.5 });

    statValues.forEach(function(el) {
      if (el.hasAttribute('data-count-target')) io.observe(el);
    });
  }

  /* ─── 7. HORIZONTAL COLLECTION SCROLL (mobile) ─── */
  function initHScroll() {
    if (window.innerWidth >= 768) return;

    var grids = document.querySelectorAll('.stones-grid');
    grids.forEach(function(grid) {
      grid.classList.add('anim-hscroll');

      // Wrap for scroll hint fade
      var parent = grid.parentElement;
      if (parent && !parent.classList.contains('anim-hscroll-wrap')) {
        parent.classList.add('anim-hscroll-wrap');
      }

      // Detect scroll end to hide hint
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
      initCountUp();
      initHScroll();
    }, 300);

    // These can run immediately
    initNavScroll();
    initParallax();
    initSwatchParallax();
  }

  // Run after DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
