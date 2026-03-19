/* ═══════════════════════════════════════════════════════════════
   ALPHA SURFACES — Shared Animation Controller v4
   Fix: 100ms init delay + above-fold stagger + transition on reveal only
   ═══════════════════════════════════════════════════════════════ */

(function() {
  'use strict';

  var prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function tag(el, cls) {
    if (!el || el.classList.contains(cls)) return;
    el.classList.add(cls);
  }

  function isAboveFold(el) {
    var rect = el.getBoundingClientRect();
    return rect.top < window.innerHeight;
  }

  /* ─── 1. SCROLL REVEAL ─── */
  function initReveal() {
    // Tag all major content elements
    var revealSelectors = [
      '.statement > *',
      '.about > *, .about-inner, .about-top, .about-bottom, .about-quote, .about-author, .about-body',
      '.gallery > *, .gallery-grid, .gallery-left, .gallery-right, .gallery-left-inner, .gallery-right-inner',
      '.contact > *, .contact-inner, .contact-left, .contact-form',
      '.locations > *, .locations-columns',
      '.intro > *, .intro-inner, .intro-top, .intro-bottom',
      '.quality > *, .quality-inner, .quality-text, .quality-img-wrap',
      '.stone-card, .col-card, .value-card, .showcase-card, .location-card, .back-benefit',
      '.about-partner-inner, .about-partner-brand, .about-partner-text',
      '.contact-heading, .contact-person, .contact-details, .contact-links, .contact-block',
      '.collection-group, .collection-header, .collection-desc',
      '.btn-order, .btn-contact, .btn-submit',
      '.intro-heading, .intro-body, .intro-shield, .intro-advantage',
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

    // Images — clip-path wipe
    document.querySelectorAll('.gallery-left-inner img, .gallery-right-inner img, .quality-img-wrap img, .intro-swatch img, .full-swatch img, .showcase-card img, .swatch img').forEach(function(img) {
      if (img.classList.contains('anim-parallax-hero')) return;
      tag(img, 'anim-img-reveal');
    });

    // Collect all animated elements
    var allAnimated = document.querySelectorAll('.anim-reveal, .anim-reveal-heading, .anim-reveal-label, .anim-img-reveal');

    // Above-fold elements get staggered delays starting at 600ms
    var aboveFoldIndex = 0;
    allAnimated.forEach(function(el) {
      if (isAboveFold(el)) {
        var delay = 600 + (aboveFoldIndex * 150);
        el.setAttribute('data-anim-delay', delay);
        aboveFoldIndex++;
      }
    });

    // Observe — elements below fold animate on scroll, above fold use staggered timeout
    var io = new IntersectionObserver(function(entries) {
      entries.forEach(function(e) {
        if (e.isIntersecting) {
          var delay = e.target.getAttribute('data-anim-delay');
          if (delay) {
            setTimeout(function() {
              e.target.classList.add('anim-visible');
            }, parseInt(delay, 10));
          } else {
            e.target.classList.add('anim-visible');
          }
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.15, rootMargin: '0px' });

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
            var p = scrollY / heroHeight;
            heroImg.style.transform = 'translateY(' + (scrollY * 0.55) + 'px) scale(' + Math.max(1.08 - p * 0.08, 1.0) + ')';
          }
          ticking = false;
        });
        ticking = true;
      }
    }, { passive: true });
  }

  /* ─── 3. CARD HOVER ─── */
  function initCardHover() {
    document.querySelectorAll('.stone-card, .showcase-card, .col-card').forEach(function(card) {
      card.classList.add('anim-card');
    });
  }

  /* ─── 4. SECTION TRANSITIONS ─── */
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

  /* ─── 5. NAV SCROLL ─── */
  function initNavScroll() {
    var nav = document.querySelector('.nav');
    if (!nav) return;

    var ticking = false;
    window.addEventListener('scroll', function() {
      if (!ticking) {
        requestAnimationFrame(function() {
          nav.classList.toggle('nav-scrolled', window.pageYOffset > 80);
          ticking = false;
        });
        ticking = true;
      }
    }, { passive: true });
  }

  /* ─── 6. SWATCH PARALLAX ─── */
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
          var wh = window.innerHeight;
          if (rect.top < wh && rect.bottom > 0) {
            var p = (wh - rect.top) / (wh + rect.height);
            swatchImg.style.transform = 'translateY(' + ((p - 0.5) * rect.height * 0.4) + 'px) scale(1.15)';
          }
          ticking = false;
        });
        ticking = true;
      }
    }, { passive: true });
  }

  /* ─── 7. COUNT-UP STATS ─── */
  function initCountUp() {
    var stats = document.querySelectorAll('.hero-stat-value, .front-stat-number');
    if (!stats.length) return;

    stats.forEach(function(el, idx) {
      var m = el.textContent.trim().match(/^(\d+)(.*)/);
      if (!m) return;
      el.setAttribute('data-count-target', parseInt(m[1], 10));
      el.setAttribute('data-count-suffix', m[2]);
      el.setAttribute('data-count-index', idx);
      el.textContent = '0' + m[2];
    });

    var io = new IntersectionObserver(function(entries) {
      entries.forEach(function(e) {
        if (!e.isIntersecting) return;
        io.unobserve(e.target);
        var target = parseInt(e.target.getAttribute('data-count-target'), 10);
        var suffix = e.target.getAttribute('data-count-suffix') || '';
        var idx = parseInt(e.target.getAttribute('data-count-index') || '0', 10);
        setTimeout(function() {
          var start = performance.now(), dur = 1500;
          function step(now) {
            var t = Math.min((now - start) / dur, 1);
            var eased = t < 0.7 ? 1.08 * (1 - Math.pow(1 - t / 0.7, 3)) : 1.08 - 0.08 * ((t - 0.7) / 0.3);
            e.target.textContent = Math.round(eased * target) + suffix;
            if (t < 1) requestAnimationFrame(step);
            else e.target.textContent = target + suffix;
          }
          requestAnimationFrame(step);
        }, 400 + idx * 200);
      });
    }, { threshold: 0.5 });

    stats.forEach(function(el) { if (el.hasAttribute('data-count-target')) io.observe(el); });
  }

  /* ─── 8. HORIZONTAL SCROLL (mobile) ─── */
  function initHScroll() {
    if (window.innerWidth >= 768) return;
    document.querySelectorAll('.stones-grid').forEach(function(grid) {
      grid.classList.add('anim-hscroll');
      var parent = grid.parentElement;
      if (parent && !parent.classList.contains('anim-hscroll-wrap')) parent.classList.add('anim-hscroll-wrap');
      grid.addEventListener('scroll', function() {
        if (parent) parent.classList.toggle('scrolled-end', grid.scrollLeft + grid.clientWidth >= grid.scrollWidth - 10);
      }, { passive: true });
    });
  }

  /* ─── INIT ─── */
  function initAnimations() {
    // Wait for dynamic content (stones.json)
    setTimeout(function() {
      initReveal();
      initCardHover();
      initSectionTransitions();
      initCountUp();
      initHScroll();
    }, 400);

    initNavScroll();
    initParallax();
    initSwatchParallax();
  }

  // 100ms delay ensures elements paint in hidden state before observer starts
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      setTimeout(initAnimations, 100);
    });
  } else {
    setTimeout(initAnimations, 100);
  }
})();
