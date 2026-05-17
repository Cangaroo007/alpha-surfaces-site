// landing-page-tracker.js
// Engagement tracking for partner/prospect landing pages. Self-disables
// when no ?pid= URL param is present, so it's safe to include on every
// partner page (organic visits incur zero tracking overhead).
//
// What it does when ?pid= is present:
//   1. Tags the session in Microsoft Clarity for dashboard filtering
//   2. Fires a GA4 landing_page_view event
//   3. Tracks scroll depth, time-on-page, and CTA clicks
//   4. Periodically posts the engagement summary to /api/tracking/landing-page
//      via sendBeacon (fires on tab-hide and beforeunload as well)
//   5. Rewrites any /order-sample or /enquiry CTA hrefs to carry the
//      UTM params + pid through to the form pages for attribution

(function () {
  var params = new URLSearchParams(window.location.search);
  var pid = params.get('pid');
  var campaign = params.get('utm_campaign');
  var amEmail = params.get('utm_content');

  if (!pid) return; // organic visit — no tracking

  // ─── Microsoft Clarity custom tags (for dashboard filtering) ───
  if (typeof window.clarity === 'function') {
    try {
      window.clarity('identify', pid);
      if (campaign) window.clarity('set', 'campaign', campaign);
      if (amEmail) window.clarity('set', 'account_manager', amEmail);
      window.clarity('set', 'visit_type', 'outreach');
    } catch (e) { /* no-op */ }
  }

  // ─── GA4 custom event for the landing-page view ───
  if (typeof window.gtag === 'function') {
    window.gtag('event', 'landing_page_view', {
      prospect_id: pid,
      campaign: campaign,
      account_manager: amEmail,
      page_slug: window.location.pathname
    });
  }

  var startTime = Date.now();
  var maxScroll = 0;
  var ctaClicks = [];
  var lastSentAt = 0;

  window.addEventListener('scroll', function () {
    var doc = document.documentElement;
    var fullHeight = Math.max(document.body.scrollHeight, doc.scrollHeight);
    if (fullHeight <= 0) return;
    var scrollPct = Math.round(
      (window.scrollY + window.innerHeight) / fullHeight * 100
    );
    if (scrollPct > maxScroll) maxScroll = Math.min(scrollPct, 100);
  }, { passive: true });

  // CTA tracking — covers sample/enquiry forms and direct mailto/tel
  // contact links so we capture phone & email clicks too.
  var ctaSelector =
    'a[href*="order-sample"], a[href*="enquiry"], ' +
    'a[href*="tel:"], a[href*="mailto:"]';
  document.querySelectorAll(ctaSelector).forEach(function (el) {
    el.addEventListener('click', function () {
      var href = el.getAttribute('href') || '';
      var type = 'other';
      if (href.indexOf('order-sample') > -1) type = 'sample_request';
      else if (href.indexOf('enquiry') > -1) type = 'enquiry';
      else if (href.indexOf('tel:') === 0) type = 'phone_call';
      else if (href.indexOf('mailto:') === 0) type = 'email_click';

      ctaClicks.push({ type: type, timestamp: Date.now() });

      if (typeof window.gtag === 'function') {
        window.gtag('event', 'landing_page_cta', {
          cta_type: type,
          prospect_id: pid,
          campaign: campaign,
          account_manager: amEmail
        });
      }
    });
  });

  // Rewrite order-sample / enquiry CTAs to carry the attribution params
  // through to the form pages, so the form submission can be linked back
  // to this outreach send. Safe no-op if the page has no such links.
  document.querySelectorAll('a[href*="order-sample"], a[href*="enquiry"]')
    .forEach(function (el) {
      try {
        var url = new URL(el.getAttribute('href'), window.location.origin);
        url.searchParams.set('pid', pid);
        url.searchParams.set('utm_source', 'landing_page');
        if (campaign) url.searchParams.set('utm_campaign', campaign);
        if (amEmail) url.searchParams.set('utm_content', amEmail);
        el.setAttribute('href', url.toString());
      } catch (e) { /* skip malformed URLs */ }
    });

  function sendTracking() {
    // Debounce: at most one send per 10 seconds.
    if (Date.now() - lastSentAt < 10000) return;
    lastSentAt = Date.now();

    var payload = {
      pid: pid,
      campaign: campaign,
      am_email: amEmail,
      page: window.location.pathname,
      duration_seconds: Math.round((Date.now() - startTime) / 1000),
      max_scroll_pct: maxScroll,
      cta_clicks: ctaClicks,
      referrer: document.referrer,
      user_agent: navigator.userAgent,
      timestamp: new Date().toISOString()
    };

    var body = JSON.stringify(payload);
    if (navigator.sendBeacon) {
      try { navigator.sendBeacon('/api/tracking/landing-page', body); return; }
      catch (e) { /* fall through */ }
    }
    try {
      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/tracking/landing-page', true);
      xhr.setRequestHeader('Content-Type', 'application/json');
      xhr.send(body);
    } catch (e) { /* fire-and-forget */ }
  }

  window.addEventListener('beforeunload', sendTracking);
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'hidden') sendTracking();
  });
  setInterval(sendTracking, 30000);
})();
