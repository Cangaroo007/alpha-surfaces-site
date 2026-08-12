// roadrunner.js
// Fire-and-forget forwarder that mirrors live website engagement into
// RoadRunner (the CRM). Gated on ROADRUNNER_INGEST_URL + ROADRUNNER_API_KEY;
// if either is unset the integration is simply off and nothing happens.
//
// Every failure is swallowed and logged so a RoadRunner outage, timeout or
// bad response can never block or throw into the visitor-facing request path —
// the same discipline the Pipedrive integration uses.

function getConfig() {
  return {
    url: process.env.ROADRUNNER_INGEST_URL,
    key: process.env.ROADRUNNER_API_KEY
  };
}

// Internal: POST a single event to RoadRunner. Never rejects.
async function postEvent(body) {
  const { url, key } = getConfig();
  if (!url || !key) return; // integration disabled — do nothing
  try {
    await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${key}`
      },
      body: JSON.stringify(body)
    });
  } catch (err) {
    console.error('[roadrunner] forward failed:', err.message);
  }
}

// Forward a landing-page engagement snapshot for a tracked prospect.
function forwardEngagement(v = {}) {
  return postEvent({
    event_type: 'engagement',
    prospect_id: v.pid || null,
    campaign: v.campaign || null,
    account_manager: v.am_email || null,
    page: v.page || null,
    duration_seconds: Number(v.duration_seconds) || 0,
    max_scroll_pct: Number(v.max_scroll_pct) || 0,
    cta_clicks: Array.isArray(v.cta_clicks) ? v.cta_clicks : [],
    referrer: v.referrer || null,
    occurred_at: new Date().toISOString()
  });
}

// Forward a form conversion for a tracked prospect. conversion_type is an
// extra field beyond the base engagement shape so RoadRunner can distinguish
// a sample request from an enquiry.
function forwardConversion(v = {}) {
  return postEvent({
    event_type: 'conversion',
    prospect_id: v.pid || null,
    campaign: v.campaign || null,
    account_manager: v.account_manager || null,
    page: v.page || null,
    conversion_type: v.conversion_type || null,
    duration_seconds: null,
    max_scroll_pct: null,
    cta_clicks: [],
    referrer: v.referrer || null,
    occurred_at: new Date().toISOString()
  });
}

module.exports = { forwardEngagement, forwardConversion };
