const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const Anthropic = require('@anthropic-ai/sdk');
const OpenAI = require('openai');
const { GoogleGenerativeAI } = require('@google/generative-ai');

const versions = require('./lib/versions');
const { initDB, saveSubmission, saveSubscriber, unsubscribeEmail, pool } = require('./db');
const notifications = require('./notifications');
const { notifyOrderSample, notifyContact, notifySubscribe, sendTestForForm, sendDailyDigest, generateWeeklyReport, readSettings: readNotifSettings, writeSettings: writeNotifSettings, notifyNewSubmission, checkAndSendTimeAlert } = notifications;
const { scheduleAutoTracker } = require('./auto-time-tracker');
// Track I: typed-form insert helper. Loaded statically (the require below
// mounts routes; this property is attached to the module.exports object).
const { insertTypedSubmission } = require('./projects-routes');
// Pipedrive integration — best-effort sync of public form submits into the
// Pipedrive Leads Inbox (forms → HOT leads). All calls are wrapped so a
// Pipedrive outage can't fail the form response.
const pipedrive = require('./pipedrive');
const cmsCore = require('./cms-core');

const app = express();
const PORT = process.env.PORT || 3000;

// Railway terminates HTTPS at one upstream proxy and forwards via HTTP with
// X-Forwarded-For. express-rate-limit@8 throws ERR_ERL_UNEXPECTED_X_FORWARDED_FOR
// unless we declare the proxy trust depth — set to 1 (single hop).
app.set('trust proxy', 1);

// ─── Config ───
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'alpha2025';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const CONTENT_FILE = path.join(DATA_DIR, 'content.json');
const KEYS_FILE = path.join(DATA_DIR, 'keys.json');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// ─── API Keys Management ───
const KEY_NAMES = [
  'anthropic', 'openai', 'google', 'xai', 'runway',
  'cloudinary_cloud_name', 'cloudinary_api_key', 'cloudinary_api_secret'
];

const ENV_MAP = {
  anthropic: 'ANTHROPIC_API_KEY',
  openai: 'OPENAI_API_KEY',
  google: 'GOOGLE_AI_API_KEY',
  xai: 'XAI_API_KEY',
  runway: 'RUNWAY_API_KEY',
  cloudinary_cloud_name: 'CLOUDINARY_CLOUD_NAME',
  cloudinary_api_key: 'CLOUDINARY_API_KEY',
  cloudinary_api_secret: 'CLOUDINARY_API_SECRET',
};

let KEYS = {};
let keysFromFile = {};

function loadKeys() {
  // Start with empty keys
  const merged = {};
  for (const k of KEY_NAMES) merged[k] = '';

  // Load from keys.json if it exists
  try {
    if (fs.existsSync(KEYS_FILE)) {
      keysFromFile = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
      for (const k of KEY_NAMES) {
        if (keysFromFile[k]) merged[k] = keysFromFile[k];
      }
    }
  } catch (err) {
    console.error('Failed to load keys.json:', err.message);
  }

  // Env vars take priority
  for (const k of KEY_NAMES) {
    const envName = ENV_MAP[k];
    if (process.env[envName]) merged[k] = process.env[envName];
  }

  KEYS = merged;
}

function saveKeys() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(KEYS_FILE, JSON.stringify(keysFromFile, null, 2));
}

function getKeySource(keyName) {
  const envName = ENV_MAP[keyName];
  if (process.env[envName] && process.env[envName] === KEYS[keyName]) return 'env';
  if (keysFromFile[keyName] && keysFromFile[keyName] === KEYS[keyName]) return 'admin';
  return null;
}

function maskKey(value) {
  if (!value) return null;
  if (value.length < 12) return '••••••••';
  return value.substring(0, 6) + '••••••••' + value.substring(value.length - 4);
}

// Load keys on startup
loadKeys();

// ─── Cloudinary ───
function configureCloudinary() {
  cloudinary.config({
    cloud_name: KEYS.cloudinary_cloud_name,
    api_key: KEYS.cloudinary_api_key,
    api_secret: KEYS.cloudinary_api_secret,
  });
}
configureCloudinary();

// ─── Multer (memory storage) ───
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });

// Active sessions (in-memory, resets on restart)
const sessions = new Map();

// ─── Outreach tracking receiver (MUST be registered before express.json) ───
// Receiver for landing-page-tracker.js sendBeacon pings. Registered ahead
// of the global express.json() so body-parser never sees the request —
// production logs showed double-encoded payloads (""{\"pid\":...}"") that
// crashed body-parser with a strict-JSON SyntaxError, killing the response
// before the route handler could run. express.raw() hands us the untouched
// Buffer; we parse it here ourselves with a defensive single-layer
// stringification unwrap. Failures are swallowed (200) so a flaky tracking
// write never breaks the page experience.
app.post('/api/tracking/landing-page',
  express.raw({ type: '*/*', limit: '1mb' }),
  async (req, res) => {
    try {
      let raw = req.body;
      if (Buffer.isBuffer(raw)) raw = raw.toString('utf-8');
      if (typeof raw === 'string') raw = raw.trim();

      // Defensive: strip one layer of stringification if upstream
      // double-encoded the body (e.g. ""{\"pid\":...}"" → {"pid":...}).
      if (typeof raw === 'string' && raw.startsWith('"') && raw.endsWith('"')) {
        try { raw = JSON.parse(raw); } catch (e) { /* not double-wrapped */ }
      }

      const data = typeof raw === 'string' ? JSON.parse(raw) : (raw || {});
      const { pid, campaign, am_email, page,
              duration_seconds, max_scroll_pct, cta_clicks,
              referrer, user_agent } = data;
      if (!pid || !page) return res.sendStatus(400);

      await pool.query(
        `INSERT INTO landing_page_views
           (prospect_id, campaign, am_email, page_path, duration_seconds,
            max_scroll_pct, cta_clicks, referrer, user_agent, viewed_date, viewed_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, CURRENT_DATE, NOW())
         ON CONFLICT (prospect_id, page_path, viewed_date)
         DO UPDATE SET
           duration_seconds = GREATEST(landing_page_views.duration_seconds, EXCLUDED.duration_seconds),
           max_scroll_pct   = GREATEST(landing_page_views.max_scroll_pct,   EXCLUDED.max_scroll_pct),
           cta_clicks       = landing_page_views.cta_clicks || EXCLUDED.cta_clicks`,
        [pid, campaign || null, am_email || null, page,
         Number(duration_seconds) || 0, Number(max_scroll_pct) || 0,
         JSON.stringify(Array.isArray(cta_clicks) ? cta_clicks : []),
         referrer || null, user_agent || null]
      );

      // Promote send status from 'sent' → 'clicked' on first view. Don't
      // demote already-converted sends.
      await pool.query(
        `UPDATE outreach_sends
           SET status = 'clicked'
         WHERE prospect_id = $1 AND status = 'sent'`,
        [pid]
      );

      res.sendStatus(200);
    } catch (err) {
      console.error('[tracking] landing-page error:', err.message);
      res.sendStatus(200);
    }
  }
);

// ─── Middleware ───
app.use(express.json({ limit: '25mb' }));
app.use(cookieParser());
app.use(helmet());
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'", "'unsafe-inline'", "'unsafe-eval'",
        "https://cdn.jsdelivr.net", "https://online.flippingbook.com",
        "https://www.googletagmanager.com", "https://www.google-analytics.com",
        "https://www.clarity.ms", "https://*.clarity.ms"
      ],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://online.flippingbook.com", "https://*.flippingbook.com"],
      imgSrc: [
        "'self'", "https://res.cloudinary.com", "data:",
        "https://online.flippingbook.com", "https://*.flippingbook.com",
        "https://www.google-analytics.com", "https://www.googletagmanager.com",
        "https://c.clarity.ms", "https://*.clarity.ms"
      ],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: [
        "'self'", "https://online.flippingbook.com", "https://*.flippingbook.com",
        "https://www.google-analytics.com", "https://region1.google-analytics.com",
        "https://analytics.google.com",
        "https://www.clarity.ms", "https://c.clarity.ms", "https://d.clarity.ms",
        "https://*.clarity.ms",
        "https://roadrunner-api-staging.up.railway.app"
      ],
      frameSrc: ["'self'", "https://online.flippingbook.com"],
      scriptSrcAttr: ["'unsafe-inline'"],
    },
  })
);
// Cache headers — public pages cached by Cloudflare (failover during outages)
app.use((req, res, next) => {
  const p = req.path;
  const isPublicAPI = p === '/api/public/stones' || p === '/api/public/collections';
  const isAPI = p.startsWith('/api/') && !isPublicAPI;
  const isAdmin = p === '/admin' || p.startsWith('/admin/') || p.startsWith('/projects');
  const isForm = ['/order-sample', '/enquiry', '/warranty', '/showroom-checkin'].some(f => p.startsWith(f));

  if (isAPI || isAdmin || isForm) {
    res.set({ 'Cache-Control': 'no-cache, no-store, must-revalidate', 'Pragma': 'no-cache', 'Expires': '0' });
  } else if (isPublicAPI) {
    res.set({ 'Cache-Control': 'public, max-age=300, s-maxage=3600', 'Vary': 'Accept-Encoding' });
  } else if (!p.includes('.') || p.endsWith('.html')) {
    res.set({ 'Cache-Control': 'public, max-age=14400, s-maxage=14400', 'Vary': 'Accept-Encoding' });
  }
  next();
});

// ─── Shared footer partial (single source of truth) ───
// views/partials/footer.html is the canonical 4-column footer. Pages that opt
// in carry a `<!-- FOOTER -->` marker (left in place by scripts/strip-footer.js);
// the middleware below substitutes it on the way out. Pages without the marker
// (admin, kc, partner pages, catalog viewer, etc.) are served unchanged.
// Cached at startup — restart to pick up partial edits.
const PUBLIC_DIR = path.resolve(path.join(__dirname, 'public'));
const FOOTER_PARTIAL = fs.readFileSync(path.join(__dirname, 'views', 'partials', 'footer.html'), 'utf8');
const FOOTER_MARKER = '<!-- FOOTER -->';

function renderHtml(filePath) {
  const html = fs.readFileSync(filePath, 'utf8');
  return html.includes(FOOTER_MARKER)
    ? html.replace(FOOTER_MARKER, FOOTER_PARTIAL)
    : html;
}

function sendHtml(res, filePath) {
  res.set('Content-Type', 'text/html; charset=utf-8');
  res.send(renderHtml(filePath));
}

// Intercept GET requests that resolve to a public/*.html file so the footer
// partial gets injected. Runs before express.static. Path traversal is
// blocked by ensuring the resolved path stays inside PUBLIC_DIR.
app.use((req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  let urlPath = req.path;
  if (urlPath === '/') urlPath = '/index.html';
  if (!urlPath.endsWith('.html')) return next();
  const resolved = path.resolve(path.join(PUBLIC_DIR, urlPath));
  if (!resolved.startsWith(PUBLIC_DIR + path.sep)) return next();
  if (!fs.existsSync(resolved)) return next();
  return sendHtml(res, resolved);
});

// Browsers auto-request /favicon.ico; without a handler it 404s and the tab
// shows no icon. Serve the Alpha "A" mark (PNG bytes; modern browsers accept
// PNG for /favicon.ico). apple-touch-icon.png sits in /public and is served
// by express.static for iOS home-screen saves.
app.get('/favicon.ico', (_req, res) => {
  res.type('image/png');
  res.set('Cache-Control', 'public, max-age=604800');
  res.sendFile(path.join(__dirname, 'public', 'favicon-32.png'));
});

app.use(express.static(path.join(__dirname, 'public')));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
});

// ─── Helpers ───
function loadContent() {
  try {
    return JSON.parse(fs.readFileSync(CONTENT_FILE, 'utf8'));
  } catch {
    const defaults = JSON.parse(fs.readFileSync(path.join(__dirname, 'config', 'defaults.json'), 'utf8'));
    saveContent(defaults);
    return defaults;
  }
}

function saveContent(data) {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(CONTENT_FILE, JSON.stringify(data, null, 2));
}

// Bound after projects-routes mounts (see ./projects-routes require call
// later in this file). Falls back to a no-op resolver until then so the
// closure below stays safe at import time.
let resolveProjectsUser = () => null;

function authMiddleware(req, res, next) {
  const token = req.cookies?.alpha_session;
  if (token && sessions.has(token)) return next();
  // Project-tracker super_admins are granted CMS access too — one login
  // covers /projects, /forms, and /admin.
  const pUser = resolveProjectsUser(req);
  if (pUser && pUser.role === 'super_admin' && !pUser.must_change_password) {
    req.user = pUser;
    return next();
  }
  res.status(401).json({ error: 'Unauthorized' });
}

// ─── Public Form API ───
async function handleForm(req, res, formType) {
  try {
    const fields = req.body;
    if (!fields.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fields.email)) {
      return res.status(400).json({ ok: false, error: 'A valid email address is required.' });
    }
    const sampleItems = fields.sampleItems
      ? fields.sampleItems.slice(0, 3)
      : fields.samples
        ? (Array.isArray(fields.samples) ? fields.samples : [fields.samples])
            .slice(0, 3).map(slug => ({ slug, name: slug, collection: '' }))
        : [];
    if (formType === 'Sample Request' && sampleItems.length === 0 && !fields.stone_slug) {
      return res.status(400).json({ ok: false, error: 'Please select at least one sample.' });
    }
    if (fields.stone_slug && sampleItems.length === 0) {
      sampleItems.push({
        slug: fields.stone_slug,
        name: fields.stone_name || fields.stone_slug,
        collection: fields.stone_collection || ''
      });
    }
    const { id } = await saveSubmission(formType, fields, sampleItems);

    // Re-fetch the full row so the notification email gets every populated
    // column (id, name, role, reason, address, raw_data, etc.). Build a
    // synthetic stone_interest from the picked sample items so the email
    // and SMS surface what was actually requested.
    const { rows } = await pool.query('SELECT * FROM form_submissions WHERE id = $1', [id]);
    const submission = rows[0] || {};
    if (sampleItems.length && !submission.stone_interest) {
      submission.stone_interest = sampleItems.map(s => s.name).filter(Boolean).join(', ');
    }

    notifyNewSubmission(submission).catch(err =>
      console.error(`[notify] ${formType} notification error:`, err.message)
    );

    // Track I: also write into the matching typed table so the new per-form
    // views see the submission alongside the legacy archive. Best-effort —
    // a failure here mustn't block the public form response.
    let typed = null;
    try {
      if (typeof insertTypedSubmission === 'function') {
        typed = await insertTypedSubmission(pool, formType, fields, sampleItems);
      }
    } catch (err) {
      console.error('[form] typed insert error:', err.message);
    }

    // Outreach attribution — when the form arrived with a landing-page
    // pid + utm_source, link it back to the originating send and mark the
    // send as converted so the per-AM dashboard reflects the conversion.
    // Best-effort: a missing/stale pid must never block the form response.
    const pid = fields.pid || null;
    const utmSource = fields.utm_source || null;
    if (pid && utmSource === 'landing_page') {
      const conversionType = formType === 'Sample Request' ? 'sample_request'
        : formType === 'Enquiry' ? 'enquiry'
        : formType === 'Contact Enquiry' ? 'contact'
        : 'other';
      pool.query(
        `INSERT INTO outreach_conversions
           (prospect_id, outreach_send_id, form_submission_id, conversion_type)
         SELECT $1, (SELECT id FROM outreach_sends WHERE prospect_id = $1 ORDER BY sent_at DESC LIMIT 1),
                $2, $3`,
        [pid, id, conversionType]
      ).then(() =>
        pool.query(
          `UPDATE outreach_sends SET status = 'converted' WHERE prospect_id = $1`,
          [pid]
        )
      ).catch(err => console.error('[outreach] conversion log error:', err.message));
    }

    // Pipedrive: forms → HOT leads (or activity/note for walk-ins/warranty).
    // Fire-and-forget so a Pipedrive 500 / network blip never blocks the user.
    if (process.env.PIPEDRIVE_API_TOKEN) {
      pipedrive.syncFormToPipedrive(formType, fields, sampleItems, typed)
        .catch(err => console.error('[pipedrive] sync error:', err.message));
    }

    return res.json({ ok: true, id, reference: typed && typed.reference });
  } catch (err) {
    console.error(`[form] ${formType} error:`, err.message);
    return res.status(500).json({ ok: false, error: 'Something went wrong. Please try again.' });
  }
}

app.post('/api/order-sample', (req, res) => handleForm(req, res, 'Sample Request'));
app.post('/api/contact',      (req, res) => handleForm(req, res, 'Contact Enquiry'));

// ─── Warranty installation-photo upload (Track I) ───
// Used by /warranty.html before the warranty form is submitted. Photos go
// to Cloudinary; the public/secure URLs come back to the page, which then
// includes them in the warranty payload as `installation_photos`.
const warrantyUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 3 },
  fileFilter: (req, file, cb) => {
    const ok = ['image/jpeg', 'image/png', 'image/webp', 'image/heic', 'image/heif']
      .includes((file.mimetype || '').toLowerCase());
    cb(ok ? null : new Error('Only JPG, PNG, WebP, or HEIC images allowed.'), ok);
  }
});
app.post('/api/warranty-upload',
  (req, res, next) => warrantyUpload.array('photos', 3)(req, res, (err) => {
    if (err) return res.status(400).json({ ok: false, error: err.message });
    next();
  }),
  async (req, res) => {
    try {
      if (!req.files || !req.files.length) {
        return res.status(400).json({ ok: false, error: 'No photos uploaded.' });
      }
      const urls = [];
      for (const file of req.files) {
        const result = await new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            {
              folder: 'alpha-surfaces/warranty-photos',
              resource_type: 'image',
              use_filename: true,
              unique_filename: true
            },
            (err, r) => err ? reject(err) : resolve(r)
          );
          stream.end(file.buffer);
        });
        urls.push(result.secure_url);
      }
      res.json({ ok: true, urls });
    } catch (err) {
      console.error('[warranty-upload]', err.message);
      res.status(500).json({ ok: false, error: 'Upload failed.' });
    }
  }
);

// Generic submit endpoint for new public forms (enquiry, warranty, …).
// Maps `form_type` in the body to the human-readable label stored in
// form_submissions.form_type, then delegates to the same handler that
// covers Sample Request / Contact Enquiry — so DB insert, raw_data
// JSONB capture, and SMS+email notifications all flow the same way.
const FORM_TYPE_LABELS = {
  enquiry:  'Enquiry',
  warranty: 'Warranty Activation',
};
app.post('/api/form-submit', (req, res) => {
  const raw = String(req.body && req.body.form_type || '').toLowerCase().trim();
  // Showroom check-in lives outside the form_submissions pipeline because
  // walk-ins often won't share an email — handleForm requires one. We write
  // straight into showroom_checkins via insertTypedSubmission and fire the
  // standard SMS+email notification with a synthetic submission object so
  // Belinda's alerts still go out.
  if (raw === 'showroom-checkin') {
    return handleShowroomCheckin(req, res);
  }
  const label = FORM_TYPE_LABELS[raw];
  if (!label) {
    return res.status(400).json({ ok: false, error: 'Unknown form type.' });
  }
  return handleForm(req, res, label);
});

async function handleShowroomCheckin(req, res) {
  try {
    const f = req.body || {};
    const name  = String(f.name  || '').trim();
    const phone = String(f.phone || '').trim();
    if (!name)  return res.status(400).json({ ok: false, error: 'Name is required.' });
    if (!phone) return res.status(400).json({ ok: false, error: 'Phone is required.' });
    const fields = {
      name,
      phone,
      email: f.email ? String(f.email).trim() : null,
      stone_interest: f.stone_interest || null,
      source: f.source || null,
      message: f.message || f.notes || null,
      consent: true
    };
    const typed = await insertTypedSubmission(pool, 'Showroom Check-In', fields);
    if (!typed) {
      return res.status(500).json({ ok: false, error: 'Could not save check-in.' });
    }
    // Fire the same SMS+email notification path used for typed submissions.
    // Synthetic submission shape — only the keys the notifier reads.
    notifyNewSubmission({
      id: typed.id,
      form_type: 'Showroom Check-In',
      submitted_at: new Date(),
      name,
      email: fields.email,
      phone,
      stone_interest: fields.stone_interest,
      message: fields.message,
      source: fields.source,
      reference: typed.reference,
      status: 'new',
      consent: true
    }).catch(err => console.error('[notify] Showroom Check-In error:', err.message));

    // Pipedrive: log walk-in as a completed activity on the person record.
    if (process.env.PIPEDRIVE_API_TOKEN) {
      pipedrive.syncFormToPipedrive('Showroom Check-In', fields, [], typed)
        .catch(err => console.error('[pipedrive] showroom sync error:', err.message));
    }

    return res.json({ ok: true, id: typed.id, reference: typed.reference });
  } catch (err) {
    console.error('[form] Showroom Check-In error:', err.message);
    return res.status(500).json({ ok: false, error: 'Something went wrong. Please try again.' });
  }
}

function generateUnsubscribeUrl(email) {
  const secret  = process.env.SESSION_SECRET || 'alpha-surfaces-secret';
  const token   = crypto.createHmac('sha256', secret).update(email.toLowerCase().trim()).digest('hex').substring(0, 16);
  const base    = process.env.SITE_URL || 'https://alphasurfaces.com.au';
  return `${base}/unsubscribe?email=${encodeURIComponent(email)}&token=${token}`;
}

app.post('/api/subscribe', async (req, res) => {
  try {
    const { email, consent } = req.body;
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ ok: false, error: 'A valid email address is required.' });
    }
    if (!consent) {
      return res.status(400).json({ ok: false, error: 'Please tick the consent checkbox to subscribe.' });
    }
    const meta = {
      ip:        req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip,
      userAgent: req.headers['user-agent'] || '',
      sourceUrl: req.headers['referer']    || ''
    };
    const row = await saveSubscriber(email, meta);
    notifySubscribe(email, row.id, row.consent_timestamp_utc).catch(err =>
      console.error('[notify] Subscribe error:', err.message)
    );
    return res.json({ ok: true });
  } catch (err) {
    if (err.message === 'SUPPRESSED') return res.json({ ok: true });
    console.error('[form] Subscribe error:', err.message);
    return res.status(500).json({ ok: false, error: 'Something went wrong. Please try again.' });
  }
});

app.get('/unsubscribe', async (req, res) => {
  const { email, token } = req.query;
  if (!email) return res.status(400).send(unsubscribePage('Invalid unsubscribe link.', false));
  const secret   = process.env.SESSION_SECRET || 'alpha-surfaces-secret';
  const expected = crypto.createHmac('sha256', secret).update(email.toLowerCase().trim()).digest('hex').substring(0, 16);
  if (token !== expected) return res.status(400).send(unsubscribePage('This unsubscribe link is invalid or has expired.', false));
  try {
    await unsubscribeEmail(email, 'email-link');
    return res.send(unsubscribePage('You\'ve been unsubscribed.', true, email));
  } catch (err) {
    console.error('[unsubscribe] Error:', err.message);
    return res.status(500).send(unsubscribePage('Something went wrong. Please try again.', false));
  }
});

function unsubscribePage(message, success, email = '') {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Unsubscribe — Alpha Surfaces</title>
<style>
  body { font-family:Georgia,sans-serif; background:#f3f1e6; display:flex;
         align-items:center; justify-content:center; min-height:100vh;
         margin:0; padding:24px; box-sizing:border-box; }
  .card { background:#fff; border-radius:12px; padding:48px 40px;
          max-width:480px; width:100%; text-align:center; }
  .icon { font-size:40px; margin-bottom:16px; }
  h1 { font-size:22px; color:#564D22; margin:0 0 12px; }
  p  { color:#666; font-size:15px; line-height:1.6; margin:0 0 24px; }
  a  { color:#564D22; }
</style></head>
<body><div class="card">
  <div class="icon">${success ? '✓' : '✕'}</div>
  <h1>${success ? 'Unsubscribed' : 'Something went wrong'}</h1>
  <p>${message}${success && email ? `<br><br>We've removed <strong>${email}</strong> from our mailing list.` : ''}</p>
  <p><a href="/">Return to Alpha Surfaces</a></p>
  <p style="font-size:12px;color:#999;margin-top:32px">
    Alpha Surfaces Pty Ltd · ABN 21 677 729 350<br>
    13 Enterprise Street, Kunda Park QLD 4556
  </p>
</div></body></html>`;
}

// ─── Auth Routes ───
// To generate a hash for a new password, run:
// node -e "const b = require('bcryptjs'); b.hash('yourpassword', 12).then(h => console.log(h))"
// Then set ADMIN_PASSWORD in Railway to the hash string
app.post('/api/login', loginLimiter, async (req, res) => {
  const { password } = req.body;
  const storedPassword = ADMIN_PASSWORD;

  let valid = await bcrypt.compare(password, storedPassword);
  if (!valid && !storedPassword.startsWith('$2')) {
    valid = password === storedPassword;
  }

  if (valid) {
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { created: Date.now() });
    res.cookie('alpha_session', token, { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 86400000 });
    return res.json({ ok: true });
  }
  res.status(401).json({ error: 'Wrong password' });
});

app.post('/api/logout', (req, res) => {
  const token = req.cookies?.alpha_session;
  if (token) sessions.delete(token);
  res.clearCookie('alpha_session');
  res.json({ ok: true });
});

app.get('/api/auth-check', (req, res) => {
  const token = req.cookies?.alpha_session;
  if (token && sessions.has(token)) return res.json({ authenticated: true });
  // Super_admins authenticated via the projects portal also count as CMS auth.
  const pUser = resolveProjectsUser(req);
  if (pUser && pUser.role === 'super_admin' && !pUser.must_change_password) {
    return res.json({ authenticated: true, source: 'projects' });
  }
  res.json({ authenticated: false });
});

// ─── /forms — deprecated, redirects into /projects?view=forms ───
// The standalone forms portal has been folded into the project tracker so a
// single project_users login covers everything. Old forms_session cookies +
// FORMS_PASSWORD are no longer honoured. /forms/reset email links are also
// dead — anyone with an old reset link should request a new one through the
// project tracker's forgot-password flow.
app.get('/forms', (req, res) => {
  res.redirect(301, '/projects?view=forms');
});
app.get('/forms/reset', (req, res) => {
  res.redirect(301, '/projects');
});

// ─── Projects ticket tracker (self-contained module) ───
const projectsModule = require('./projects-routes')(app, { pool, sessions, loginLimiter });
if (projectsModule && typeof projectsModule.resolveUser === 'function') {
  resolveProjectsUser = projectsModule.resolveUser;
}

cmsCore.mountCms(app, { pool, authMiddleware, dataDir: DATA_DIR });

// ─── Content API (public read, auth write) ───
app.get('/api/content', (req, res) => {
  res.json(loadContent());
});

app.put('/api/content', authMiddleware, (req, res) => {
  try {
    // Auto-snapshot current content before writing
    const current = loadContent();
    versions.createVersion('content', current, {
      source: 'cms-save',
      autoLabel: 'Manual save',
      changeCount: 0,
    });
    saveContent(req.body);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save' });
  }
});

// Partial update - merge specific section
app.patch('/api/content/:section', authMiddleware, (req, res) => {
  try {
    const content = loadContent();
    content[req.params.section] = req.body;
    saveContent(content);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save' });
  }
});

// ─── File type validation (magic bytes) ───
function validateImageType(buffer) {
  if (buffer.length < 12) return false;

  // JPEG: FF D8 FF
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) return true;

  // PNG: 89 50 4E 47
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) return true;

  // WebP: bytes 8-11 are "WEBP" (57 45 42 50)
  if (buffer[8] === 0x57 && buffer[9] === 0x45 && buffer[10] === 0x42 && buffer[11] === 0x50) return true;

  // GIF87a: 47 49 46 38 37 61
  // GIF89a: 47 49 46 38 39 61
  if (
    buffer[0] === 0x47 && buffer[1] === 0x49 && buffer[2] === 0x46 &&
    buffer[3] === 0x38 && (buffer[4] === 0x37 || buffer[4] === 0x39) && buffer[5] === 0x61
  ) return true;

  return false;
}

// ─── Railway environment variables API ───
const RAILWAY_API_URL = 'https://backboard.railway.app/graphql/v2';
const RAILWAY_PROJECT_ID = '83e36e08-4562-42ac-a39c-8111a7ceb192';
const RAILWAY_SERVICE_ID = '64c256bc-0b41-4485-9611-8624dab25425';

// Railway has two token formats:
// - Project tokens (UUID format) — auth via `Project-Access-Token` header, scoped to one environment
// - Personal account tokens (longer opaque string) — auth via `Authorization: Bearer`, account-wide
// Detect by UUID shape and route to the correct header.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function railwayAuthHeaders(token) {
  return UUID_RE.test(token)
    ? { 'Content-Type': 'application/json', 'Project-Access-Token': token }
    : { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` };
}

app.post('/api/admin/railway-vars', authMiddleware, async (req, res) => {
  const { vars } = req.body;
  if (!vars || typeof vars !== 'object') {
    return res.status(400).json({ ok: false, error: 'Invalid payload' });
  }

  // Railway sets NODE_ENV=production on BOTH envs. The reliable indicator is
  // RAILWAY_ENVIRONMENT_NAME ("staging" | "production"), set by the platform.
  const isProduction = (process.env.RAILWAY_ENVIRONMENT_NAME || '').toLowerCase() === 'production';
  const token = isProduction
    ? process.env.RAILWAY_TOKEN_PRODUCTION
    : process.env.RAILWAY_TOKEN_STAGING;

  if (!token) {
    return res.status(500).json({ ok: false, error: 'Railway token not configured' });
  }

  const headers = railwayAuthHeaders(token);

  try {
    const envRes = await fetch(RAILWAY_API_URL, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        query: `query { project(id: "${RAILWAY_PROJECT_ID}") {
          environments { edges { node { id name } } }
        }}`
      })
    });
    const envData = await envRes.json();
    if (envData.errors) {
      console.error('[railway-vars] GraphQL error:', JSON.stringify(envData.errors));
      return res.status(500).json({ ok: false, error: envData.errors[0]?.message || 'Railway API error' });
    }
    const envName = isProduction ? 'production' : 'staging';
    const envs = envData.data.project.environments.edges.map(e => e.node);
    const env = envs.find(e => e.name.toLowerCase() === envName) || envs[0];

    for (const [name, value] of Object.entries(vars)) {
      await fetch(RAILWAY_API_URL, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          query: `mutation UpsertVariable($input: VariableUpsertInput!) {
            variableUpsert(input: $input)
          }`,
          variables: {
            input: {
              projectId: RAILWAY_PROJECT_ID,
              serviceId: RAILWAY_SERVICE_ID,
              environmentId: env.id,
              name,
              value
            }
          }
        })
      });
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('[railway-vars] Error:', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ─── Forms CMS + Submissions Dashboard ───
const FORMS_PATH = path.join(DATA_DIR, 'forms.json');
// Seed forms.json on first boot — and self-heal if a prior deploy wrote an
// empty stub. The bundled defaults live at seeds/forms.json (NOT under data/)
// because Railway mounts a persistent volume on top of /app/data, which would
// shadow anything baked into the image at data/forms.json. Reading the seed
// from outside the volume mount is what makes this actually work.
// Admin edits via PUT are preserved (forms.length > 0 → skip).
{
  const FORMS_SEED = path.join(__dirname, 'seeds', 'forms.json');
  if (fs.existsSync(FORMS_SEED)) {
    let needsSeed = !fs.existsSync(FORMS_PATH);
    if (!needsSeed) {
      try {
        const cur = JSON.parse(fs.readFileSync(FORMS_PATH, 'utf8'));
        needsSeed = !cur || !Array.isArray(cur.forms) || cur.forms.length === 0;
      } catch { needsSeed = true; }
    }
    if (needsSeed) {
      try {
        fs.mkdirSync(path.dirname(FORMS_PATH), { recursive: true });
        fs.copyFileSync(FORMS_SEED, FORMS_PATH);
        console.log('[forms] Seeded', FORMS_PATH, 'from', FORMS_SEED);
      } catch (e) {
        console.error('[forms] Seed failed:', e.message);
      }
    } else {
      console.log('[forms] Skip seed — existing file has', FORMS_PATH);
    }
  } else {
    console.error('[forms] Seed source missing:', FORMS_SEED);
  }
}

// ─── Notifications settings (multi-recipient per-form, instant/daily cadence) ───
const NOTIFICATIONS_PATH = path.join(DATA_DIR, 'notifications.json');
// Same volume-shadow gotcha applies — bundled defaults must live in seeds/.
{
  const NOTIF_SEED = path.join(__dirname, 'seeds', 'notifications.json');
  if (fs.existsSync(NOTIF_SEED)) {
    let needsSeed = !fs.existsSync(NOTIFICATIONS_PATH);
    if (!needsSeed) {
      try {
        const cur = JSON.parse(fs.readFileSync(NOTIFICATIONS_PATH, 'utf8'));
        // Treat as needing seed only if structure is missing entirely; preserve admin edits.
        needsSeed = !cur || !cur.notifications || typeof cur.notifications !== 'object';
      } catch { needsSeed = true; }
    }
    if (needsSeed) {
      try {
        fs.mkdirSync(path.dirname(NOTIFICATIONS_PATH), { recursive: true });
        fs.copyFileSync(NOTIF_SEED, NOTIFICATIONS_PATH);
        console.log('[notify] Seeded', NOTIFICATIONS_PATH, 'from', NOTIF_SEED);
      } catch (e) {
        console.error('[notify] Seed failed:', e.message);
      }
    } else {
      console.log('[notify] Skip seed — existing file has', NOTIFICATIONS_PATH);
    }
  } else {
    console.error('[notify] Seed source missing:', NOTIF_SEED);
  }
}
notifications.setSettingsPath(NOTIFICATIONS_PATH);

// ─── Notifications admin API ───
app.get('/api/admin/notifications', authMiddleware, (req, res) => {
  try {
    const cfg = readNotifSettings();
    res.json(cfg || { notifications: {}, _state: {} });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// Show the admin which notification env vars are configured (presence only — no values).
app.get('/api/admin/notifications/_status', authMiddleware, (req, res) => {
  try {
    res.json({
      ok: true,
      twilio: !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN),
      smtp: !!(process.env.SMTP_USER && process.env.SMTP_PASS),
      fromNumber: process.env.TWILIO_FROM || null,
      smtpFrom: process.env.SMTP_USER || null,
      railwayToken: !!((process.env.RAILWAY_ENVIRONMENT_NAME || '').toLowerCase() === 'production'
        ? process.env.RAILWAY_TOKEN_PRODUCTION
        : process.env.RAILWAY_TOKEN_STAGING)
    });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.put('/api/admin/notifications/:formId', authMiddleware, (req, res) => {
  try {
    const cfg = readNotifSettings() || { notifications: {}, _state: {} };
    const formId = req.params.formId;
    if (!cfg.notifications[formId]) {
      return res.status(404).json({ ok: false, error: 'Unknown form ID: ' + formId });
    }
    // Accept partial update — replace the form's block, keep label.
    const incoming = req.body || {};
    const existing = cfg.notifications[formId];
    cfg.notifications[formId] = {
      label: existing.label,
      sms: {
        enabled: !!(incoming.sms && incoming.sms.enabled),
        recipients: Array.isArray(incoming.sms && incoming.sms.recipients) ? incoming.sms.recipients : []
      },
      email: {
        enabled: !!(incoming.email && incoming.email.enabled),
        recipients: Array.isArray(incoming.email && incoming.email.recipients) ? incoming.email.recipients : []
      }
    };
    writeNotifSettings(cfg);
    res.json({ ok: true, notification: cfg.notifications[formId] });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.post('/api/admin/notifications/:formId/test', authMiddleware, async (req, res) => {
  try {
    // Optional ?channel=sms|email to test only one channel.
    const channel = req.query.channel || (req.body && req.body.channel) || null;
    if (channel && channel !== 'sms' && channel !== 'email') {
      return res.status(400).json({ ok: false, error: 'channel must be sms, email, or omitted' });
    }
    const results = await sendTestForForm(req.params.formId, channel);
    res.json({ ok: true, channel: channel || 'both', results });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// Manual digest fire (admin button + smoke test). Returns send summary.
app.post('/api/admin/notifications/_digest-now', authMiddleware, async (req, res) => {
  try {
    const result = await sendDailyDigest({ pool });
    res.json(result);
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.get('/api/admin/forms', authMiddleware, (req, res) => {
  try {
    const raw  = fs.existsSync(FORMS_PATH) ? fs.readFileSync(FORMS_PATH, 'utf8') : '{"forms":[]}';
    res.json(JSON.parse(raw));
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.put('/api/admin/forms/:formId', authMiddleware, (req, res) => {
  try {
    const raw   = fs.existsSync(FORMS_PATH) ? fs.readFileSync(FORMS_PATH, 'utf8') : '{"forms":[]}';
    const data  = JSON.parse(raw);
    const index = data.forms.findIndex(f => f.id === req.params.formId);
    if (index === -1) return res.status(404).json({ ok: false, error: 'Form not found' });
    data.forms[index] = { ...data.forms[index], ...req.body };
    fs.writeFileSync(FORMS_PATH, JSON.stringify(data, null, 2));
    res.json({ ok: true, form: data.forms[index] });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// ─── Submissions dashboard ───
// Helper: build WHERE clause from query filters.
// Supports:
//   form_type      — exact match on form_submissions.form_type
//   category       — semantic category mapped to form_type + store_location:
//                    'sample'  → form_type='Sample Request'
//                    'contact' → form_type='Contact Enquiry' AND store_location IS NULL
//                    'partner' → form_type='Contact Enquiry' AND store_location IS NOT NULL
//   status         — exact match on status (e.g. 'new', 'actioned')
//   q              — case-insensitive ILIKE across name/email/phone/message
//   date_from/date_to — ISO date strings; inclusive on the day
function buildSubmissionsWhere(q) {
  const vals = [];
  const where = [];
  if (q.form_type)  { vals.push(q.form_type); where.push(`form_type = $${vals.length}`); }
  if (q.category === 'sample') {
    where.push(`form_type = 'Sample Request'`);
  } else if (q.category === 'contact') {
    where.push(`form_type = 'Contact Enquiry' AND (store_location IS NULL OR store_location = '')`);
  } else if (q.category === 'partner') {
    where.push(`form_type = 'Contact Enquiry' AND store_location IS NOT NULL AND store_location <> ''`);
  }
  if (q.status) { vals.push(q.status); where.push(`status = $${vals.length}`); }
  if (q.q) {
    vals.push('%' + q.q + '%');
    const i = vals.length;
    where.push(`(name ILIKE $${i} OR email ILIKE $${i} OR phone ILIKE $${i} OR message ILIKE $${i} OR company ILIKE $${i})`);
  }
  if (q.date_from) { vals.push(q.date_from); where.push(`submitted_at >= $${vals.length}::date`); }
  if (q.date_to)   { vals.push(q.date_to);   where.push(`submitted_at < ($${vals.length}::date + INTERVAL '1 day')`); }
  return { vals, where: where.length ? ' WHERE ' + where.join(' AND ') : '' };
}

app.get('/api/admin/submissions', authMiddleware, async (req, res) => {
  try {
    const { limit = 50, offset = 0 } = req.query;
    const { vals, where } = buildSubmissionsWhere(req.query);

    // Aggregate sample item names so the table can show stones at a glance
    // without n+1 queries. STRING_AGG keeps order by the items' insert id.
    const dataQ = `
      SELECT s.*,
             COALESCE(
               (SELECT STRING_AGG(stone_name, ', ' ORDER BY id)
                  FROM sample_request_items
                 WHERE submission_id = s.id),
               ''
             ) AS samples,
             (SELECT COUNT(*)::int FROM sample_request_items WHERE submission_id = s.id) AS sample_count
        FROM form_submissions s
        ${where}
       ORDER BY submitted_at DESC
       LIMIT $${vals.length+1} OFFSET $${vals.length+2}
    `;
    const dataVals = [...vals, parseInt(limit), parseInt(offset)];
    const { rows } = await pool.query(dataQ, dataVals);

    const { rows: cr } = await pool.query(
      `SELECT COUNT(*) FROM form_submissions${where}`, vals
    );

    // Headline counts by category — useful for nav badges.
    const { rows: counts } = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE status='new')                                                         AS new_total,
        COUNT(*) FILTER (WHERE form_type='Sample Request' AND status='new')                          AS new_sample,
        COUNT(*) FILTER (WHERE form_type='Contact Enquiry' AND (store_location IS NULL OR store_location='') AND status='new') AS new_contact,
        COUNT(*) FILTER (WHERE form_type='Contact Enquiry' AND store_location IS NOT NULL AND store_location<>'' AND status='new') AS new_partner
      FROM form_submissions
    `);

    res.json({
      ok: true,
      submissions: rows,
      total: parseInt(cr[0].count),
      counts: counts[0]
    });
  } catch (err) {
    console.error('[admin/submissions] error:', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// CSV export — must be declared BEFORE /:id so Express doesn't match
// "export" as the :id param (which then fails as a Postgres integer cast).
// Supports an `ids` query param (comma-separated) for selective download
// from the admin UI checkboxes; falls back to all rows otherwise.
app.get('/api/admin/submissions/export', authMiddleware, async (req, res) => {
  try {
    const { form_type, ids } = req.query;
    const vals = [];
    const conditions = [];

    if (ids) {
      const idList = ids.split(',').map(Number).filter(n => !isNaN(n) && n > 0);
      if (idList.length === 0) {
        return res.status(400).json({ ok: false, error: 'No valid IDs provided' });
      }
      conditions.push(`id = ANY($${vals.length + 1}::int[])`);
      vals.push(idList);
    }

    if (form_type) {
      conditions.push(`form_type = $${vals.length + 1}`);
      vals.push(form_type);
    }

    let query = 'SELECT * FROM form_submissions';
    if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');
    query += ' ORDER BY submitted_at DESC';

    const { rows } = await pool.query(query, vals);

    // Pull sample items for any Sample Request rows in the result set
    const sampleRows = rows.filter(r => r.form_type === 'Sample Request');
    const sampleMap = {};
    if (sampleRows.length) {
      const ids = sampleRows.map(r => r.id);
      const sr = await pool.query(
        `SELECT submission_id, stone_name FROM sample_request_items
          WHERE submission_id = ANY($1::int[]) ORDER BY id`, [ids]
      );
      sr.rows.forEach(it => {
        (sampleMap[it.submission_id] ||= []).push(it.stone_name);
      });
    }

    const cols = ['id','form_type','submitted_at','name','email','phone',
                  'company','role','reason',
                  'unit','street','suburb','postcode','state','store_location',
                  'stone_interest','message','source','consent','status'];

    // Discover any keys in raw_data that don't have a dedicated column,
    // so newly-added form fields surface in the CSV before a column exists.
    const skip = new Set(['name','first_name','last_name','email','phone','company',
                          'stone_interest','message','special_instructions','postcode',
                          'state','store_location','source','consent','status',
                          'i_am_a','role','type','reason','enquiry_reason',
                          'street','suburb','unit',
                          'sampleItems','samples']);
    const extraKeys = new Set();
    rows.forEach(r => {
      if (r.raw_data && typeof r.raw_data === 'object') {
        Object.keys(r.raw_data).forEach(k => {
          if (!cols.includes(k) && !skip.has(k)) extraKeys.add(k);
        });
      }
    });
    const extraCols = [...extraKeys].sort();
    const allCols = [...cols, ...extraCols, 'sample_items'];

    const escapeCSV = (v) => {
      if (v == null) return '';
      const s = v instanceof Date ? v.toISOString() : String(v);
      return (s.includes(',') || s.includes('"') || s.includes('\n'))
        ? `"${s.replace(/"/g,'""')}"` : s;
    };

    const csv = [
      allCols.join(','),
      ...rows.map(r => {
        const base = cols.map(c => escapeCSV(r[c]));
        const extra = extraCols.map(k => escapeCSV(r.raw_data?.[k]));
        const rawSamples = r.raw_data?.sampleItems || r.raw_data?.samples || [];
        const dbSamples = sampleMap[r.id] || [];
        const sampleStr = dbSamples.length
          ? dbSamples.join('; ')
          : Array.isArray(rawSamples)
            ? rawSamples.map(s => typeof s === 'object' ? (s.name || s.slug || JSON.stringify(s)) : s).join('; ')
            : '';
        return [...base, ...extra, escapeCSV(sampleStr)].join(',');
      })
    ].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="submissions-${Date.now()}.csv"`);
    res.send(csv);
  } catch (err) {
    console.error('[admin/submissions/export] error:', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Single submission with its sample items, for the detail drawer.
app.get('/api/admin/submissions/:id', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM form_submissions WHERE id = $1', [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ ok: false, error: 'Not found' });
    const submission = rows[0];

    let items = [];
    if (submission.form_type === 'Sample Request') {
      const r = await pool.query(
        'SELECT id, stone_slug, stone_name, collection FROM sample_request_items WHERE submission_id = $1 ORDER BY id',
        [submission.id]
      );
      items = r.rows;
    }

    res.json({ ok: true, submission, sampleItems: items });
  } catch (err) {
    console.error('[admin/submissions/:id] error:', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.patch('/api/admin/submissions/:id', authMiddleware, async (req, res) => {
  try {
    const allowed = ['new', 'actioned', 'archived'];
    const status = req.body.status;
    if (!allowed.includes(status)) {
      return res.status(400).json({ ok: false, error: `status must be one of ${allowed.join(', ')}` });
    }
    await pool.query('UPDATE form_submissions SET status = $1 WHERE id = $2',
      [status, req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// ─── Newsletter subscribers (separate table) ───
function buildNewsletterWhere(q) {
  const vals = [];
  const where = [];
  if (q.status) { vals.push(q.status); where.push(`status = $${vals.length}`); }
  if (q.q) {
    vals.push('%' + q.q + '%');
    where.push(`email ILIKE $${vals.length}`);
  }
  if (q.date_from) { vals.push(q.date_from); where.push(`consent_timestamp_utc >= $${vals.length}::date`); }
  if (q.date_to)   { vals.push(q.date_to);   where.push(`consent_timestamp_utc < ($${vals.length}::date + INTERVAL '1 day')`); }
  return { vals, where: where.length ? ' WHERE ' + where.join(' AND ') : '' };
}

app.get('/api/admin/newsletter', authMiddleware, async (req, res) => {
  try {
    const { limit = 50, offset = 0 } = req.query;
    const { vals, where } = buildNewsletterWhere(req.query);

    const dataQ = `
      SELECT id, email, consent_timestamp_utc, confirmed_timestamp_utc,
             ip_address, user_agent, source_url, status,
             unsubscribed_timestamp_utc, unsubscribe_method
        FROM newsletter_subscribers
        ${where}
       ORDER BY consent_timestamp_utc DESC
       LIMIT $${vals.length+1} OFFSET $${vals.length+2}
    `;
    const dataVals = [...vals, parseInt(limit), parseInt(offset)];
    const { rows } = await pool.query(dataQ, dataVals);

    const { rows: cr } = await pool.query(
      `SELECT COUNT(*) FROM newsletter_subscribers${where}`, vals
    );

    const { rows: counts } = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE status='active')        AS active,
        COUNT(*) FILTER (WHERE status='unsubscribed')  AS unsubscribed,
        COUNT(*) FILTER (WHERE status='pending')       AS pending,
        COUNT(*)                                       AS total_all
      FROM newsletter_subscribers
    `);

    res.json({
      ok: true,
      subscribers: rows,
      total: parseInt(cr[0].count),
      counts: counts[0]
    });
  } catch (err) {
    console.error('[admin/newsletter] error:', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/api/admin/newsletter/export', authMiddleware, async (req, res) => {
  try {
    const { vals, where } = buildNewsletterWhere(req.query);
    const { rows } = await pool.query(`
      SELECT id, email, consent_timestamp_utc, confirmed_timestamp_utc,
             ip_address, user_agent, source_url, status,
             unsubscribed_timestamp_utc, unsubscribe_method
        FROM newsletter_subscribers
        ${where}
       ORDER BY consent_timestamp_utc DESC
    `, vals);
    const cols = ['id','email','consent_timestamp_utc','confirmed_timestamp_utc',
                  'ip_address','source_url','status',
                  'unsubscribed_timestamp_utc','unsubscribe_method'];
    const escape = v => {
      if (v == null) return '';
      const s = v instanceof Date ? v.toISOString() : String(v);
      return s.includes(',') || s.includes('"') || s.includes('\n')
        ? `"${s.replace(/"/g,'""')}"` : s;
    };
    const csv = [
      cols.join(','),
      ...rows.map(r => cols.map(c => escape(r[c])).join(','))
    ].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="newsletter-${Date.now()}.csv"`);
    res.send(csv);
  } catch (err) {
    console.error('[admin/newsletter/export] error:', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.patch('/api/admin/newsletter/:id', authMiddleware, async (req, res) => {
  try {
    const allowed = ['active', 'unsubscribed', 'pending'];
    const status = req.body.status;
    if (!allowed.includes(status)) {
      return res.status(400).json({ ok: false, error: `status must be one of ${allowed.join(', ')}` });
    }
    if (status === 'unsubscribed') {
      await pool.query(
        `UPDATE newsletter_subscribers
            SET status='unsubscribed',
                unsubscribed_timestamp_utc=NOW(),
                unsubscribe_method='admin'
          WHERE id=$1`, [req.params.id]
      );
    } else {
      await pool.query(
        'UPDATE newsletter_subscribers SET status=$1 WHERE id=$2',
        [status, req.params.id]
      );
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// ─── Upload route ───
app.post('/api/upload', authMiddleware, upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file provided.' });
  }

  if (!validateImageType(req.file.buffer)) {
    return res.status(400).json({ error: 'Invalid file type. Only JPEG, PNG, WebP and GIF images are allowed.' });
  }

  const b64 = req.file.buffer.toString('base64');
  const dataUri = `data:${req.file.mimetype};base64,${b64}`;

  cloudinary.uploader.upload(dataUri, { folder: 'alpha-surfaces' }, (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Upload failed.' });
    }
    res.json({ url: result.secure_url });
  });
});

// ─── AI CMS Routes ───

const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Too many AI requests. Please slow down.' },
});

// Video generation jobs (in-memory)
const videoJobs = new Map();

// Build the system prompt used by all LLM providers
function buildSystemPrompt(currentContent) {
  return `You are the AI content editor for Alpha Surfaces, a premium Australian benchtop brand. You have full knowledge of and control over the website's content via a JSON content store.

Alpha Surfaces brand context:
- Premium mineral stone benchtops with zero crystalline silica (silicosis-safe)
- AlphaShield™ Lifetime Stain Resistance Guarantee
- 30+ surfaces across 5 collections (01–05) plus Original Alpha Zero
- Jumbo slabs: 3200 × 1600mm, 20mm thickness
- Target markets: fabricators, architects, designers, builders, homeowners
- Managing Director: Belinda Kelaher
- Tone: Luxury editorial — confident, precise, premium without being cold

Brand voice guidelines:
- Avoid generic superlatives ("world-class", "leading", "best-in-class")
- Prefer sensory and material language ("tactile", "weight", "grain", "depth")
- Short declarative sentences work better than long compound ones for headlines
- Australian English spelling throughout (e.g. "colour" not "color")
- HTML <em> tags may be used in headings for italic emphasis — preserve this pattern

The current website content.json is below. This is the live content of the site:

<content>
${JSON.stringify(currentContent, null, 2)}
</content>

When the user asks you to make changes to the site:
1. Make the changes thoughtfully, in the brand voice described above
2. Return your conversational reply AND the proposed content changes in this exact format at the end of your response:

<proposed_changes>
{ ...only the changed fields as a deep partial object... }
</proposed_changes>

The proposed_changes object must use the exact same key structure as content.json. Only include keys that have actually changed — do not return the entire content object in proposed_changes, only the changed portions.

Examples:
- If you changed hero.heading: { "hero": { "heading": "new value" } }
- If you changed two collections: { "collections": { "items": [null, { "name": "new name" }, null] } } — use null for unchanged array items
- If you changed a colour: { "styles": { "olive": "#6B6820" } }

If the user is asking a question and no changes are needed, reply helpfully and omit the <proposed_changes> block entirely.

If the user asks you to do something outside your capabilities (e.g. upload images, change passwords, deploy code), explain what you can and can't do, and suggest alternatives where possible.`;
}

// ─── Deep Merge & Diff Utilities ───

// Deep merge a partial object into the original, producing a full updated object.
// For arrays, null entries in partial mean "keep the original item at this index".
function deepMergeContent(original, partial) {
  const result = JSON.parse(JSON.stringify(original));

  function mergeInto(target, source) {
    if (Array.isArray(source)) {
      if (!Array.isArray(target)) return source;
      for (let i = 0; i < source.length; i++) {
        if (source[i] === null) continue;
        if (i >= target.length) {
          target[i] = source[i];
        } else if (typeof source[i] === 'object' && source[i] !== null && typeof target[i] === 'object' && target[i] !== null) {
          target[i] = mergeInto(target[i], source[i]);
        } else {
          target[i] = source[i];
        }
      }
      return target;
    }

    if (typeof source === 'object' && source !== null) {
      if (typeof target !== 'object' || target === null || Array.isArray(target)) {
        return source;
      }
      for (const key of Object.keys(source)) {
        if (typeof source[key] === 'object' && source[key] !== null && typeof target[key] === 'object' && target[key] !== null) {
          target[key] = mergeInto(target[key], source[key]);
        } else {
          target[key] = source[key];
        }
      }
      return target;
    }

    return source;
  }

  mergeInto(result, partial);
  return result;
}

// Recursively compare two objects, returning an array of {path, before, after} for changed leaf values.
// Skips image objects (those containing url/publicId/thumb/medium/large keys).
function computeDiff(original, proposed) {
  const diffs = [];

  function isImageObj(obj) {
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return false;
    const keys = Object.keys(obj);
    return keys.some(k => ['url', 'publicId', 'thumb', 'medium', 'large'].includes(k));
  }

  function walk(a, b, currentPath) {
    if (a === b) return;

    const aIsObj = a !== null && a !== undefined && typeof a === 'object';
    const bIsObj = b !== null && b !== undefined && typeof b === 'object';

    if (aIsObj && bIsObj && !Array.isArray(a) && !Array.isArray(b)) {
      if (isImageObj(a) || isImageObj(b)) return;
      const allKeys = new Set([...Object.keys(a), ...Object.keys(b)]);
      for (const key of allKeys) {
        walk(a[key], b[key], currentPath ? `${currentPath}.${key}` : key);
      }
      return;
    }

    if (Array.isArray(a) && Array.isArray(b)) {
      const maxLen = Math.max(a.length, b.length);
      for (let i = 0; i < maxLen; i++) {
        walk(a[i], b[i], `${currentPath}[${i}]`);
      }
      return;
    }

    // Leaf comparison
    const aStr = a != null ? String(a) : '';
    const bStr = b != null ? String(b) : '';
    if (aStr !== bStr) {
      diffs.push({ path: currentPath, before: aStr, after: bStr });
    }
  }

  walk(original, proposed, '');
  return diffs;
}

// ─── LLM Provider Functions ───

async function callAnthropic(model, messages, attachments, systemPrompt) {
  const client = new Anthropic({ apiKey: KEYS.anthropic });
  const anthropicMessages = messages.map((msg, idx) => {
    const content = [];
    if (msg.role === 'user' && idx === messages.length - 1 && attachments && attachments.length > 0) {
      for (const att of attachments) {
        if (att.type === 'image' && att.base64 && att.mimeType) {
          content.push({
            type: 'image',
            source: { type: 'base64', media_type: att.mimeType, data: att.base64 },
          });
        } else if (att.type === 'document' && att.base64 && att.mimeType) {
          content.push({
            type: 'document',
            source: { type: 'base64', media_type: att.mimeType, data: att.base64 },
          });
        }
      }
    }
    content.push({ type: 'text', text: msg.content });
    return { role: msg.role, content };
  });

  const response = await client.messages.create({
    model: model || 'claude-sonnet-4-20250514',
    max_tokens: 4096,
    system: systemPrompt,
    messages: anthropicMessages,
  });

  const rawText = response.content.filter(b => b.type === 'text').map(b => b.text).join('');
  const usage = response.usage;
  const tokens = (usage?.input_tokens || 0) + (usage?.output_tokens || 0);
  return { rawText, tokens };
}

async function callOpenAI(model, messages, attachments, systemPrompt, baseURL, apiKey) {
  const client = new OpenAI({
    apiKey: apiKey || KEYS.openai,
    ...(baseURL ? { baseURL } : {}),
  });

  const openaiMessages = [{ role: 'system', content: systemPrompt }];
  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    if (msg.role === 'user' && i === messages.length - 1 && attachments && attachments.length > 0) {
      const contentParts = [];
      for (const att of attachments) {
        if (att.type === 'image' && att.base64 && att.mimeType) {
          contentParts.push({
            type: 'image_url',
            image_url: { url: `data:${att.mimeType};base64,${att.base64}` },
          });
        }
      }
      contentParts.push({ type: 'text', text: msg.content });
      openaiMessages.push({ role: 'user', content: contentParts });
    } else {
      openaiMessages.push({ role: msg.role, content: msg.content });
    }
  }

  const response = await client.chat.completions.create({
    model: model,
    max_tokens: 4096,
    messages: openaiMessages,
  });

  const rawText = response.choices[0]?.message?.content || '';
  const usage = response.usage;
  const tokens = (usage?.prompt_tokens || 0) + (usage?.completion_tokens || 0);
  return { rawText, tokens };
}

async function callGemini(model, messages, attachments, systemPrompt) {
  const genAI = new GoogleGenerativeAI(KEYS.google);
  const geminiModel = genAI.getGenerativeModel({ model: model || 'gemini-1.5-pro' });

  const history = [];
  for (let i = 0; i < messages.length - 1; i++) {
    const msg = messages[i];
    history.push({
      role: msg.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: msg.content }],
    });
  }

  const chat = geminiModel.startChat({
    history,
    systemInstruction: { parts: [{ text: systemPrompt }] },
  });

  const lastMsg = messages[messages.length - 1];
  const parts = [];

  if (lastMsg.role === 'user' && attachments && attachments.length > 0) {
    for (const att of attachments) {
      if (att.type === 'image' && att.base64 && att.mimeType) {
        parts.push({ inlineData: { mimeType: att.mimeType, data: att.base64 } });
      }
    }
  }
  parts.push({ text: lastMsg.content });

  const result = await chat.sendMessage(parts);
  const response = result.response;
  const rawText = response.text();
  const usage = response.usageMetadata;
  const tokens = (usage?.promptTokenCount || 0) + (usage?.candidatesTokenCount || 0);
  return { rawText, tokens };
}

async function callGrok(model, messages, attachments, systemPrompt) {
  return callOpenAI(
    model || 'grok-2',
    messages,
    attachments,
    systemPrompt,
    'https://api.x.ai/v1',
    KEYS.xai
  );
}

async function routeToLLM(model, messages, attachments, currentContent) {
  const systemPrompt = buildSystemPrompt(currentContent);
  if (model.startsWith('claude')) return callAnthropic(model, messages, attachments, systemPrompt);
  if (model.startsWith('gpt'))    return callOpenAI(model, messages, attachments, systemPrompt);
  if (model.startsWith('gemini')) return callGemini(model, messages, attachments, systemPrompt);
  if (model.startsWith('grok'))   return callGrok(model, messages, attachments, systemPrompt);
  throw new Error(`Unknown model: ${model}`);
}

// POST /api/ai/chat — Core NL CMS endpoint (multi-LLM)
app.post('/api/ai/chat', authMiddleware, aiLimiter, async (req, res) => {
  try {
    const { messages, attachments, model: requestedModel } = req.body;
    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ ok: false, message: 'Messages array is required.' });
    }

    const model = requestedModel || 'claude-sonnet-4-20250514';

    // Validate the provider has an API key
    if (model.startsWith('claude') && !KEYS.anthropic) {
      return res.status(503).json({ ok: false, message: 'Claude API key not configured. Add it in API Keys → Claude.' });
    }
    if (model.startsWith('gpt') && !KEYS.openai) {
      return res.status(503).json({ ok: false, message: 'OpenAI API key not configured. Add it in API Keys → GPT-4o.' });
    }
    if (model.startsWith('gemini') && !KEYS.google) {
      return res.status(503).json({ ok: false, message: 'Google AI API key not configured. Add it in API Keys → Gemini.' });
    }
    if (model.startsWith('grok') && !KEYS.xai) {
      return res.status(503).json({ ok: false, message: 'xAI API key not configured. Add it in API Keys → Grok.' });
    }

    // Always read fresh content from disk
    const currentContent = loadContent();
    const { rawText, tokens } = await routeToLLM(model, messages, attachments, currentContent);

    // Parse response: extract reply text and <proposed_changes> block
    const changesMatch = rawText.match(/<proposed_changes>\s*([\s\S]*?)\s*<\/proposed_changes>/);

    let reply = rawText;
    let proposedChanges = null;

    if (changesMatch) {
      reply = rawText.substring(0, rawText.indexOf('<proposed_changes>')).trim();
      try {
        proposedChanges = JSON.parse(changesMatch[1]);
      } catch (e) {
        // JSON parsing failed — treat as no changes
        proposedChanges = null;
      }
    }

    if (!proposedChanges) {
      return res.json({
        ok: true,
        reply,
        diff: [],
        proposedContent: null,
        hasChanges: false,
        model,
        tokens
      });
    }

    // Deep merge proposed changes with current content
    const proposedContent = deepMergeContent(currentContent, proposedChanges);

    // Compute diff array
    const diff = computeDiff(currentContent, proposedContent);

    res.json({
      ok: true,
      reply,
      diff,
      proposedContent,
      hasChanges: diff.length > 0,
      model,
      tokens
    });
  } catch (err) {
    console.error('AI chat error:', err);
    const message = err?.status === 401
      ? 'Invalid API key. Check your key in API Keys settings.'
      : err?.status === 429
      ? 'Rate limit exceeded. Please wait a moment and try again.'
      : err?.message || 'AI request failed. Please try again.';
    res.status(500).json({ ok: false, message });
  }
});

// POST /api/ai/apply — Apply proposed content changes
app.post('/api/ai/apply', authMiddleware, async (req, res) => {
  try {
    const { proposedContent } = req.body;
    if (!proposedContent) {
      return res.status(400).json({ error: 'proposedContent is required.' });
    }
    // Snapshot current content via version history
    const current = loadContent();
    const diff = computeDiff(current, proposedContent);
    versions.createVersion('content', current, {
      source: 'nl-cms',
      autoLabel: versions.generateAutoLabel(diff),
      changeCount: diff.length,
    });
    // Write new content
    saveContent(proposedContent);
    res.json({ ok: true, message: 'Changes applied. Version saved.' });
  } catch (err) {
    console.error('AI apply error:', err);
    res.status(500).json({ error: 'Failed to apply changes.' });
  }
});

// /api/ai/undo removed — replaced by multi-level version history (see /api/versions/*)

// GET /api/ai/status — Provider availability & model capability data
app.get('/api/ai/status', (req, res) => {
  res.json({
    anthropic: !!KEYS.anthropic,
    openai: !!KEYS.openai,
    google: !!KEYS.google,
    xai: !!KEYS.xai,
    runway: !!KEYS.runway,
    models: {
      'claude-sonnet-4-20250514': {
        available: !!KEYS.anthropic,
        label: 'Claude Sonnet',
        capabilities: ['text', 'vision', 'content-edit'],
      },
      'gpt-4o': {
        available: !!KEYS.openai,
        label: 'GPT-4o',
        capabilities: ['text', 'vision', 'content-edit', 'image-gen'],
      },
      'gemini-1.5-pro': {
        available: !!KEYS.google,
        label: 'Gemini 1.5 Pro',
        capabilities: ['text', 'vision', 'content-edit', 'large-context'],
      },
      'grok-2': {
        available: !!KEYS.xai,
        label: 'Grok',
        capabilities: ['text', 'content-edit', 'image-gen', 'web-search'],
      },
    },
  });
});

// ─── Image Generation ───

// Helper: upload a buffer to Cloudinary
function uploadBufferToCloudinary(buffer, options = {}) {
  return new Promise((resolve, reject) => {
    const uploadOptions = {
      folder: 'alpha-surfaces',
      ...options,
    };
    const stream = cloudinary.uploader.upload_stream(uploadOptions, (err, result) => {
      if (err) return reject(err);
      resolve(result);
    });
    stream.end(buffer);
  });
}

// POST /api/ai/generate-image
app.post('/api/ai/generate-image', authMiddleware, aiLimiter, async (req, res) => {
  const { prompt, provider, size, targetField } = req.body;
  if (!prompt) return res.status(400).json({ error: 'Prompt is required.' });

  const selectedProvider = provider || 'dalle3';

  try {
    let imageBuffer;

    if (selectedProvider === 'dalle3') {
      if (!KEYS.openai) {
        return res.status(503).json({ error: 'OpenAI API key not configured.' });
      }
      const client = new OpenAI({ apiKey: KEYS.openai });
      const imageSize = size || '1792x1024';
      const response = await client.images.generate({
        model: 'dall-e-3',
        prompt,
        n: 1,
        size: imageSize,
        response_format: 'b64_json',
      });
      const b64 = response.data[0].b64_json;
      imageBuffer = Buffer.from(b64, 'base64');

    } else if (selectedProvider === 'imagen3') {
      if (!KEYS.google) {
        return res.status(503).json({ error: 'Google AI API key not configured.' });
      }
      const genAI = new GoogleGenerativeAI(KEYS.google);
      const model = genAI.getGenerativeModel({ model: 'imagen-3.0-generate-002' });
      const result = await model.generateImages({
        prompt,
        config: { numberOfImages: 1 },
      });
      const imgBytes = result.images[0].imageBytes;
      imageBuffer = Buffer.from(imgBytes, 'base64');

    } else if (selectedProvider === 'grok-aurora') {
      if (!KEYS.xai) {
        return res.status(503).json({ error: 'xAI API key not configured.' });
      }
      const client = new OpenAI({
        apiKey: KEYS.xai,
        baseURL: 'https://api.x.ai/v1',
      });
      const response = await client.images.generate({
        model: 'grok-2-image',
        prompt,
        n: 1,
        response_format: 'b64_json',
      });
      const b64 = response.data[0].b64_json;
      imageBuffer = Buffer.from(b64, 'base64');

    } else {
      return res.status(400).json({ error: `Unknown image provider: ${selectedProvider}` });
    }

    // Upload to Cloudinary
    const result = await uploadBufferToCloudinary(imageBuffer, {
      public_id: `ai-gen-${Date.now()}`,
      resource_type: 'image',
    });

    res.json({
      ok: true,
      url: result.secure_url,
      publicId: result.public_id,
      thumb: cloudinary.url(result.public_id, { width: 200, crop: 'fill', fetch_format: 'auto' }),
      medium: cloudinary.url(result.public_id, { width: 800, crop: 'limit', fetch_format: 'auto' }),
      large: cloudinary.url(result.public_id, { width: 1920, crop: 'limit', fetch_format: 'auto' }),
      targetField: targetField || null,
      prompt,
    });
  } catch (err) {
    console.error('Image generation error:', err);
    const message = err?.message || 'Image generation failed.';
    res.status(500).json({ error: message });
  }
});

// ─── Video Generation ───

// POST /api/ai/generate-video — Start async video job
app.post('/api/ai/generate-video', authMiddleware, async (req, res) => {
  const { prompt, provider, duration, targetField } = req.body;
  if (!prompt) return res.status(400).json({ error: 'Prompt is required.' });

  if ((provider || 'runway') !== 'runway') {
    return res.status(400).json({ error: `Unsupported video provider: ${provider}` });
  }
  if (!KEYS.runway) {
    return res.status(503).json({ error: 'Runway API key not configured.' });
  }

  const jobId = 'vid-' + crypto.randomBytes(8).toString('hex');
  videoJobs.set(jobId, { status: 'processing', prompt, targetField, provider: 'runway', createdAt: Date.now() });

  // Run async
  (async () => {
    try {
      // Start generation
      const startRes = await fetch('https://api.dev.runwayml.com/v1/text_to_video', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${KEYS.runway}`,
          'Content-Type': 'application/json',
          'X-Runway-Version': '2024-11-06',
        },
        body: JSON.stringify({
          model: 'gen4_turbo',
          text_prompt: prompt,
          duration: duration || 5,
          ratio: '1280:720',
        }),
      });

      if (!startRes.ok) {
        const errBody = await startRes.text();
        throw new Error(`Runway API error: ${startRes.status} — ${errBody}`);
      }

      const startData = await startRes.json();
      const taskId = startData.id;

      // Poll for completion
      let attempts = 0;
      const maxAttempts = 60; // 5 minutes max (5s intervals)
      while (attempts < maxAttempts) {
        await new Promise(r => setTimeout(r, 5000));
        attempts++;

        const pollRes = await fetch(`https://api.dev.runwayml.com/v1/tasks/${taskId}`, {
          headers: {
            'Authorization': `Bearer ${KEYS.runway}`,
            'X-Runway-Version': '2024-11-06',
          },
        });

        if (!pollRes.ok) continue;
        const pollData = await pollRes.json();

        if (pollData.status === 'SUCCEEDED') {
          const videoUrl = pollData.output?.[0];
          if (!videoUrl) throw new Error('No video URL in Runway response');

          // Download the video
          const videoRes = await fetch(videoUrl);
          const videoBuffer = Buffer.from(await videoRes.arrayBuffer());

          // Upload to Cloudinary as video
          const cloudResult = await uploadBufferToCloudinary(videoBuffer, {
            public_id: `ai-video-${Date.now()}`,
            resource_type: 'video',
          });

          videoJobs.set(jobId, {
            status: 'complete',
            prompt,
            targetField,
            provider: 'runway',
            result: {
              url: cloudResult.secure_url,
              publicId: cloudResult.public_id,
              thumb: cloudResult.secure_url.replace(/\.[^.]+$/, '.jpg'),
              targetField,
              prompt,
            },
          });
          return;
        } else if (pollData.status === 'FAILED') {
          throw new Error(pollData.error || 'Runway generation failed');
        }
        // else still processing, continue polling
      }
      throw new Error('Video generation timed out');
    } catch (err) {
      console.error('Video generation error:', err);
      videoJobs.set(jobId, { status: 'failed', error: err.message, prompt, targetField, provider: 'runway' });
    }
  })();

  res.json({ jobId });
});

// GET /api/ai/video-status/:jobId — Poll video job status
app.get('/api/ai/video-status/:jobId', authMiddleware, (req, res) => {
  const job = videoJobs.get(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'Job not found.' });
  res.json(job);
});

// Helpers for nested value access with bracket notation support (e.g. "collections.items[0].name")
function getNestedValue(obj, path) {
  const keys = parsePath(path);
  let current = obj;
  for (const key of keys) {
    if (current == null) return undefined;
    current = current[key];
  }
  return current;
}

function setNestedValue(obj, path, value) {
  const keys = parsePath(path);
  let current = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i];
    if (current[key] == null) {
      current[key] = typeof keys[i + 1] === 'number' ? [] : {};
    }
    current = current[key];
  }
  current[keys[keys.length - 1]] = value;
}

function parsePath(path) {
  const keys = [];
  const parts = path.split('.');
  for (const part of parts) {
    const match = part.match(/^([^[]+)(?:\[(\d+)\])?$/);
    if (match) {
      keys.push(match[1]);
      if (match[2] !== undefined) keys.push(parseInt(match[2], 10));
    } else {
      keys.push(part);
    }
  }
  return keys;
}

// ─── API Keys Management Routes ───

// GET /api/keys — Return key status (masked values only)
app.get('/api/keys', authMiddleware, (req, res) => {
  const result = {};
  for (const k of KEY_NAMES) {
    const value = KEYS[k];
    result[k] = {
      set: !!value,
      masked: maskKey(value),
      source: value ? getKeySource(k) : null,
    };
  }
  res.json(result);
});

// PUT /api/keys — Save one or more keys
app.put('/api/keys', authMiddleware, (req, res) => {
  const updated = [];
  const cloudinaryChanged = false;
  let reloadCloudinary = false;

  for (const [key, value] of Object.entries(req.body)) {
    if (!KEY_NAMES.includes(key)) continue;

    const trimmed = String(value).trim();

    // Skip if value is only bullet characters (masked value submitted accidentally)
    if (/^[•]+$/.test(trimmed)) continue;

    // Update keys.json data
    keysFromFile[key] = trimmed;
    updated.push(key);

    if (key.startsWith('cloudinary_')) reloadCloudinary = true;
  }

  if (updated.length > 0) {
    saveKeys();
    loadKeys();
    if (reloadCloudinary) configureCloudinary();
  }

  res.json({ ok: true, updated });
});

// POST /api/keys/test/:provider — Test a provider connection
app.post('/api/keys/test/:provider', authMiddleware, async (req, res) => {
  const { provider } = req.params;
  const start = Date.now();

  try {
    if (provider === 'anthropic') {
      if (!KEYS.anthropic) return res.json({ ok: false, provider, message: 'No API key configured' });
      const resp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': KEYS.anthropic,
          'anthropic-version': '2023-06-01',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'claude-haiku-4-5-20251001',
          max_tokens: 1,
          messages: [{ role: 'user', content: 'hi' }],
        }),
      });
      if (!resp.ok) {
        const body = await resp.text();
        throw new Error(resp.status === 401 ? 'Invalid API key — check and try again' : `API error ${resp.status}`);
      }
      return res.json({ ok: true, provider, latencyMs: Date.now() - start, message: 'Connected' });

    } else if (provider === 'openai') {
      if (!KEYS.openai) return res.json({ ok: false, provider, message: 'No API key configured' });
      const resp = await fetch('https://api.openai.com/v1/models', {
        headers: { 'Authorization': `Bearer ${KEYS.openai}` },
      });
      if (!resp.ok) throw new Error(resp.status === 401 ? 'Invalid API key — check and try again' : `API error ${resp.status}`);
      return res.json({ ok: true, provider, latencyMs: Date.now() - start, message: 'Connected' });

    } else if (provider === 'google') {
      if (!KEYS.google) return res.json({ ok: false, provider, message: 'No API key configured' });
      const resp = await fetch(`https://generativelanguage.googleapis.com/v1/models?key=${encodeURIComponent(KEYS.google)}`);
      if (!resp.ok) throw new Error(resp.status === 400 || resp.status === 403 ? 'Invalid API key — check and try again' : `API error ${resp.status}`);
      return res.json({ ok: true, provider, latencyMs: Date.now() - start, message: 'Connected' });

    } else if (provider === 'xai') {
      if (!KEYS.xai) return res.json({ ok: false, provider, message: 'No API key configured' });
      const resp = await fetch('https://api.x.ai/v1/models', {
        headers: { 'Authorization': `Bearer ${KEYS.xai}` },
      });
      if (!resp.ok) throw new Error(resp.status === 401 ? 'Invalid API key — check and try again' : `API error ${resp.status}`);
      return res.json({ ok: true, provider, latencyMs: Date.now() - start, message: 'Connected' });

    } else if (provider === 'runway') {
      if (!KEYS.runway) return res.json({ ok: false, provider, message: 'No API key configured' });
      const resp = await fetch('https://api.dev.runwayml.com/v1/organizations', {
        headers: {
          'Authorization': `Bearer ${KEYS.runway}`,
          'X-Runway-Version': '2024-11-06',
        },
      });
      // 200 or 401 both count as reachable
      if (resp.status === 200 || resp.status === 401) {
        return res.json({ ok: true, provider, latencyMs: Date.now() - start, message: 'Connected' });
      }
      throw new Error(`API error ${resp.status}`);

    } else if (provider === 'cloudinary') {
      if (!KEYS.cloudinary_cloud_name || !KEYS.cloudinary_api_key || !KEYS.cloudinary_api_secret) {
        return res.json({ ok: false, provider, message: 'Cloudinary credentials not fully configured' });
      }
      await cloudinary.api.ping();
      return res.json({ ok: true, provider, latencyMs: Date.now() - start, message: 'Connected' });

    } else {
      return res.status(400).json({ ok: false, provider, message: `Unknown provider: ${provider}` });
    }
  } catch (err) {
    return res.json({ ok: false, provider, message: err.message || 'Connection failed' });
  }
});

// DELETE /api/keys/:keyName — Clear a single key
app.delete('/api/keys/:keyName', authMiddleware, (req, res) => {
  const { keyName } = req.params;
  if (!KEY_NAMES.includes(keyName)) {
    return res.status(400).json({ error: `Unknown key: ${keyName}` });
  }
  keysFromFile[keyName] = '';
  saveKeys();
  loadKeys();
  if (keyName.startsWith('cloudinary_')) configureCloudinary();
  res.json({ ok: true, cleared: keyName });
});

// ─── Version History API Routes ───

// GET /api/versions/:page — List versions
app.get('/api/versions/:page', authMiddleware, (req, res) => {
  try {
    const pageKey = req.params.page;
    const versionList = versions.getIndex(pageKey);
    res.json({ ok: true, page: pageKey, versions: versionList.slice(0, MAX_VERSIONS) });
  } catch (err) {
    console.error('Version list error:', err);
    res.status(500).json({ ok: false, message: 'Failed to load versions.' });
  }
});

// GET /api/versions/:page/:id/snapshot — Get full snapshot
app.get('/api/versions/:page/:id/snapshot', authMiddleware, (req, res) => {
  try {
    const { page, id } = req.params;
    const snapshot = versions.getSnapshot(page, id);
    if (snapshot === null) {
      return res.status(404).json({ ok: false, message: 'Snapshot not found.' });
    }
    if (page === 'content') {
      res.json(snapshot);
    } else {
      res.type('text/html').send(snapshot);
    }
  } catch (err) {
    console.error('Snapshot error:', err);
    res.status(500).json({ ok: false, message: 'Failed to load snapshot.' });
  }
});

// GET /api/versions/:page/:id/diff — Diff vs current live
app.get('/api/versions/:page/:id/diff', authMiddleware, (req, res) => {
  try {
    const { page, id } = req.params;
    let currentLive;
    if (page === 'content') {
      currentLive = loadContent();
    } else {
      const htmlPath = path.join(__dirname, 'public', page + '.html');
      if (!fs.existsSync(htmlPath)) {
        return res.status(404).json({ ok: false, message: 'Live page not found.' });
      }
      currentLive = fs.readFileSync(htmlPath, 'utf8');
    }
    const result = versions.getDiff(page, id, currentLive);
    if (!result) {
      return res.status(404).json({ ok: false, message: 'Snapshot not found.' });
    }
    res.json(result);
  } catch (err) {
    console.error('Diff error:', err);
    res.status(500).json({ ok: false, message: 'Failed to compute diff.' });
  }
});

// POST /api/versions/:page/checkpoint — Create manual checkpoint
app.post('/api/versions/:page/checkpoint', authMiddleware, (req, res) => {
  try {
    const pageKey = req.params.page;
    const label = req.body.label || null;
    let currentLive;
    if (pageKey === 'content') {
      currentLive = loadContent();
    } else {
      const htmlPath = path.join(__dirname, 'public', pageKey + '.html');
      if (!fs.existsSync(htmlPath)) {
        return res.status(404).json({ ok: false, message: 'Page not found.' });
      }
      currentLive = fs.readFileSync(htmlPath, 'utf8');
    }
    const version = versions.createCheckpoint(pageKey, currentLive, label);
    res.json({ ok: true, version });
  } catch (err) {
    console.error('Checkpoint error:', err);
    res.status(500).json({ ok: false, message: 'Failed to create checkpoint.' });
  }
});

// PUT /api/versions/:page/:id/label — Rename a version
app.put('/api/versions/:page/:id/label', authMiddleware, (req, res) => {
  try {
    const { page, id } = req.params;
    let label = req.body.label;
    if (label !== null && label !== undefined) {
      label = String(label).trim();
      if (label === '') label = null;
    }
    const updated = versions.renameVersion(page, id, label);
    if (!updated) {
      return res.status(404).json({ ok: false, message: 'Version not found.' });
    }
    res.json({ ok: true, version: updated });
  } catch (err) {
    console.error('Label error:', err);
    res.status(500).json({ ok: false, message: 'Failed to update label.' });
  }
});

// DELETE /api/versions/:page/:id — Delete a version
app.delete('/api/versions/:page/:id', authMiddleware, (req, res) => {
  try {
    const { page, id } = req.params;
    const result = versions.deleteVersion(page, id);
    res.json(result);
  } catch (err) {
    console.error('Delete version error:', err);
    res.status(500).json({ ok: false, message: 'Failed to delete version.' });
  }
});

// PUT /api/versions/:page/:id/protect — Toggle protected status
app.put('/api/versions/:page/:id/protect', authMiddleware, (req, res) => {
  try {
    const { page, id } = req.params;
    const protectedVal = !!req.body.protected;
    const updated = versions.toggleProtect(page, id, protectedVal);
    if (!updated) {
      return res.status(404).json({ ok: false, message: 'Version not found.' });
    }
    res.json({ ok: true, version: updated });
  } catch (err) {
    console.error('Protect error:', err);
    res.status(500).json({ ok: false, message: 'Failed to update protection.' });
  }
});

// POST /api/versions/:page/:id/restore — Restore a version
app.post('/api/versions/:page/:id/restore', authMiddleware, (req, res) => {
  try {
    const { page, id } = req.params;
    let currentLive;
    let writeLiveFile;

    if (page === 'content') {
      currentLive = loadContent();
      writeLiveFile = (snapshot) => {
        saveContent(snapshot);
      };
    } else {
      const htmlPath = path.join(__dirname, 'public', page + '.html');
      if (!fs.existsSync(htmlPath)) {
        return res.status(404).json({ ok: false, message: 'Page not found.' });
      }
      currentLive = fs.readFileSync(htmlPath, 'utf8');
      writeLiveFile = (snapshot) => {
        fs.writeFileSync(htmlPath, snapshot);
      };
    }

    const result = versions.restoreVersion(page, id, currentLive, writeLiveFile);

    // If restoring content, reload in-memory DATA
    if (page === 'content' && result.ok) {
      // Content is already written to disk by writeLiveFile
    }

    res.json(result);
  } catch (err) {
    console.error('Restore error:', err);
    res.status(500).json({ ok: false, message: 'Failed to restore version.' });
  }
});

// Expose MAX_VERSIONS for the version list route
const MAX_VERSIONS = 50;

// ─── Admin route ───
app.get('/admin', (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'admin.html'));
});

// ─── Kitchen Connection landing page ───
app.get('/kc', (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'kc.html'));
});

// ─── Collections page ───
app.get('/collections', (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'collections.html'));
});

// TODO: Instagram API endpoint
// When Belinda provides Instagram credentials, add a /api/instagram route here
// that fetches the latest 4 posts from the Instagram Graph API and returns
// { posts: [{ imageUrl, permalink, caption }] }
// Then update public/collections.html to fetch from this endpoint on page load
// and replace the .instagram-placeholder tiles with live content.
// Instagram handle: @alpha.surfaces (unconfirmed — verify with Belinda)
// Facebook URL: https://facebook.com/alphasurfaces (unconfirmed — verify with Belinda)

// ─── Preview route — shareable URL for Belinda and Jay to review ───
app.get('/preview', (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'index.html'));
});

// ─── Document pages (clean URLs) ───
app.get('/care-and-maintenance', (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'care-and-maintenance.html'));
});
app.get('/fabrication-guide', (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'fabrication-guide.html'));
});
app.get('/warranty', (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'warranty.html'));
});
app.get('/warranty-terms', (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'warranty-terms.html'));
});
app.get('/enquiry', (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'enquiry.html'));
});

app.get('/brochure', (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'brochure.html'));
});

// Standalone iPad-kiosk check-in for showroom walk-ins. No nav, no chrome.
app.get('/showroom-checkin', (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'showroom-checkin.html'));
});

// Legacy WordPress URLs Jess may still have bookmarked on the iPad.
app.get(['/showroom-enquiry-2026', '/showroom-enquiry-2026/'], (req, res) =>
  res.redirect(301, '/showroom-checkin'));
app.get(['/wp-admin', '/wp-admin/'], (req, res) =>
  res.redirect(301, '/projects'));

// ─── Digital catalog (flipbook viewer) ───
// Slugs in EXTERNAL_CATALOGS are 302-redirected to a hosted viewer (FlippingBook
// etc.) — used when the external service blocks iframe embedding. Other slugs
// fall through to the self-hosted StPageFlip viewer.
const EXTERNAL_CATALOGS = {
  brochure: 'https://online.flippingbook.com/view/134563990/',
};
app.get('/catalog', (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'catalog', 'index.html'));
});
app.get('/catalog/:slug', (req, res) => {
  const slug = (req.params.slug || '').replace(/[^a-z0-9-]/gi, '');
  if (!slug) return res.redirect(302, '/catalog');
  if (EXTERNAL_CATALOGS[slug]) return res.redirect(302, EXTERNAL_CATALOGS[slug]);
  // The viewer reads the slug from window.location and fetches the matching manifest
  sendHtml(res, path.join(__dirname, 'public', 'catalog', 'viewer.html'));
});

// ─── Discontinued Alpha Zero stones — redirect to collections ───
const discontinuedSlugs = [
  'silver-travertine', 'crystello', 'grande-glacier', 'basaltina',
  'carbon', 'acropolis', 'glacier-grey', 'noosa', 'calacatta-oro', 'serena'
];

// ─── Renamed stones — 301 to new slug ───
const renamedSlugs = {
  'viola-ligerra': 'viola-ligera'
};

// ─── Partner landing pages (private ABM pages — direct URL only) ───
// Maps /partners/<slug> to public/partners/<slug>.html.
app.get('/partners/:slug', (req, res) => {
  const slug = req.params.slug.replace(/[^a-z0-9-]/gi, '');
  const filePath = path.join(__dirname, 'public', 'partners', slug + '.html');
  if (fs.existsSync(filePath)) return sendHtml(res, filePath);
  res.redirect('/');
});

// ─── Stone detail page ───
app.get('/surfaces/:slug', (req, res) => {
  const slug = req.params.slug.replace(/[^a-z0-9-]/gi, '');
  if (renamedSlugs[slug]) {
    return res.redirect(301, '/surfaces/' + renamedSlugs[slug]);
  }
  if (discontinuedSlugs.includes(slug)) {
    return res.redirect(301, '/collections#alpha-zero');
  }
  const filePath = path.join(__dirname, 'public', 'surfaces', slug + '.html');
  if (fs.existsSync(filePath)) {
    sendHtml(res, filePath);
  } else {
    res.status(404).send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Surface Not Found | Alpha Surfaces</title>
<style>
:root{--olive:#564d22;--cream:#f3f1e6;--black:#000000;--white:#ffffff}
body{background:var(--cream);color:var(--black);font-family:'Degular',sans-serif;margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center}
h1{font-family:'Concrette S',serif;font-size:42px;font-weight:700;margin:0 0 12px}
p{font-size:16px;color:var(--black);opacity:0.5;margin-bottom:32px}
a{font-size:12px;font-weight:600;letter-spacing:0.15em;text-transform:uppercase;color:var(--white);background:var(--olive);padding:12px 28px;border-radius:8px;text-decoration:none}
a:hover{opacity:0.9}
</style></head><body><div><h1>Surface Not Found</h1><p>The surface you're looking for doesn't exist.</p><a href="/collections.html">Return to Collections</a></div></body></html>`);
  }
});

// Generate a tracked outreach URL — admin-only. Records the send so the
// view receiver and form attribution can link visits back to the prospect.
app.get('/api/admin/outreach/generate-url', authMiddleware, async (req, res) => {
  try {
    const { prospect_email, am_email, page_slug, prospect_name, prospect_company } = req.query;
    if (!prospect_email || !am_email || !page_slug) {
      return res.status(400).json({
        error: 'Missing required params: prospect_email, am_email, page_slug'
      });
    }
    const cleanSlug = String(page_slug).replace(/[^a-z0-9-]/gi, '');
    if (!cleanSlug) return res.status(400).json({ error: 'Invalid page_slug' });

    const prospectId = crypto.randomUUID();
    const baseUrl = process.env.SITE_URL || 'https://alphasurfaces.com.au';
    const trackedUrl = `${baseUrl}/partners/${cleanSlug}` +
      `?pid=${prospectId}` +
      `&utm_source=landing_page` +
      `&utm_medium=email` +
      `&utm_campaign=${encodeURIComponent(cleanSlug)}` +
      `&utm_content=${encodeURIComponent(am_email)}`;

    await pool.query(
      `INSERT INTO outreach_sends
         (prospect_id, prospect_email, prospect_name, prospect_company,
          am_email, landing_page_slug, landing_page_url, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'sent')`,
      [prospectId, prospect_email, prospect_name || null,
       prospect_company || null, am_email, cleanSlug, trackedUrl]
    );

    res.json({
      ok: true,
      prospect_id: prospectId,
      tracked_url: trackedUrl,
      page_slug: cleanSlug,
      am_email,
      prospect_email
    });
  } catch (err) {
    console.error('[outreach] generate-url error:', err.message);
    res.status(500).json({ error: 'Failed to generate tracked URL' });
  }
});

// Admin dashboard summary — last 30 days of sends, engagement, per-AM.
app.get('/api/admin/outreach/stats', authMiddleware, async (req, res) => {
  try {
    const sends = await pool.query(`
      SELECT
        COUNT(*)::int as total_sends,
        COUNT(*) FILTER (WHERE status = 'sent')::int      as pending,
        COUNT(*) FILTER (WHERE status = 'opened')::int    as opened,
        COUNT(*) FILTER (WHERE status = 'clicked')::int   as clicked,
        COUNT(*) FILTER (WHERE status = 'converted')::int as converted,
        COUNT(*) FILTER (WHERE status = 'stale')::int     as stale
      FROM outreach_sends
      WHERE sent_at > NOW() - INTERVAL '30 days'
    `);

    const views = await pool.query(`
      SELECT
        COUNT(*)::int                                     as total_views,
        COALESCE(ROUND(AVG(duration_seconds))::int, 0)    as avg_duration,
        COALESCE(ROUND(AVG(max_scroll_pct))::int, 0)      as avg_scroll
      FROM landing_page_views
      WHERE viewed_at > NOW() - INTERVAL '30 days'
    `);

    const perAm = await pool.query(`
      SELECT
        am_email,
        COUNT(*)::int                                                          as sends,
        COUNT(*) FILTER (WHERE status IN ('opened','clicked','converted'))::int as engaged,
        COUNT(*) FILTER (WHERE status = 'converted')::int                       as converted
      FROM outreach_sends
      WHERE sent_at > NOW() - INTERVAL '30 days'
      GROUP BY am_email
      ORDER BY sends DESC
    `);

    res.json({
      ok: true,
      summary: sends.rows[0],
      engagement: views.rows[0],
      per_am: perAm.rows
    });
  } catch (err) {
    console.error('[outreach] stats error:', err.message);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// ─── Catch-all for SPA ───
app.get('*', (req, res) => {
  sendHtml(res, path.join(__dirname, 'public', 'index.html'));
});

// ─── Version History Startup ───
versions.ensureDirectories();
versions.snapshotContentOnStartup(loadContent());
versions.detectAndSnapshotPages();

// ─── Daily digest scheduler ───
// Fires sendDailyDigest({pool}) once per day at or after 17:00 Australia/Brisbane.
// We compute the local Brisbane date string from Intl, and only fire when
// _state.lastDigestSent is from a different day. Persisting the date string
// after firing prevents the 60s-tick from re-sending within the same day.
function brisbaneTodayString() {
  // 'en-CA' gives YYYY-MM-DD which is naturally sortable / comparable.
  return new Date().toLocaleDateString('en-CA', { timeZone: 'Australia/Brisbane' });
}
function brisbaneHour() {
  const parts = new Intl.DateTimeFormat('en-AU', {
    timeZone: 'Australia/Brisbane',
    hour: 'numeric',
    hour12: false
  }).formatToParts(new Date());
  const h = parts.find(p => p.type === 'hour');
  return h ? parseInt(h.value, 10) : 0;
}
async function checkDailyDigest() {
  try {
    const cfg = readNotifSettings();
    if (!cfg) return;
    const today = brisbaneTodayString();
    const lastSentISO = cfg._state && cfg._state.lastDigestSent;
    const lastSentDay = lastSentISO
      ? new Date(lastSentISO).toLocaleDateString('en-CA', { timeZone: 'Australia/Brisbane' })
      : null;
    if (lastSentDay === today) return;          // already fired today
    if (brisbaneHour() < 17) return;             // before 5pm Brisbane
    console.log('[notify] Firing daily digest for', today);
    const result = await sendDailyDigest({ pool });
    console.log('[notify] Digest result:', JSON.stringify(result));
  } catch (err) {
    console.error('[notify] Digest scheduler error:', err.message);
  }
}

// ─── Weekly sales report scheduler — Friday 5pm Brisbane ───
// Two-layer dedup: this in-memory `lastSentWeek` guards against re-fires
// inside the same process, and notifications.js persists the same key to
// settings.json so the guard also survives a restart (which is what caused
// the duplicate-send incident). The in-memory flag is only set after a
// confirmed successful send so a failed attempt is retried on the next tick.
let lastSentWeek = null;
async function checkWeeklyReport() {
  try {
    if (!process.env.SENDGRID_API_KEY) return; // can't send without sg
    const briz = new Date(new Date().toLocaleString('en-US', { timeZone: 'Australia/Brisbane' }));
    if (briz.getDay() !== 5) return;          // Friday only
    if (briz.getHours() !== 17) return;       // 5pm hour only (cron runs every 5min)
    const currentWeek = notifications.isoWeekStringBrisbane();
    if (lastSentWeek === currentWeek) return;
    console.log('[report/weekly] firing for week', currentWeek);
    const result = await generateWeeklyReport({ pool });
    console.log('[report/weekly] result:', JSON.stringify(result));
    if (result && result.ok) lastSentWeek = currentWeek;
  } catch (err) {
    console.error('[report/weekly] scheduler error:', err.message);
  }
}

initDB()
  .then(() => cmsCore.initCms({ pool }))
  .then(() => {
    app.listen(PORT, () => console.log(`[server] Listening on port ${PORT}`));
    // Kick off scheduler — first check after 30s, then every 60s.
    setTimeout(checkDailyDigest, 30 * 1000);
    setInterval(checkDailyDigest, 60 * 1000);
    // Weekly Friday 5pm Brisbane sales report.
    setInterval(checkWeeklyReport, 5 * 60 * 1000);
    // Auto time-tracking from GitHub commits — runs at the top of each
    // hour between 06:00 and 22:00 Brisbane. Silent no-op when
    // GITHUB_TOKEN is unset.
    scheduleAutoTracker({ pool, checkAndSendTimeAlert });
    // Cache the Pipedrive HOT label id once the network is up. Silent
    // no-op when PIPEDRIVE_API_TOKEN is unset.
    pipedrive.initPipedriveLabels().catch(err =>
      console.error('[pipedrive] init labels error:', err.message)
    );
  })
  .catch(err => {
    console.error('[db] Failed to initialise database:', err);
    process.exit(1);
  });
