'use strict';
/**
 * Website forms through sprintrep (sprintrep ADR 0080).
 *
 * Each public form handler can hand a submission to sprintrep, server to server, instead of
 * doing the work here. sprintrep then issues the reference (SR-, WA-, ...), writes Pipedrive,
 * alerts the staff (hello@ and the SMS) and sends the customer's confirmation. The browser and the
 * pages do not change.
 *
 * Switched per form with FORMS_VIA_SPRINTREP, a comma list of:
 *   newsletter, contact, enquiry, showroom-checkin, sample-modal, order-sample, warranty
 * ("partner-contact" is the same switch as "contact"; the two sample forms share the SR- series
 * so switching one switches both.) Unset or empty: every form works exactly as before.
 *
 * Nothing is lost:
 * - a copy of every submission is kept here (table sprintrep_form_copies) for 30 days;
 * - if sprintrep can't be reached, answers with a server error, or refuses the site, this server
 *   does what it always did (saves it, tells the staff, writes Pipedrive) except that it does not
 *   number it: the visitor gets an FB- reference, the copy is marked "fallback" and retried every
 *   minute; sprintrep then numbers it, sends the customer's confirmation and adds its reference
 *   to Pipedrive, without telling the staff or writing the lead a second time;
 * - if this server's own database is down too, the file queue (form-fallback-queue.js) holds it.
 *
 * Settings (Railway, names only):
 *   FORMS_VIA_SPRINTREP     which forms go to sprintrep
 *   SPRINTREP_FORMS_URL     sprintrep's API address (default https://api.sprintrep.ai)
 *   SPRINTREP_SITE_KEY      this website's public site key in sprintrep (as SPRINTREP_SITE_ID)
 *   SPRINTREP_FORMS_SECRET  the shared secret sprintrep checks (never in code or logs)
 */

const crypto = require('crypto');

const FORM_IDS = ['newsletter', 'contact', 'enquiry', 'showroom-checkin', 'sample-modal', 'order-sample', 'warranty'];
const ALIASES = { 'partner-contact': 'contact', showroom: 'showroom-checkin', samples: 'order-sample', subscribe: 'newsletter' };
// Forms that share an endpoint or a reference series go together.
const GROUPS = { 'sample-modal': 'samples', 'order-sample': 'samples' };
const DEFAULT_URL = 'https://api.sprintrep.ai';
const TIMEOUT_MS = 10000;
const KEEP_DAYS = 30;
const PHOTO_HOSTS = /^https:\/\/res\.cloudinary\.com\//;
const PHOTO_MAX_BYTES = 5 * 1024 * 1024;

function canonical(id) {
  const key = String(id || '').trim().toLowerCase();
  if (FORM_IDS.includes(key)) return key;
  return ALIASES[key] || null;
}

/** The forms switched on, with group members added (both sample forms, never one). */
function enabledForms(env) {
  const raw = String((env || process.env).FORMS_VIA_SPRINTREP || '');
  const out = new Set();
  for (const part of raw.split(',')) {
    const id = canonical(part);
    if (id) out.add(id);
  }
  for (const id of Array.from(out)) {
    const group = GROUPS[id];
    if (!group) continue;
    for (const other of Object.keys(GROUPS)) if (GROUPS[other] === group) out.add(other);
  }
  return out;
}

function configured(env) {
  const e = env || process.env;
  return Boolean(e.SPRINTREP_SITE_KEY && /^[a-f0-9]{32}$/.test(e.SPRINTREP_SITE_KEY) && e.SPRINTREP_FORMS_SECRET);
}

/** Which sprintrep form a website form type is, or null when it isn't switched on. */
function formIdFor(formType, body, env) {
  let id = null;
  if (formType === 'Sample Request') {
    // The order-sample page sends sampleItems / samples; the pop-up sends one stone_slug.
    id = (body && (body.sampleItems || body.samples)) ? 'order-sample' : 'sample-modal';
  } else if (formType === 'Contact Enquiry') id = 'contact';
  else if (formType === 'Enquiry') id = 'enquiry';
  else if (formType === 'Warranty Activation') id = 'warranty';
  else if (formType === 'Showroom Check-In') id = 'showroom-checkin';
  else if (formType === 'Newsletter') id = 'newsletter';
  if (!id) return null;
  if (!enabledForms(env).has(id)) return null;
  if (!configured(env)) {
    console.warn('[sprintrep-forms] ' + id + ' is switched on but SPRINTREP_SITE_KEY / SPRINTREP_FORMS_SECRET are not set; handling it here');
    return null;
  }
  return id;
}

function clientSubmissionId(fields) {
  const v = fields && (fields._client_submission_id || fields.client_submission_id || fields.submission_uuid);
  const s = v ? String(v).trim() : '';
  return /^[A-Za-z0-9_.:-]{1,100}$/.test(s) ? s : null;
}

function fallbackReference(id) {
  return 'FB-' + String(id || crypto.randomUUID()).replace(/[^a-zA-Z0-9]/g, '').slice(0, 10).toUpperCase();
}

/* ── the local copy (30 days) ────────────────────────────────────────── */

let ready = null;
function ensureTable(pool) {
  if (!ready) {
    ready = pool.query(
      'CREATE TABLE IF NOT EXISTS sprintrep_form_copies (' +
      '  id SERIAL PRIMARY KEY,' +
      '  client_submission_id VARCHAR(100) NOT NULL UNIQUE,' +
      '  form_id VARCHAR(40) NOT NULL,' +
      '  fields JSONB NOT NULL,' +
      '  sample_items JSONB NOT NULL DEFAULT \'[]\',' +
      '  meta JSONB NOT NULL DEFAULT \'{}\',' +
      // pending: saved, not yet sent. forwarded: sprintrep has it. fallback: done here, to send.
      // invalid: sprintrep refused the answers (the visitor was told).
      '  status VARCHAR(20) NOT NULL DEFAULT \'pending\',' +
      '  done TEXT[] NOT NULL DEFAULT \'{}\',' +
      '  sprintrep_id VARCHAR(64),' +
      '  reference VARCHAR(40),' +
      '  fallback_reference VARCHAR(40),' +
      '  attempts INTEGER NOT NULL DEFAULT 0,' +
      '  last_error TEXT,' +
      '  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),' +
      '  forwarded_at TIMESTAMPTZ' +
      ');' +
      'CREATE INDEX IF NOT EXISTS idx_sprintrep_copies_status ON sprintrep_form_copies(status, created_at);'
    ).catch(err => { ready = null; throw err; });
  }
  return ready;
}

async function saveCopy(pool, item) {
  await ensureTable(pool);
  const { rows } = await pool.query(
    'INSERT INTO sprintrep_form_copies (client_submission_id, form_id, fields, sample_items, meta) ' +
    'VALUES ($1, $2, $3, $4, $5) ' +
    'ON CONFLICT (client_submission_id) DO UPDATE SET client_submission_id = EXCLUDED.client_submission_id ' +
    'RETURNING id, status, reference, fallback_reference, sprintrep_id',
    [item.clientSubmissionId, item.formId, JSON.stringify(item.fields || {}), JSON.stringify(item.sampleItems || []), JSON.stringify(item.meta || {})]
  );
  return rows[0];
}

async function markCopy(pool, clientId, patch) {
  try {
    await ensureTable(pool);
    await pool.query(
      'UPDATE sprintrep_form_copies SET status = COALESCE($2, status), reference = COALESCE($3, reference),' +
      ' fallback_reference = COALESCE($4, fallback_reference), sprintrep_id = COALESCE($5, sprintrep_id),' +
      ' done = COALESCE($6, done), last_error = $7,' +
      ' attempts = attempts + CASE WHEN $8 THEN 1 ELSE 0 END,' +
      ' forwarded_at = CASE WHEN $2 = \'forwarded\' THEN NOW() ELSE forwarded_at END' +
      ' WHERE client_submission_id = $1',
      [clientId, patch.status || null, patch.reference || null, patch.fallbackReference || null,
       patch.sprintrepId || null, patch.done || null, patch.error || null, Boolean(patch.attempt)]
    );
  } catch (err) {
    console.error('[sprintrep-forms] copy update failed:', err.message);
  }
}

async function pruneCopies(pool) {
  try {
    await ensureTable(pool);
    // Only what sprintrep has: a copy still waiting is never thrown away.
    await pool.query(
      'DELETE FROM sprintrep_form_copies WHERE created_at < NOW() - make_interval(days => $1)' +
      ' AND status IN (\'forwarded\', \'invalid\')',
      [KEEP_DAYS]
    );
  } catch (err) {
    console.error('[sprintrep-forms] prune failed:', err.message);
  }
}

/* ── sending ─────────────────────────────────────────────────────────── */

async function photoFiles(fields, fetchImpl) {
  const urls = Array.isArray(fields && fields.installation_photos) ? fields.installation_photos.slice(0, 3) : [];
  const files = [];
  for (const url of urls) {
    if (!PHOTO_HOSTS.test(String(url))) continue;
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
      const r = await fetchImpl(url, { signal: ctrl.signal });
      clearTimeout(timer);
      if (!r.ok) continue;
      const type = String(r.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
      const buf = Buffer.from(await r.arrayBuffer());
      if (!buf.length || buf.length > PHOTO_MAX_BYTES) continue;
      files.push({ type: type || 'image/jpeg', buf, name: String(url).split('/').pop().slice(0, 100) || 'photo' });
    } catch (err) {
      // The photo's link stays in the answers; the submission never waits on a photo.
      console.warn('[sprintrep-forms] photo copy skipped:', err.message);
    }
  }
  return files;
}

/**
 * Sends one submission. Returns { kind: 'ok', id, reference } | { kind: 'invalid', error } |
 * { kind: 'unavailable', error }. Never throws.
 */
async function forward(item, options) {
  const env = (options && options.env) || process.env;
  const fetchImpl = (options && options.fetchImpl) || globalThis.fetch;
  const base = String(env.SPRINTREP_FORMS_URL || DEFAULT_URL).replace(/\/+$/, '');
  const url = base + '/forms/' + env.SPRINTREP_SITE_KEY + '/' + item.formId;
  const envelope = {
    clientSubmissionId: item.clientSubmissionId,
    submittedAt: item.submittedAt || new Date().toISOString(),
    fallback: (item.done || []).indexOf('staff_alert') >= 0,
    done: item.done || [],
    fields: item.fields,
    sampleItems: item.sampleItems || [],
    meta: item.meta || {}
  };
  let body;
  const headers = { authorization: 'Bearer ' + env.SPRINTREP_FORMS_SECRET };
  const photos = item.formId === 'warranty' ? await photoFiles(item.fields, fetchImpl) : [];
  if (photos.length) {
    body = new FormData();
    body.set('envelope', JSON.stringify(envelope));
    for (const p of photos) body.append('photos', new Blob([p.buf], { type: p.type }), p.name);
  } else {
    body = JSON.stringify(envelope);
    headers['content-type'] = 'application/json';
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), (options && options.timeoutMs) || TIMEOUT_MS);
  try {
    const res = await fetchImpl(url, { method: 'POST', headers, body, signal: ctrl.signal });
    let json = null;
    try { json = await res.json(); } catch (e) { json = null; }
    if (res.status === 200 && json && json.ok) {
      return { kind: 'ok', id: json.id || null, reference: json.reference || null };
    }
    if (res.status === 400 && json && json.error) return { kind: 'invalid', error: String(json.error) };
    return { kind: 'unavailable', error: 'sprintrep answered ' + res.status };
  } catch (err) {
    return { kind: 'unavailable', error: err && err.name === 'AbortError' ? 'sprintrep timed out' : 'sprintrep unreachable' };
  } finally {
    clearTimeout(timer);
  }
}

function requestMeta(req) {
  return {
    ip: (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || null,
    userAgent: req.headers['user-agent'] || null,
    page: req.headers.referer || req.headers.referrer || null
  };
}

/**
 * Handles one switched-on submission end to end and answers the visitor.
 *   opts.formId, opts.fields, opts.sampleItems
 *   opts.localFallback(fbRef) -> Promise: do what this server always did, without a number
 *   opts.done: what localFallback does ('staff_alert', 'crm', and 'customer_email' for newsletter)
 *   opts.queueFallback(err) -> response: the file queue when this server's database is down too
 *   opts.extraMeta: e.g. the newsletter's unsubscribe link
 */
async function handle(req, res, deps, opts) {
  const pool = deps.pool;
  const clientId = clientSubmissionId(opts.fields) || crypto.randomUUID();
  const item = {
    clientSubmissionId: clientId,
    formId: opts.formId,
    fields: opts.fields,
    sampleItems: opts.sampleItems || [],
    submittedAt: new Date().toISOString(),
    meta: Object.assign(requestMeta(req), opts.extraMeta || {})
  };
  let copy = null;
  try {
    copy = await saveCopy(pool, item);
  } catch (err) {
    console.error('[sprintrep-forms] local copy failed:', err.message);
  }
  // A browser retry of something sprintrep already has: the same answer, nothing sent again.
  if (copy && copy.status === 'forwarded') {
    return res.json({ ok: true, id: copy.sprintrep_id, reference: copy.reference || undefined });
  }
  if (copy && copy.status === 'fallback') {
    return res.json({ ok: true, queued: true, reference: copy.fallback_reference });
  }
  const sent = await forward(item, deps);
  if (sent.kind === 'ok') {
    await markCopy(pool, clientId, { status: 'forwarded', reference: sent.reference, sprintrepId: sent.id });
    if (typeof opts.onForwarded === 'function') {
      try { opts.onForwarded(sent); } catch (err) { console.error('[sprintrep-forms] after-send hook:', err.message); }
    }
    return res.json({ ok: true, id: sent.id, reference: sent.reference || undefined });
  }
  if (sent.kind === 'invalid') {
    await markCopy(pool, clientId, { status: 'invalid', error: sent.error });
    return res.status(400).json({ ok: false, error: sent.error });
  }
  // sprintrep can't take it: do it here, as always, and send it to sprintrep later.
  const fbRef = fallbackReference(clientId);
  console.warn('[sprintrep-forms] ' + opts.formId + ' fell back to the website (' + sent.error + ') as ' + fbRef);
  try {
    const local = await opts.localFallback(fbRef);
    await markCopy(pool, clientId, {
      status: copy ? 'fallback' : null,
      fallbackReference: fbRef,
      done: opts.done || ['staff_alert', 'crm'],
      error: sent.error,
      attempt: true
    });
    if (!copy) {
      // No local copy (this server's database refused it): the file queue keeps it for sprintrep.
      deps.queue.enqueue({ kind: 'sprintrep', formType: opts.formId, fields: Object.assign({}, opts.fields, { _client_submission_id: clientId }), sampleItems: item.sampleItems, meta: Object.assign({}, item.meta, { done: opts.done || ['staff_alert', 'crm'], fallbackReference: fbRef }) });
    }
    return res.json({ ok: true, queued: true, id: local && local.id, reference: fbRef });
  } catch (err) {
    console.error('[sprintrep-forms] local fallback failed:', err.message);
    return opts.queueFallback(err);
  }
}

/**
 * Sends what is waiting: copies saved but never sent (crash), and fallbacks. Every minute.
 * A fallback is sent with what this server already did, so sprintrep doesn't do it twice.
 */
async function retryWaiting(deps, limit) {
  const pool = deps.pool;
  const stats = { sent: 0, waiting: 0, invalid: 0 };
  try {
    await ensureTable(pool);
  } catch (err) {
    return stats;
  }
  const { rows } = await pool.query(
    'SELECT client_submission_id, form_id, fields, sample_items, meta, status, done, fallback_reference, created_at' +
    ' FROM sprintrep_form_copies' +
    ' WHERE (status = \'fallback\' OR (status = \'pending\' AND created_at < NOW() - INTERVAL \'2 minutes\'))' +
    ' ORDER BY created_at LIMIT $1',
    [limit || 25]
  );
  for (const row of rows) {
    const item = {
      clientSubmissionId: row.client_submission_id,
      formId: row.form_id,
      fields: row.fields,
      sampleItems: row.sample_items,
      submittedAt: new Date(row.created_at).toISOString(),
      meta: Object.assign({}, row.meta || {}, row.fallback_reference ? { fallbackReference: row.fallback_reference } : {}),
      done: row.status === 'fallback' ? (row.done || []) : []
    };
    const sent = await forward(item, deps);
    if (sent.kind === 'ok') {
      stats.sent += 1;
      await markCopy(pool, row.client_submission_id, { status: 'forwarded', reference: sent.reference, sprintrepId: sent.id });
    } else if (sent.kind === 'invalid') {
      // The website accepted it, so its answers are kept here; a person looks at it.
      stats.invalid += 1;
      await markCopy(pool, row.client_submission_id, { status: 'invalid', error: sent.error, attempt: true });
      console.error('[sprintrep-forms] sprintrep refused a waiting ' + row.form_id + ': ' + sent.error);
    } else {
      stats.waiting += 1;
      await markCopy(pool, row.client_submission_id, { error: sent.error, attempt: true });
    }
  }
  return stats;
}

/** How many are still waiting, and the oldest, for the stuck alert. */
async function waitingSummary(pool) {
  try {
    await ensureTable(pool);
    const { rows } = await pool.query(
      'SELECT count(*)::int AS n, MIN(created_at) AS oldest FROM sprintrep_form_copies' +
      ' WHERE status IN (\'fallback\', \'pending\')'
    );
    return rows[0] || { n: 0, oldest: null };
  } catch (err) {
    return { n: 0, oldest: null };
  }
}

module.exports = {
  FORM_IDS,
  canonical,
  enabledForms,
  configured,
  formIdFor,
  clientSubmissionId,
  fallbackReference,
  forward,
  handle,
  retryWaiting,
  pruneCopies,
  waitingSummary,
  saveCopy,
  _setReady: (v) => { ready = v; }
};
