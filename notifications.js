'use strict';
/**
 * Notification dispatch — multi-recipient, per-form, with instant/daily cadence.
 *
 * Settings live in DATA_DIR/notifications.json (see seeds/notifications.json
 * for shape). Each form has independent SMS and email blocks; each recipient
 * has {name, phone|email, enabled, cadence}. Cadence='instant' fires per
 * submission; cadence='daily' is collected by the digest scheduler in
 * server.js and sent at 17:00 Australia/Brisbane.
 *
 * Twilio/SMTP env vars (TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM,
 * SMTP_USER, SMTP_PASS, SMTP_HOST) are still required for the *sender* side —
 * recipients moved into settings, but credentials remain in env.
 */

const fs         = require('fs');
const path       = require('path');
const nodemailer = require('nodemailer');
const twilio     = require('twilio');
const sgMail     = require('@sendgrid/mail');
const crypto     = require('crypto');

// ─── Single-recipient instant notification (env-driven, fires on every submit)
//
// Required Railway env vars:
//   TWILIO_ACCOUNT_SID  - Twilio Account SID
//   TWILIO_AUTH_TOKEN   - Twilio Auth Token
//   TWILIO_FROM         - Twilio sending number (e.g. +19784876059)
//   NOTIFY_SMS_TO       - SMS recipient (default +61417764689)
//   SENDGRID_API_KEY    - SendGrid API key
//   NOTIFY_EMAIL_TO     - Email recipient (default hello@alphasurfaces.com.au)
//   NOTIFY_EMAIL_FROM   - Verified SendGrid sender (default noreply@alphasurfaces.com.au)
//   SITE_URL            - Base URL for admin links in emails (default https://alphasurfaces.com.au)

const NOTIFY_SMS_TO     = () => process.env.NOTIFY_SMS_TO     || '+61417764689';
const NOTIFY_EMAIL_TO   = () => process.env.NOTIFY_EMAIL_TO   || 'hello@alphasurfaces.com.au';
const NOTIFY_EMAIL_FROM = () => process.env.NOTIFY_EMAIL_FROM || 'noreply@alphasurfaces.com.au';

let sendgridConfigured = false;
function configureSendgrid() {
  if (sendgridConfigured) return true;
  const key = process.env.SENDGRID_API_KEY;
  if (!key) return false;
  sgMail.setApiKey(key);
  sendgridConfigured = true;
  return true;
}

// ─── Settings I/O ─────────────────────────────────────────────────────────
let SETTINGS_PATH = null;
function setSettingsPath(p) { SETTINGS_PATH = p; }
function readSettings() {
  if (!SETTINGS_PATH || !fs.existsSync(SETTINGS_PATH)) return null;
  try { return JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf8')); }
  catch (e) { console.error('[notify] settings parse error:', e.message); return null; }
}
function writeSettings(data) {
  if (!SETTINGS_PATH) return;
  try { fs.writeFileSync(SETTINGS_PATH, JSON.stringify(data, null, 2)); }
  catch (e) { console.error('[notify] settings write error:', e.message); }
}
function getRecipients(formId, channel, cadenceFilter) {
  const cfg = readSettings();
  if (!cfg) return [];
  const block = cfg.notifications && cfg.notifications[formId] && cfg.notifications[formId][channel];
  if (!block || !block.enabled) return [];
  return (block.recipients || []).filter(r => r && r.enabled && (cadenceFilter ? r.cadence === cadenceFilter : true));
}

// ─── Channel senders ─────────────────────────────────────────────────────
function getSMSClient() {
  const sid = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  if (!sid || !token) return null;
  return twilio(sid, token);
}
async function sendSMSTo(phone, body) {
  const client = getSMSClient();
  if (!client) { console.warn('[notify] Twilio not configured — skipping SMS'); return false; }
  if (!process.env.TWILIO_FROM) { console.warn('[notify] TWILIO_FROM not set — skipping SMS'); return false; }
  try {
    await client.messages.create({ body, from: process.env.TWILIO_FROM, to: phone });
    console.log('[notify] SMS sent to', phone);
    return true;
  } catch (err) { console.error('[notify] SMS error to', phone, ':', err.message); return false; }
}
function getMailTransport() {
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  if (!user || !pass) return null;
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.office365.com',
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: false,
    auth: { user, pass }
  });
}
async function sendEmailTo(to, subject, html, extraOpts) {
  const transport = getMailTransport();
  if (!transport) { console.warn('[notify] SMTP not configured — skipping email'); return false; }
  try {
    await transport.sendMail({ from: process.env.SMTP_USER, to, subject, html, ...(extraOpts || {}) });
    console.log('[notify] Email sent to', to);
    return true;
  } catch (err) { console.error('[notify] Email error to', to, ':', err.message); return false; }
}

// ─── Fan-out helpers ─────────────────────────────────────────────────────
async function fanoutInstant(formId, smsBody, emailSubject, emailHtml) {
  const smsRecipients   = getRecipients(formId, 'sms',   'instant');
  const emailRecipients = getRecipients(formId, 'email', 'instant');
  if (!smsRecipients.length && !emailRecipients.length) {
    console.log(`[notify] no instant recipients for ${formId}`);
    return;
  }
  await Promise.all([
    ...smsRecipients.map(r => sendSMSTo(r.phone, smsBody)),
    ...emailRecipients.map(r => sendEmailTo(r.email, emailSubject, emailHtml))
  ]);
}

// ─── Public unsubscribe URL helper (newsletter only) ─────────────────────
function generateUnsubscribeUrl(email) {
  const secret = process.env.SESSION_SECRET || 'alpha-surfaces-secret';
  const token  = crypto.createHmac('sha256', secret).update(email.toLowerCase().trim()).digest('hex').substring(0, 16);
  const base   = process.env.SITE_URL || 'https://alphasurfaces.com.au';
  return `${base}/unsubscribe?email=${encodeURIComponent(email)}&token=${token}`;
}

// ─── Body builders (extracted so digest can reuse) ───────────────────────
function buildOrderSampleBodies(fields, sampleItems, id, submittedAt) {
  const stoneList = sampleItems.length
    ? sampleItems.map(s => `• ${s.name} (${s.collection})`).join('\n')
    : 'No stones selected';
  const sms = [
    `New Sample Request #${id}`,
    `${fields.first_name} ${fields.last_name} — ${fields.role || 'Not specified'}`,
    `${fields.suburb} ${fields.state} ${fields.postcode}`,
    `Samples: ${sampleItems.map(s => s.name).join(', ')}`,
    `${fields.phone} | ${fields.email}`
  ].join('\n');
  const html = `<h2 style="color:#564D22">New Sample Request #${id}</h2>
    <p><strong>Submitted:</strong> ${new Date(submittedAt).toLocaleString('en-AU', { timeZone: 'Australia/Brisbane' })}</p>
    <table cellpadding="6" style="border-collapse:collapse;width:100%;max-width:600px">
      <tr><td><strong>Name</strong></td><td>${fields.first_name} ${fields.last_name}</td></tr>
      <tr><td><strong>Role</strong></td><td>${fields.role || '—'}</td></tr>
      <tr><td><strong>Phone</strong></td><td>${fields.phone}</td></tr>
      <tr><td><strong>Email</strong></td><td>${fields.email}</td></tr>
      <tr><td><strong>Address</strong></td><td>${fields.unit ? fields.unit + ' / ' : ''}${fields.street}, ${fields.suburb} ${fields.state} ${fields.postcode}</td></tr>
      <tr><td><strong>Reason</strong></td><td>${fields.reason || '—'}</td></tr>
      <tr><td><strong>Samples (${sampleItems.length}/3)</strong></td><td><pre style="margin:0">${stoneList}</pre></td></tr>
      <tr><td><strong>Message</strong></td><td>${fields.message || '—'}</td></tr>
      <tr><td><strong>Consent</strong></td><td>${fields.consent ? 'Yes' : 'No'}</td></tr>
    </table>`;
  const subject = `New Sample Request — ${fields.first_name} ${fields.last_name} (${fields.state})`;
  return { sms, html, subject };
}

function buildContactBodies(fields, id, submittedAt) {
  const partnerLine = fields.store_location ? `\nPartner Store: ${fields.store_location}` : '';
  const sms = [`New Contact Enquiry #${id}`, `${fields.name}${partnerLine}`, `${fields.phone} | ${fields.email}`].join('\n');
  const html = `<h2 style="color:#564D22">New Contact Enquiry #${id}</h2>
    <p><strong>Submitted:</strong> ${new Date(submittedAt).toLocaleString('en-AU', { timeZone: 'Australia/Brisbane' })}</p>
    <table cellpadding="6" style="border-collapse:collapse;width:100%;max-width:600px">
      <tr><td><strong>Name</strong></td><td>${fields.name}</td></tr>
      <tr><td><strong>Phone</strong></td><td>${fields.phone}</td></tr>
      <tr><td><strong>Email</strong></td><td>${fields.email}</td></tr>
      ${fields.store_location ? `<tr><td><strong>Partner Store</strong></td><td style="color:#564D22;font-weight:600">${fields.store_location}</td></tr>` : ''}
      ${fields.message ? `<tr><td><strong>Message</strong></td><td>${fields.message}</td></tr>` : ''}
    </table>`;
  const subject = `New Enquiry — ${fields.name}${fields.store_location ? ' via ' + fields.store_location : ''}`;
  return { sms, html, subject };
}

function buildSubscribeBodies(email, id) {
  const sms = `New Newsletter Signup #${id}\n${email}`;
  const html = `<h2 style="color:#564D22">New Newsletter Signup #${id}</h2><p><strong>Email:</strong> ${email}</p>`;
  return { sms, html, subject: 'New Newsletter Signup — ' + email };
}

// ─── Public notify* functions (instant fan-out + welcome email for newsletter) ─
async function notifyOrderSample(fields, sampleItems, id, submittedAt, formId = 'order-sample') {
  const { sms, html, subject } = buildOrderSampleBodies(fields, sampleItems, id, submittedAt);
  await fanoutInstant(formId, sms, subject, html);
}

async function notifyContact(fields, id, submittedAt, formId = 'partner-contact') {
  const { sms, html, subject } = buildContactBodies(fields, id, submittedAt);
  await fanoutInstant(formId, sms, subject, html);
}

async function notifySubscribe(email, id) {
  const { sms, html, subject } = buildSubscribeBodies(email, id);
  // Send welcome email to subscriber regardless of admin notification settings
  const transport = getMailTransport();
  const unsubUrl  = generateUnsubscribeUrl(email);
  const welcomeHtml = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"></head>
    <body style="margin:0;padding:0;background:#f3f1e6;font-family:Georgia,serif">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr><td align="center" style="padding:48px 24px">
          <table width="100%" style="max-width:560px;background:#fff;border-radius:12px;overflow:hidden">
            <tr><td style="background:#564D22;padding:32px 40px">
              <p style="margin:0;color:#f3f1e6;font-size:22px;letter-spacing:.05em">Alpha <span style="font-weight:300">Surfaces</span></p>
            </td></tr>
            <tr><td style="padding:40px">
              <h1 style="color:#564D22;font-size:20px;margin:0 0 16px">Welcome to Alpha Surfaces.</h1>
              <p style="color:#444;font-size:15px;line-height:1.7;margin:0 0 24px">
                You signed up at alphasurfaces.com.au. We'll be in touch with new collections, finishes and stories from Alpha Surfaces.
              </p>
              <p style="color:#444;font-size:15px;line-height:1.7;margin:0 0 40px">
                If you didn't sign up, you can safely ignore this email — we won't contact you again.
              </p>
              <hr style="border:none;border-top:1px solid #e5e0d0;margin:0 0 24px">
              <p style="color:#999;font-size:12px;line-height:1.6;margin:0">
                Alpha Surfaces Pty Ltd · ABN 21 677 729 350<br>
                13 Enterprise Street, Kunda Park QLD 4556<br>
                1300 257 420 · info@alphasurfaces.com.au<br><br>
                <a href="${unsubUrl}" style="color:#564D22">Unsubscribe</a> ·
                <a href="https://alphasurfaces.com.au/privacy.html" style="color:#564D22">Privacy Policy</a>
              </p>
            </td></tr>
          </table>
        </td></tr>
      </table>
    </body></html>`;
  await Promise.all([
    fanoutInstant('newsletter', sms, subject, html),
    // 2 Sep 2026 — moved off the dead SMTP/nodemailer path onto SendGrid.
    // SMTP_HOST/USER/PASS were never set in either environment, so every
    // welcome since launch was silently skipped.
    (configureSendgrid() ? sgMail.send({
      to: email,
      from: NOTIFY_EMAIL_FROM(),
      replyTo: NOTIFY_EMAIL_TO(),
      subject: 'Welcome to Alpha Surfaces',
      html: welcomeHtml,
      headers: {
        'List-Unsubscribe': `<${unsubUrl}>`,
        'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click'
      }
    }).then(() => console.log('[notify] newsletter welcome sent to', email))
      .catch(err => console.error('[notify] newsletter welcome error:',
        err.response?.body?.errors ? JSON.stringify(err.response.body.errors) : err.message))
    : Promise.resolve(console.warn('[notify] SENDGRID_API_KEY not set — skipping newsletter welcome')))
  ]);
}

// ─── Test send (used by admin "Send Test" button) ────────────────────────
// channel: undefined | null = both; 'sms' = SMS only; 'email' = email only
async function sendTestForForm(formId, channel) {
  const cfg = readSettings();
  const formLabel = (cfg && cfg.notifications && cfg.notifications[formId] && cfg.notifications[formId].label) || formId;
  const sms = `[TEST] Alpha Surfaces notification for "${formLabel}". If you got this, instant alerts are wired up.`;
  const subject = `[TEST] Alpha Surfaces — ${formLabel}`;
  const html = `<h2 style="color:#564D22">Test notification</h2>
    <p>This is a test from the Alpha Surfaces admin. Form: <strong>${formLabel}</strong>.</p>
    <p>If you got this, your instant alerts for this form are wired up correctly.</p>`;
  const wantSms   = !channel || channel === 'sms';
  const wantEmail = !channel || channel === 'email';
  const smsRecipients   = wantSms   ? getRecipients(formId, 'sms',   null) : [];
  const emailRecipients = wantEmail ? getRecipients(formId, 'email', null) : [];
  const results = await Promise.all([
    ...smsRecipients.map(r => sendSMSTo(r.phone, sms).then(ok => ({ channel: 'sms', to: r.phone, name: r.name, ok }))),
    ...emailRecipients.map(r => sendEmailTo(r.email, subject, html).then(ok => ({ channel: 'email', to: r.email, name: r.name, ok })))
  ]);
  return results;
}

// ─── Daily digest (called by scheduler in server.js) ─────────────────────
async function sendDailyDigest({ pool }) {
  const cfg = readSettings();
  if (!cfg) return { ok: false, reason: 'no settings' };

  // Gather submissions from the last 24h, grouped by form_type
  // (form_type values in DB: 'Sample Request', 'Contact Enquiry', 'Newsletter')
  // We map form_type → formId for recipient lookup.
  const formTypeToId = {
    'Sample Request':  'order-sample',
    'Contact Enquiry': 'partner-contact',
    'Newsletter':      'newsletter'
  };
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const { rows } = await pool.query(
    'SELECT * FROM form_submissions WHERE submitted_at >= $1 ORDER BY submitted_at DESC',
    [since]
  );

  const byFormId = {};
  for (const r of rows) {
    const formId = formTypeToId[r.form_type] || 'order-sample';
    (byFormId[formId] = byFormId[formId] || []).push(r);
  }

  let sent = 0;
  for (const [formId, subs] of Object.entries(byFormId)) {
    // Defensive — byFormId only contains forms with submissions, but guard anyway.
    if (!subs || subs.length === 0) continue;
    const smsRecipients   = getRecipients(formId, 'sms',   'daily');
    const emailRecipients = getRecipients(formId, 'email', 'daily');
    if (!smsRecipients.length && !emailRecipients.length) continue;

    const formLabel = cfg.notifications[formId]?.label || formId;
    const smsBody = `Alpha Surfaces daily digest — ${formLabel}: ${subs.length} new submission${subs.length === 1 ? '' : 's'} in last 24h.`;
    const emailRows = subs.map(s => `
      <tr>
        <td style="padding:6px;border-bottom:1px solid #eee">#${s.id}</td>
        <td style="padding:6px;border-bottom:1px solid #eee">${new Date(s.submitted_at).toLocaleString('en-AU', { timeZone: 'Australia/Brisbane' })}</td>
        <td style="padding:6px;border-bottom:1px solid #eee">${s.name || '—'}</td>
        <td style="padding:6px;border-bottom:1px solid #eee">${s.email || '—'}</td>
        <td style="padding:6px;border-bottom:1px solid #eee">${s.phone || '—'}</td>
      </tr>`).join('');
    const emailHtml = `<h2 style="color:#564D22">Daily digest — ${formLabel}</h2>
      <p>${subs.length} new submission${subs.length === 1 ? '' : 's'} in the last 24h.</p>
      <table cellpadding="6" style="border-collapse:collapse;width:100%;max-width:700px">
        <thead><tr style="background:#f3f1e6">
          <th align="left" style="padding:6px">#</th>
          <th align="left" style="padding:6px">When</th>
          <th align="left" style="padding:6px">Name</th>
          <th align="left" style="padding:6px">Email</th>
          <th align="left" style="padding:6px">Phone</th>
        </tr></thead>
        <tbody>${emailRows}</tbody>
      </table>
      <p style="margin-top:24px;color:#888;font-size:12px">View full details in the admin: <a href="https://alphasurfaces.com.au/admin.html">alphasurfaces.com.au/admin.html</a></p>`;
    const subject = `Alpha Surfaces daily digest — ${formLabel} (${subs.length})`;

    await Promise.all([
      ...smsRecipients.map(r => sendSMSTo(r.phone, smsBody)),
      ...emailRecipients.map(r => sendEmailTo(r.email, subject, emailHtml))
    ]);
    sent += smsRecipients.length + emailRecipients.length;
  }

  // Persist lastDigestSent regardless — daily cadence should fire once per
  // day even if there were 0 submissions (prevents the scheduler from re-firing).
  cfg._state = cfg._state || {};
  cfg._state.lastDigestSent = new Date().toISOString();
  writeSettings(cfg);

  return { ok: true, sent, formsCovered: Object.keys(byFormId).length };
}

// ─── Weekly sales activity report (Friday 5pm Brisbane) ─────────────────
// Combines local DB (typed-form submissions this week) with Pipedrive
// (open deals / activities / leads inbox) into a single branded email to
// Belinda + Jay, CC Jana + Sean. Best-effort throughout — missing
// PIPEDRIVE_API_TOKEN renders the Pipedrive sections empty rather than
// failing the whole report.

function brisbaneNow() {
  // Construct a Date that, when read with getDate/getDay/getHours/etc,
  // returns Brisbane wall-clock fields. Used by the Friday 5pm scheduler.
  return new Date(new Date().toLocaleString('en-US', { timeZone: 'Australia/Brisbane' }));
}

function formatBrisbaneDate(d) {
  return d.toLocaleDateString('en-AU', {
    timeZone: 'Australia/Brisbane',
    day: 'numeric', month: 'long', year: 'numeric',
  });
}

// ISO-8601 week key (YYYY-Www) anchored to Brisbane local time. Used as the
// once-per-week dedup key for the weekly report, persisted to settings so
// the guard survives process restarts.
function isoWeekStringBrisbane(date) {
  const briz = new Date((date || new Date()).toLocaleString('en-US', { timeZone: 'Australia/Brisbane' }));
  // Copy as UTC date so the ISO-week math (which assumes UTC) doesn't drift.
  const d = new Date(Date.UTC(briz.getFullYear(), briz.getMonth(), briz.getDate()));
  // ISO week: Thursday determines the year, weeks start Monday.
  const dayNum = d.getUTCDay() || 7; // Sun=0 → 7
  d.setUTCDate(d.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  const weekNum = Math.ceil((((d - yearStart) / 86400000) + 1) / 7);
  return `${d.getUTCFullYear()}-W${String(weekNum).padStart(2, '0')}`;
}

async function generateWeeklyReport({ pool }) {
  if (!pool) return { ok: false, reason: 'no pool' };

  // Persistent dedup: skip if we already sent for this ISO week. Survives
  // restarts (the in-memory guard in server.js does not), which is the
  // actual cause of the duplicate-send incident.
  const currentWeek = isoWeekStringBrisbane();
  const cfg = readSettings() || { notifications: {}, _state: {} };
  if (cfg._state && cfg._state.lastWeeklyReportWeek === currentWeek) {
    console.log(`[report/weekly] already sent for week ${currentWeek} — skipping`);
    return { ok: false, reason: 'already sent', week: currentWeek };
  }
  const pipedrive = (() => {
    try { return require('./pipedrive'); } catch { return null; }
  })();

  const now = new Date();
  const weekStart = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const weekStartISO = weekStart.toISOString();
  const weekStartDate = weekStartISO.split('T')[0];
  const todayDate = now.toISOString().split('T')[0];

  // 1. Local DB — submission counts by typed table.
  const tableLabels = [
    ['sample_requests',      'Sample Requests'],
    ['enquiries',            'Enquiries'],
    ['contact_submissions',  'Contacts'],
    ['partner_enquiries',    'Partner Enquiries'],
    ['showroom_checkins',    'Showroom Walk-ins'],
    ['warranty_activations', 'Warranty Activations'],
  ];
  const formCounts = {};
  let formCountFailures = 0;
  for (const [table, label] of tableLabels) {
    try {
      const { rows } = await pool.query(
        `SELECT COUNT(*)::int AS c FROM ${table} WHERE created_at >= $1`,
        [weekStartISO]
      );
      formCounts[label] = rows[0].c;
    } catch (err) {
      console.error('[report/weekly]', table, 'count error:', err.message);
      formCounts[label] = 0;
      formCountFailures += 1;
    }
  }
  // If every form-count query failed, the report would be all zeros and
  // misleading — skip the send entirely and let the next cron tick retry.
  if (formCountFailures === tableLabels.length) {
    console.warn(`[report/weekly] all ${tableLabels.length} form-count queries failed — skipping send (would have been all zeros)`);
    return { ok: false, reason: 'all form counts failed', week: currentWeek };
  }
  // Showroom: split walk-ins by `interests`/source if available so the
  // "(2 homeowners, 1 builder)" summary lands. This is best-effort —
  // the 'role' isn't always captured for walk-ins.
  let showroomBreakdown = '';
  try {
    const { rows } = await pool.query(
      `SELECT COALESCE(NULLIF(source, ''), 'unspecified') AS bucket, COUNT(*)::int AS c
         FROM showroom_checkins WHERE created_at >= $1
        GROUP BY 1 ORDER BY c DESC`,
      [weekStartISO]
    );
    if (rows.length) {
      showroomBreakdown = rows.map(r => `${r.c} ${r.bucket}`).join(', ');
    }
  } catch (_) { /* table may not exist on fresh dbs — ignore */ }

  // Warranty bucket counts (new this week / under_review / approved).
  let warrantyBuckets = { new: 0, under_review: 0, approved: 0 };
  try {
    const { rows } = await pool.query(
      `SELECT status, COUNT(*)::int AS c FROM warranty_activations WHERE created_at >= $1 GROUP BY status`,
      [weekStartISO]
    );
    rows.forEach(r => { warrantyBuckets[r.status] = r.c; });
  } catch (_) {}

  // 2. Pipedrive — pull open deals, activities, leads inbox.
  let deals = [];
  let activities = [];
  let leads = [];
  if (pipedrive && process.env.PIPEDRIVE_API_TOKEN) {
    try {
      const dealsResp = await pipedrive.pdGet('deals', { status: 'open', limit: 500 });
      deals = Array.isArray(dealsResp?.data) ? dealsResp.data : [];
    } catch (err) { console.error('[report/weekly] deals fetch:', err.message); }
    try {
      const actResp = await pipedrive.pdGet('activities', {
        start_date: weekStartDate,
        end_date: todayDate,
        limit: 500,
      });
      activities = Array.isArray(actResp?.data) ? actResp.data : [];
    } catch (err) { console.error('[report/weekly] activities fetch:', err.message); }
    try {
      const leadsResp = await pipedrive.pdGet('leads', { limit: 500 });
      leads = Array.isArray(leadsResp?.data) ? leadsResp.data : [];
    } catch (err) { console.error('[report/weekly] leads fetch:', err.message); }
  }

  // 3. Build & send.
  const html = buildWeeklyReportHtml({
    formCounts, showroomBreakdown, warrantyBuckets,
    deals, activities, leads,
    weekStart, now,
  });

  if (!configureSendgrid()) {
    console.warn('[report/weekly] SENDGRID_API_KEY not set — skipping send');
    return { ok: false, reason: 'no sendgrid' };
  }
  const from = NOTIFY_EMAIL_FROM();
  const to = ['belinda@alphasurfaces.com.au', 'jay@alphasurfaces.com.au'];
  const cc = ['jana@northcoaststone.com.au', 'sean@cangaroo.ai'];
  const subject = `Alpha Surfaces Weekly Sales Report — Week ending ${formatBrisbaneDate(now)}`;
  try {
    await sgMail.send({ to, cc, from, subject, html });
    console.log('[report/weekly] sent to', to.join(', '), 'cc', cc.join(', '));
    // Persist the dedup key only after a confirmed send so a failed attempt
    // is retried on the next cron tick.
    cfg._state = cfg._state || {};
    cfg._state.lastWeeklyReportWeek = currentWeek;
    cfg._state.lastWeeklyReportSentAt = new Date().toISOString();
    writeSettings(cfg);
    return { ok: true, recipients: to.length + cc.length, week: currentWeek };
  } catch (err) {
    const detail = err.response?.body?.errors ? JSON.stringify(err.response.body.errors) : err.message;
    console.error('[report/weekly] send error:', detail);
    return { ok: false, reason: detail };
  }
}

function moneyAUD(n) {
  const v = Number(n) || 0;
  return '$' + v.toLocaleString('en-AU', { maximumFractionDigits: 0 });
}

function buildWeeklyReportHtml({ formCounts, showroomBreakdown, warrantyBuckets, deals, activities, leads, weekStart, now }) {
  // Pipeline buckets — Tile Pipeline (id 1) vs Commercial Projects (id 4).
  const pipelineBuckets = { 1: { name: 'Tile Pipeline', open: 0, value: 0, won: 0 },
                            4: { name: 'Commercial',    open: 0, value: 0, won: 0 } };
  deals.forEach(d => {
    const p = pipelineBuckets[d.pipeline_id];
    if (!p) return;
    p.open++;
    p.value += Number(d.value) || 0;
  });
  // Top 3 open deals by value across all pipelines.
  const topDeals = [...deals]
    .sort((a, b) => (Number(b.value) || 0) - (Number(a.value) || 0))
    .slice(0, 3);

  // Activities per assignee (calls / emails / meetings).
  const teamActivity = {};
  activities.forEach(a => {
    const owner = a.owner_name || a.user_name || 'Unassigned';
    teamActivity[owner] = teamActivity[owner] || { call: 0, email: 0, meeting: 0 };
    const t = String(a.type || '').toLowerCase();
    if (t === 'call') teamActivity[owner].call++;
    else if (t === 'email') teamActivity[owner].email++;
    else if (t === 'meeting' || t === 'lunch' || t === 'demo') teamActivity[owner].meeting++;
  });

  // Leads inbox bucketed by label name. We don't enforce label colour →
  // bucket here because Pipedrive labels are workspace-defined; just
  // bucket by lowercased name and surface counts.
  const leadBuckets = { hot: 0, warm: 0, cold: 0, other: 0 };
  let oldestLeadDays = 0;
  leads.forEach(l => {
    const labelNames = (l.label_ids || []).map(() => '').filter(Boolean);
    // We don't have label name on the lead — fall back to first label_id
    // bucket. Best-effort summary; the link in the report goes to the inbox.
    if (l.label_ids && l.label_ids.length) {
      // Without a label-id → name map we can't do better than 'other'.
      leadBuckets.other++;
    } else {
      leadBuckets.other++;
    }
    const added = l.add_time ? new Date(l.add_time) : null;
    if (added) {
      const days = Math.floor((now - added) / (1000 * 60 * 60 * 24));
      if (days > oldestLeadDays) oldestLeadDays = days;
    }
  });

  const totalLeadsThisWeek =
    (formCounts['Sample Requests'] || 0) +
    (formCounts['Enquiries'] || 0) +
    (formCounts['Contacts'] || 0) +
    (formCounts['Partner Enquiries'] || 0);

  const olive = '#564D22';
  const cream = '#f3f1e6';

  const pipelineRows = Object.values(pipelineBuckets).map(p => `
    <tr>
      <td style="padding:6px 12px;border-bottom:1px solid #eee">${escapeHtml(p.name)}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #eee;text-align:right">${p.open}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #eee;text-align:right">${moneyAUD(p.value)}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #eee;text-align:right">${p.won}</td>
    </tr>
  `).join('');

  const topDealsHtml = topDeals.length
    ? '<ol style="margin:8px 0 0;padding-left:22px;color:#222">' +
      topDeals.map(d => `<li style="margin:3px 0">${escapeHtml(d.title || '—')} — <strong>${moneyAUD(d.value)}</strong> <span style="color:#888">(${escapeHtml(d.stage_name || d.status || '—')})</span></li>`).join('') +
      '</ol>'
    : '<p style="margin:6px 0 0;color:#888">No open deals.</p>';

  const teamRows = Object.entries(teamActivity).map(([who, c]) => `
    <tr>
      <td style="padding:6px 12px;border-bottom:1px solid #eee">${escapeHtml(who)}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #eee;text-align:right">${c.call}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #eee;text-align:right">${c.email}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #eee;text-align:right">${c.meeting}</td>
    </tr>
  `).join('');
  const teamWarning = !Object.keys(teamActivity).length
    ? '<p style="margin:8px 0 0;color:#b07020;font-size:13px">⚠️ No activities logged in Pipedrive this week — tracking recommended.</p>'
    : '';

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:${cream};font-family:'Helvetica Neue',Arial,sans-serif">
<table cellpadding="0" cellspacing="0" border="0" width="100%" style="background:${cream}">
<tr><td align="center" style="padding:48px 16px">
<table cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:680px;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.06)">
  <tr><td style="background:${olive};padding:28px 32px;color:#fff">
    <p style="margin:0;font-size:13px;letter-spacing:.12em;text-transform:uppercase;opacity:.85">Alpha Surfaces · Weekly Report</p>
    <h1 style="margin:8px 0 0;font-size:22px;font-weight:600">Weekly Sales Activity Report</h1>
    <p style="margin:6px 0 0;font-size:14px;opacity:.9">Week ending ${escapeHtml(formatBrisbaneDate(now))}</p>
  </td></tr>

  <tr><td style="padding:28px 32px;color:#222;font-size:14px;line-height:1.55">

    <h2 style="margin:0 0 8px;font-size:14px;letter-spacing:.06em;text-transform:uppercase;color:${olive};border-bottom:1px solid #eee;padding-bottom:6px">New Leads This Week</h2>
    <p style="margin:6px 0 0">Total: <strong>${totalLeadsThisWeek}</strong> hot leads from website</p>
    <ul style="margin:6px 0 0;padding-left:22px;color:#444">
      <li>${formCounts['Sample Requests'] || 0} Sample Requests</li>
      <li>${formCounts['Enquiries'] || 0} General Enquiries</li>
      <li>${formCounts['Partner Enquiries'] || 0} Partner Enquiries</li>
      <li>${formCounts['Contacts'] || 0} Contact Forms</li>
    </ul>

    <h2 style="margin:24px 0 8px;font-size:14px;letter-spacing:.06em;text-transform:uppercase;color:${olive};border-bottom:1px solid #eee;padding-bottom:6px">Showroom</h2>
    <p style="margin:6px 0 0">Walk-ins: <strong>${formCounts['Showroom Walk-ins'] || 0}</strong>${showroomBreakdown ? ' (' + escapeHtml(showroomBreakdown) + ')' : ''}</p>

    <h2 style="margin:24px 0 8px;font-size:14px;letter-spacing:.06em;text-transform:uppercase;color:${olive};border-bottom:1px solid #eee;padding-bottom:6px">Pipedrive Pipeline</h2>
    <table cellpadding="0" cellspacing="0" border="0" width="100%" style="border-collapse:collapse;margin-top:8px;font-size:13px">
      <thead><tr style="background:${cream}">
        <th align="left"  style="padding:6px 12px">Pipeline</th>
        <th align="right" style="padding:6px 12px">Open</th>
        <th align="right" style="padding:6px 12px">Value</th>
        <th align="right" style="padding:6px 12px">Won this week</th>
      </tr></thead>
      <tbody>${pipelineRows || '<tr><td colspan="4" style="padding:8px 12px;color:#888">No data.</td></tr>'}</tbody>
    </table>
    <p style="margin:14px 0 0;font-weight:600;color:${olive}">Top 3 open deals</p>
    ${topDealsHtml}

    <h2 style="margin:24px 0 8px;font-size:14px;letter-spacing:.06em;text-transform:uppercase;color:${olive};border-bottom:1px solid #eee;padding-bottom:6px">Team Activity (Pipedrive)</h2>
    <table cellpadding="0" cellspacing="0" border="0" width="100%" style="border-collapse:collapse;margin-top:8px;font-size:13px">
      <thead><tr style="background:${cream}">
        <th align="left"  style="padding:6px 12px">Owner</th>
        <th align="right" style="padding:6px 12px">Calls</th>
        <th align="right" style="padding:6px 12px">Emails</th>
        <th align="right" style="padding:6px 12px">Meetings</th>
      </tr></thead>
      <tbody>${teamRows || '<tr><td colspan="4" style="padding:8px 12px;color:#888">No activities logged this week.</td></tr>'}</tbody>
    </table>
    ${teamWarning}

    <h2 style="margin:24px 0 8px;font-size:14px;letter-spacing:.06em;text-transform:uppercase;color:${olive};border-bottom:1px solid #eee;padding-bottom:6px">Leads Inbox</h2>
    <p style="margin:6px 0 0">Total in inbox: <strong>${leads.length}</strong></p>
    <p style="margin:4px 0 0;color:#555">Oldest unactioned lead: <strong>${oldestLeadDays}</strong> day${oldestLeadDays === 1 ? '' : 's'}</p>

    <h2 style="margin:24px 0 8px;font-size:14px;letter-spacing:.06em;text-transform:uppercase;color:${olive};border-bottom:1px solid #eee;padding-bottom:6px">Warranty Activations</h2>
    <p style="margin:6px 0 0">New this week: <strong>${formCounts['Warranty Activations'] || 0}</strong></p>
    <p style="margin:4px 0 0;color:#555">Under review: ${warrantyBuckets.under_review || 0} · Approved: ${warrantyBuckets.approved || 0}</p>

    <p style="margin:32px 0 0;color:#888;font-size:12px">Auto-generated by alphasurfaces.com.au — fires every Friday 5pm AEST.</p>
  </td></tr>
</table>
</td></tr>
</table>
</body></html>`;
}

// ─── Single-recipient instant notification helpers ──────────────────────
// These fire on every form submit regardless of admin-configured per-form
// recipients. Used by the form POST handlers in server.js. Failures never
// throw — every external call is wrapped so the form response is unaffected.

async function sendSubmissionSMS(submission) {
  const client = getSMSClient();
  if (!client) { console.warn('[notify] Twilio not configured — skipping submission SMS'); return false; }
  if (!process.env.TWILIO_FROM) { console.warn('[notify] TWILIO_FROM not set — skipping submission SMS'); return false; }
  const body = buildSubmissionSMSBody(submission);
  try {
    await client.messages.create({ body, from: process.env.TWILIO_FROM, to: NOTIFY_SMS_TO() });
    console.log('[notify] submission SMS sent to', NOTIFY_SMS_TO());
    return true;
  } catch (err) {
    console.error('[notify] submission SMS error:', err.message);
    return false;
  }
}

async function sendSubmissionEmail(submission) {
  if (!configureSendgrid()) {
    console.warn('[notify] SENDGRID_API_KEY not set — skipping submission email');
    return false;
  }
  const subject = `New ${formatFormType(submission.form_type)} — ${submission.name || submission.email || 'Anonymous'} — Alpha Surfaces`;
  const html = buildSubmissionEmailHTML(submission);
  try {
    await sgMail.send({
      to: NOTIFY_EMAIL_TO(),
      from: NOTIFY_EMAIL_FROM(),
      subject,
      html
    });
    console.log('[notify] submission email sent to', NOTIFY_EMAIL_TO());
    return true;
  } catch (err) {
    // SendGrid wraps the upstream error message inside response.body
    const detail = err.response?.body?.errors ? JSON.stringify(err.response.body.errors) : err.message;
    console.error('[notify] submission email error:', detail);
    return false;
  }
}

// Forms-portal password reset email. `to` should match NOTIFY_EMAIL_TO so a
// stolen forgot-password attempt by anyone else just bounces silently.
async function sendFormsResetEmail(to, resetUrl) {
  if (!configureSendgrid()) {
    console.warn('[notify] SENDGRID_API_KEY not set — skipping forms reset email');
    return false;
  }
  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Forms password reset — Alpha Surfaces</title></head>
<body style="margin:0;padding:0;background:#f3f1e6;font-family:'Helvetica Neue',Arial,sans-serif">
<table cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#f3f1e6">
  <tr><td align="center" style="padding:48px 16px">
    <table cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:560px;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.06)">
      <tr><td style="background:#564D22;padding:28px 32px">
        <p style="margin:0;color:#f3f1e6;font-size:13px;letter-spacing:.12em;text-transform:uppercase">Alpha Surfaces</p>
        <h1 style="margin:6px 0 0;color:#fff;font-size:22px;font-weight:600">Forms password reset</h1>
      </td></tr>
      <tr><td style="padding:32px">
        <p style="margin:0 0 20px;color:#222;font-size:15px;line-height:1.6">Someone requested a password reset for the Alpha Surfaces forms portal.</p>
        <p style="margin:0 0 28px;color:#222;font-size:15px;line-height:1.6">Click the button below to set a new password. This link expires in 1 hour and can only be used once.</p>
        <p style="margin:0 0 28px"><a href="${escapeAttr(resetUrl)}" style="display:inline-block;background:#564D22;color:#fff;padding:14px 28px;text-decoration:none;font-size:14px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;border-radius:4px">Reset password</a></p>
        <p style="margin:0 0 8px;color:#777;font-size:13px;line-height:1.6">Or paste this link into your browser:</p>
        <p style="margin:0 0 24px;color:#564D22;font-size:13px;line-height:1.5;word-break:break-all">${escapeHtml(resetUrl)}</p>
        <p style="margin:0;color:#999;font-size:13px;line-height:1.6">If you didn't request this, you can ignore this email — your password won't change.</p>
      </td></tr>
      <tr><td style="padding:20px 32px;background:#f7f4e8;color:#999;font-size:12px;text-align:center">
        This is an automated message from alphasurfaces.com.au
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>`;
  try {
    await sgMail.send({
      to,
      from: NOTIFY_EMAIL_FROM(),
      subject: 'Alpha Surfaces — Forms Password Reset',
      html
    });
    console.log('[notify] forms reset email sent to', to);
    return true;
  } catch (err) {
    const detail = err.response?.body?.errors ? JSON.stringify(err.response.body.errors) : err.message;
    console.error('[notify] forms reset email error:', detail);
    return false;
  }
}

// ── Time-tracking threshold alerts ──
// Fires when a user crosses their warning_hours threshold and again when
// they hit monthly_hours_cap, for the supplied month. Dedupe is enforced by
// the time_alerts UNIQUE(user_id, month, alert_type) — a successful INSERT
// is treated as authoritative; if it conflicts the email is skipped.
async function getSuperAdminEmails(pool) {
  if (!pool) return [];
  try {
    const { rows } = await pool.query(
      `SELECT email FROM project_users WHERE role = 'super_admin' AND active = TRUE`
    );
    return rows.map(r => r.email).filter(Boolean);
  } catch (err) {
    console.error('[notify/time] super_admin lookup error:', err.message);
    return [];
  }
}

async function checkAndSendTimeAlert(pool, userId, month) {
  if (!pool || !userId || !month) return { sent: [] };
  if (!/^\d{4}-\d{2}$/.test(month)) return { sent: [] };
  try {
    const { rows: settingsRows } = await pool.query(
      `SELECT s.monthly_hours_cap, s.warning_hours, s.alert_email,
              u.name AS user_name, u.email AS user_email
         FROM user_time_settings s
         JOIN project_users u ON u.id = s.user_id
        WHERE s.user_id = $1`,
      [userId]
    );
    if (!settingsRows.length) return { sent: [] };
    const settings = settingsRows[0];

    // Range query is half-open: [first-of-month, first-of-next-month).
    const [yyyy, mm] = month.split('-').map(Number);
    const startDate = `${month}-01`;
    const nextMonth = mm === 12 ? `${yyyy + 1}-01-01` : `${yyyy}-${String(mm + 1).padStart(2, '0')}-01`;
    const { rows: sumRows } = await pool.query(
      `SELECT COALESCE(SUM(minutes), 0)::int AS total_min FROM time_entries
        WHERE user_id = $1 AND date >= $2::date AND date < $3::date`,
      [userId, startDate, nextMonth]
    );
    const totalMinutes = sumRows[0].total_min;
    const totalHours   = totalMinutes / 60;

    const cap     = settings.monthly_hours_cap;
    const warning = settings.warning_hours;
    const sent = [];
    const monthLabel = new Date(`${startDate}T00:00:00Z`).toLocaleString('en-AU', {
      month: 'long', year: 'numeric', timeZone: 'UTC'
    });

    // Resolve recipient list once per call. Track D requirement: every
    // super_admin gets the alert, sent as separate one-recipient emails so
    // each lands in their own inbox (not a single CC-everyone send).
    const recipients = await getSuperAdminEmails(pool);
    if (!recipients.length) {
      console.warn('[notify/time] no active super_admin recipients — alert skipped');
      return { sent: [], totalHours };
    }

    // Build the threshold ladder. Floor on each level so a brief 14.99 hr
    // calculation doesn't fire the 15hr alert; only fires once the user is
    // genuinely *at* or above the threshold.
    const thresholds = [];
    if (warning && warning < cap) {
      thresholds.push({ hours: warning, type: `${warning}hr_warning`, label: 'Approaching monthly cap', color: '#b07020' });
    }
    thresholds.push({ hours: cap, type: `${cap}hr_reached`, label: 'Monthly cap reached', color: '#b3261e' });
    // Overage rungs every 5 hours above the cap. Cap at totalHours so we
    // don't preemptively schedule alerts that haven't been crossed yet.
    if (totalHours > cap) {
      const top = Math.floor(totalHours / 5) * 5;
      for (let h = cap + 5; h <= top; h += 5) {
        thresholds.push({
          hours: h,
          type: `${h}hr_overage`,
          label: `${h - cap} hours over cap`,
          color: '#b3261e'
        });
      }
    }

    async function maybeSend(threshold) {
      // Race-safe dedupe: insert first, only send if we won the row. If
      // another request already inserted, ON CONFLICT swallows the error
      // and we skip the email.
      const ins = await pool.query(
        `INSERT INTO time_alerts (user_id, month, alert_type)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id, month, alert_type) DO NOTHING
         RETURNING id`,
        [userId, month, threshold.type]
      );
      if (!ins.rows.length) return; // already sent — skip
      if (!configureSendgrid()) {
        console.warn('[notify/time] SENDGRID_API_KEY not set — alert recorded but no email sent');
        return;
      }
      const overBy = totalHours - cap;
      const subject = `⏱ Time tracking alert — ${settings.user_name} has logged ${totalHours.toFixed(1)} of ${cap} hours in ${monthLabel}`;
      const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f3f1e6;font-family:'Helvetica Neue',Arial,sans-serif">
<table cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#f3f1e6">
  <tr><td align="center" style="padding:48px 16px">
    <table cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:560px;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.06)">
      <tr><td style="background:${threshold.color};padding:24px 32px">
        <p style="margin:0;color:#fff;font-size:13px;letter-spacing:.12em;text-transform:uppercase;opacity:.85">Alpha Surfaces · Time tracking</p>
        <h1 style="margin:6px 0 0;color:#fff;font-size:21px;font-weight:600">${escapeHtml(threshold.label)}</h1>
      </td></tr>
      <tr><td style="padding:28px 32px;color:#222;font-size:15px;line-height:1.6">
        <p style="margin:0 0 14px"><strong>${escapeHtml(settings.user_name)}</strong> (${escapeHtml(settings.user_email)}) has logged
          <strong>${totalHours.toFixed(1)} hours</strong> against a ${cap}-hour monthly allocation in ${escapeHtml(monthLabel)}.</p>
        ${overBy > 0
          ? `<p style="margin:0 0 14px;color:#b3261e"><strong>${overBy.toFixed(1)} hours over cap.</strong></p>`
          : `<p style="margin:0 0 14px;color:#555">Warning threshold: ${warning} hrs · Cap: ${cap} hrs.</p>`}
        <p style="margin:24px 0 0">
          <a href="${escapeAttr((process.env.SITE_URL || 'https://alphasurfaces.com.au') + '/projects?view=time')}"
             style="display:inline-block;background:#564D22;color:#fff;padding:11px 22px;text-decoration:none;font-size:13px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;border-radius:4px">
            Open time dashboard
          </a>
        </p>
      </td></tr>
      <tr><td style="padding:18px 32px;background:#f7f4e8;color:#999;font-size:12px;text-align:center">
        Sent to all super_admins. To change thresholds, edit the row in user_time_settings.
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>`;
      // One-by-one send so each recipient gets the email directly addressed
      // to them (some clients de-prioritise mail with multiple To: addresses).
      const results = await Promise.allSettled(recipients.map(to =>
        sgMail.send({ to, from: NOTIFY_EMAIL_FROM(), subject, html })
      ));
      const okCount = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected');
      sent.push(threshold.type);
      console.log('[notify/time]', threshold.type, '→', okCount, '/', recipients.length, 'super_admins (', totalHours.toFixed(1), 'hrs )');
      failed.forEach(f => {
        const detail = f.reason?.response?.body?.errors
          ? JSON.stringify(f.reason.response.body.errors)
          : (f.reason && f.reason.message);
        console.error('[notify/time] send error:', detail);
      });
    }

    // Fire any threshold the user has reached. maybeSend dedupes per
    // (user, month, alert_type) so re-running the sweep is safe.
    for (const t of thresholds) {
      if (totalHours >= t.hours) {
        await maybeSend(t);
      }
    }
    return { sent, totalHours };
  } catch (err) {
    console.error('[notify/time] checkAndSendTimeAlert error:', err.message);
    return { sent: [] };
  }
}

// ─── Review/approval workflow emails (Track F · review/approval) ─────────
//
// All four helpers share the same Alpha Surfaces template chrome and the same
// {to, subject, html} dispatch path. They look up email addresses from
// project_users by name (case-insensitive) — names come from the ticket's
// reviewers[] / approver / assigned_to fields. Failures are logged but never
// thrown; review/approval workflow continues even if SendGrid is down.

async function lookupEmailsByNames(pool, names) {
  if (!pool || !Array.isArray(names) || !names.length) return [];
  const cleaned = names.map(n => String(n || '').trim()).filter(Boolean);
  if (!cleaned.length) return [];
  // ILIKE matches both 'Jay' (first name) and 'Jana Zemanova' (full name) —
  // mirrors the existing ticketRoleFilter logic in projects-routes.js.
  const { rows } = await pool.query(
    `SELECT name, email FROM project_users
      WHERE active = TRUE
        AND (name = ANY($1::text[])
          OR LOWER(SPLIT_PART(name, ' ', 1)) = ANY(SELECT LOWER(unnest($1::text[]))))`,
    [cleaned]
  );
  return rows;
}

// Resolve a blocker name (free-text) to actual project_users rows. Used by
// the blocker-notice and blocker-nag emails so the addressee is the person
// being waited on, not a super_admin. Tries, in order:
//   1) exact case-insensitive match on full name
//   2) case-insensitive match on first token (e.g. 'Belinda' → 'Belinda Kelaher')
// Why: blocker_by is free-text and can be saved as 'belinda', 'Belinda',
// 'Belinda Kelaher' etc. The previous lookup was strict-case on full name
// and silently dropped these — emails fell through to super_admins only.
async function lookupBlockerEmails(pool, rawName) {
  if (!pool) return [];
  const name = String(rawName || '').trim();
  if (!name) return [];
  // Step 1: case-insensitive full-name match.
  let { rows } = await pool.query(
    `SELECT name, email FROM project_users
      WHERE active = TRUE AND LOWER(name) = LOWER($1)`,
    [name]
  );
  if (rows.length) return rows;
  // Step 2: partial — match by first token of either side. Lets 'Belinda'
  // resolve to 'Belinda Kelaher' and vice versa.
  const firstToken = name.split(/\s+/)[0];
  ({ rows } = await pool.query(
    `SELECT name, email FROM project_users
      WHERE active = TRUE
        AND (LOWER(SPLIT_PART(name, ' ', 1)) = LOWER($1)
          OR LOWER(name) LIKE LOWER($2))`,
    [firstToken, `${firstToken}%`]
  ));
  return rows;
}

function reviewEmailChrome({ headerLabel, headerColor, ticket, body, ctaUrl }) {
  const base = process.env.SITE_URL || 'https://alphasurfaces.com.au';
  const url  = ctaUrl || `${base}/projects?ticket=${encodeURIComponent(ticket.ticket_id)}`;
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f3f1e6;font-family:'Helvetica Neue',Arial,sans-serif">
<table cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#f3f1e6">
  <tr><td align="center" style="padding:48px 16px">
    <table cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:580px;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.06)">
      <tr><td style="background:${headerColor || '#564D22'};padding:24px 32px">
        <p style="margin:0;color:#fff;font-size:13px;letter-spacing:.12em;text-transform:uppercase;opacity:.85">Alpha Surfaces · Project Tracker</p>
        <h1 style="margin:6px 0 0;color:#fff;font-size:21px;font-weight:600">${escapeHtml(headerLabel)}</h1>
        <p style="margin:6px 0 0;color:#fff;font-size:14px;opacity:.9">${escapeHtml(ticket.ticket_id)} — ${escapeHtml(ticket.title)}</p>
      </td></tr>
      <tr><td style="padding:28px 32px;color:#222;font-size:15px;line-height:1.6">
        ${body}
        <p style="margin:24px 0 0">
          <a href="${escapeAttr(url)}" style="display:inline-block;background:#564D22;color:#fff;padding:11px 22px;text-decoration:none;font-size:13px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;border-radius:4px">
            Open ticket
          </a>
        </p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>`;
}

async function dispatchReviewEmails(recipients, subject, html) {
  if (!configureSendgrid()) {
    console.warn('[notify/review] SENDGRID_API_KEY not set — skipping review emails');
    return;
  }
  const from = NOTIFY_EMAIL_FROM();
  await Promise.all(recipients.map(async r => {
    if (!r || !r.email) return;
    try {
      await sgMail.send({ to: r.email, from, subject, html });
      console.log('[notify/review] sent to', r.email);
    } catch (err) {
      const detail = err.response?.body?.errors ? JSON.stringify(err.response.body.errors) : err.message;
      console.error('[notify/review] send error to', r.email, ':', detail);
    }
  }));
}

// Fired when a ticket enters 'pending_review'. Reviewers can leave advisory
// feedback or do nothing — the ticket auto-advances after 24h either way.
async function notifyReviewersRequested(pool, ticket, submitterName) {
  const reviewers = Array.isArray(ticket.reviewers) ? ticket.reviewers : [];
  if (!reviewers.length) return;
  const recipients = await lookupEmailsByNames(pool, reviewers);
  if (!recipients.length) {
    console.log('[notify/review] no reviewer emails resolved for', ticket.ticket_id);
    return;
  }
  const body = `
    <p style="margin:0 0 14px"><strong>${escapeHtml(submitterName || 'Someone')}</strong> has submitted this ticket for review.</p>
    ${ticket.description ? `<p style="margin:0 0 14px;color:#555;white-space:pre-wrap">${escapeHtml(ticket.description)}</p>` : ''}
    <p style="margin:0 0 14px;color:#555;font-size:13px">
      You are an <strong>advisory reviewer</strong>. Leave feedback if you want, or do nothing — this ticket
      will auto-advance to the approver after 24 hours.
    </p>
    ${ticket.approver ? `<p style="margin:0 0 14px;color:#555;font-size:13px">Final approver: <strong>${escapeHtml(ticket.approver)}</strong></p>` : ''}
  `;
  const subject = `[${ticket.ticket_id}] Ready for review — ${ticket.title}`;
  const html = reviewEmailChrome({ headerLabel: 'Ready for review', headerColor: '#564D22', ticket, body });
  await dispatchReviewEmails(recipients, subject, html);
}

// Fired when a ticket enters 'pending_approval' (after reviewer feedback or
// after the 24h auto-advance, or directly if no reviewers were set).
async function notifyApproverRequested(pool, ticket, reviewSummary) {
  if (!ticket.approver) return;
  const recipients = await lookupEmailsByNames(pool, [ticket.approver]);
  if (!recipients.length) {
    console.log('[notify/review] approver email not resolved for', ticket.approver);
    return;
  }
  const body = `
    <p style="margin:0 0 14px">This ticket is ready for your final approval.</p>
    ${ticket.description ? `<p style="margin:0 0 14px;color:#555;white-space:pre-wrap">${escapeHtml(ticket.description)}</p>` : ''}
    ${reviewSummary ? `<div style="margin:0 0 14px;padding:12px 14px;background:#f7f4e8;border-left:3px solid #564D22;font-size:13px;color:#444">
      <strong style="display:block;margin-bottom:6px">Reviewer feedback</strong>${reviewSummary}
    </div>` : ''}
    <p style="margin:0 0 14px;color:#555;font-size:13px">Approve to mark the ticket done, or request changes to send it back to the assignee.</p>
  `;
  const subject = `[${ticket.ticket_id}] Ready for approval — ${ticket.title}`;
  const html = reviewEmailChrome({ headerLabel: 'Ready for approval', headerColor: '#564D22', ticket, body });
  await dispatchReviewEmails(recipients, subject, html);
}

// Fired when the approver clicks Approve. Notifies the assignee, every active
// super_admin, and the ticket's reviewers.
async function notifyApproved(pool, ticket, approverName, approverFeedback) {
  const targets = new Set();
  if (ticket.assigned_to) targets.add(ticket.assigned_to);
  if (Array.isArray(ticket.reviewers)) ticket.reviewers.forEach(r => targets.add(r));
  // Super_admins by role — explicit listing keeps the "all super_admins" promise
  // honest even if names change.
  let superAdmins = [];
  try {
    const { rows } = await pool.query(
      `SELECT name, email FROM project_users WHERE active = TRUE AND role = 'super_admin'`
    );
    superAdmins = rows;
  } catch (err) {
    console.error('[notify/review] super_admin lookup error:', err.message);
  }
  const named = await lookupEmailsByNames(pool, [...targets]);
  // Dedupe by email — a reviewer who is also a super_admin should only get one mail.
  const byEmail = new Map();
  [...named, ...superAdmins].forEach(r => { if (r && r.email) byEmail.set(r.email.toLowerCase(), r); });
  const recipients = [...byEmail.values()];
  if (!recipients.length) return;
  const body = `
    <p style="margin:0 0 14px"><strong>${escapeHtml(approverName || ticket.approver || 'The approver')}</strong> has approved this ticket. It's now marked as done.</p>
    ${approverFeedback ? `<div style="margin:0 0 14px;padding:12px 14px;background:#eef5ee;border-left:3px solid #2e7d32;font-size:13px;color:#284428">${escapeHtml(approverFeedback)}</div>` : ''}
    ${ticket.assigned_to ? `<p style="margin:0 0 14px;color:#555">Assignee: <strong>${escapeHtml(ticket.assigned_to)}</strong></p>` : ''}
  `;
  const subject = `[${ticket.ticket_id}] Approved ✅ — ${ticket.title}`;
  const html = reviewEmailChrome({ headerLabel: 'Approved', headerColor: '#2e7d32', ticket, body });
  await dispatchReviewEmails(recipients, subject, html);
}

// Fired when the approver clicks "Request changes". Sends the assignee back
// to the work — feedback is mandatory in this case (validated server-side).
async function notifyChangesRequested(pool, ticket, approverName, feedback) {
  if (!ticket.assigned_to) return;
  const recipients = await lookupEmailsByNames(pool, [ticket.assigned_to]);
  if (!recipients.length) return;
  const body = `
    <p style="margin:0 0 14px"><strong>${escapeHtml(approverName || ticket.approver || 'The approver')}</strong> has requested changes on this ticket.</p>
    <div style="margin:0 0 14px;padding:12px 14px;background:#fbeee0;border-left:3px solid #b07020;font-size:14px;color:#5a3a10;white-space:pre-wrap">${escapeHtml(feedback || '(no feedback note)')}</div>
    <p style="margin:0 0 14px;color:#555;font-size:13px">The ticket is back in your queue. Address the feedback and move it to "Review" again to restart the cycle.</p>
  `;
  const subject = `[${ticket.ticket_id}] Changes requested — ${ticket.title}`;
  const html = reviewEmailChrome({ headerLabel: 'Changes requested', headerColor: '#b07020', ticket, body });
  await dispatchReviewEmails(recipients, subject, html);
}

// Fired when a reviewer leaves advisory feedback. Goes to the assignee so they
// can react during the review window — does NOT change the ticket status.
async function notifyReviewerFeedback(pool, ticket, reviewerName, feedback) {
  if (!ticket.assigned_to) return;
  const recipients = await lookupEmailsByNames(pool, [ticket.assigned_to]);
  if (!recipients.length) return;
  const body = `
    <p style="margin:0 0 14px"><strong>${escapeHtml(reviewerName || 'A reviewer')}</strong> left feedback on this ticket.</p>
    <div style="margin:0 0 14px;padding:12px 14px;background:#f7f4e8;border-left:3px solid #564D22;font-size:14px;color:#3a3320;white-space:pre-wrap">${escapeHtml(feedback || '(no note)')}</div>
    <p style="margin:0 0 14px;color:#555;font-size:13px">This is advisory — the ticket continues toward final approval.</p>
  `;
  const subject = `[${ticket.ticket_id}] Reviewer feedback from ${reviewerName || 'reviewer'}`;
  const html = reviewEmailChrome({ headerLabel: 'Reviewer feedback', headerColor: '#564D22', ticket, body });
  await dispatchReviewEmails(recipients, subject, html);
}

// ─── Blocker system + ticket status emails (Track B-Slim) ───────────────
//
// All three helpers reuse reviewEmailChrome for visual consistency with the
// review workflow, and resolve recipients dynamically from project_users so
// no hardcoded address list rots when team membership changes.

// Initial "you are blocking this ticket" email — fires the moment a blocker
// is set. CCs all super_admins so they have visibility from minute zero.
async function sendBlockerNotice(pool, ticket, flaggedByName) {
  if (!pool || !ticket || !ticket.blocked_by) return;
  const blockerRows = await lookupBlockerEmails(pool, ticket.blocked_by);
  const adminRows = await getSuperAdminEmails(pool);
  if (!blockerRows.length) {
    console.warn('[notify/blocker] could not resolve blocker name to user:', ticket.blocked_by, '— falling back to super_admins');
  }
  // Dedupe by lowercased email — admin who is also the blocker should
  // only get one mail.
  const byEmail = new Map();
  blockerRows.forEach(r => { if (r && r.email) byEmail.set(r.email.toLowerCase(), { email: r.email, primary: true }); });
  adminRows.forEach(e => {
    if (!e) return;
    const k = e.toLowerCase();
    if (!byEmail.has(k)) byEmail.set(k, { email: e, primary: false });
  });
  const recipients = [...byEmail.values()];
  if (!recipients.length) {
    console.log('[notify/blocker] no recipients resolved for', ticket.ticket_id);
    return;
  }
  const reason = ticket.blocked_reason ? `<div style="margin:0 0 14px;padding:12px 14px;background:#fdecea;border-left:3px solid #dc2626;font-size:14px;color:#5a1a1a;white-space:pre-wrap">${escapeHtml(ticket.blocked_reason)}</div>` : '';
  const body = `
    <p style="margin:0 0 14px"><strong>${escapeHtml(flaggedByName || 'Someone')}</strong> has flagged this ticket as blocked, waiting on <strong>${escapeHtml(ticket.blocked_by)}</strong>.</p>
    ${reason}
    ${ticket.assigned_to ? `<p style="margin:0 0 14px;color:#555">Assigned to: <strong>${escapeHtml(ticket.assigned_to)}</strong></p>` : ''}
    <p style="margin:0 0 14px;color:#555;font-size:13px">Please action this when you can. We'll send a reminder every 2 days while it stays blocked.</p>
  `;
  const subject = `⚠️ Action needed: [${ticket.ticket_id}] ${ticket.title} is waiting on you`;
  const html = reviewEmailChrome({ headerLabel: 'Action needed', headerColor: '#dc2626', ticket, body });
  await dispatchReviewEmails(recipients, subject, html);
}

// Cron-fired reminder. Goes TO the blocker (the person we're waiting on) with
// super_admins CC'd via additional sends. If we can't resolve the blocker name
// to a real user, we fall back to super_admins only and log a warning so the
// nag still surfaces somewhere.
async function sendBlockerNagEmail(pool, ticket) {
  if (!pool || !ticket || !ticket.blocked_by) return;
  const blockerRows = await lookupBlockerEmails(pool, ticket.blocked_by);
  const adminRows = await getSuperAdminEmails(pool);
  const byEmail = new Map();
  // Blocker first — they're the actual addressee.
  blockerRows.forEach(r => { if (r && r.email) byEmail.set(r.email.toLowerCase(), { email: r.email }); });
  if (!blockerRows.length) {
    console.warn('[notify/blocker-nag] could not resolve blocker name to user:', ticket.blocked_by, '— falling back to super_admins');
  }
  adminRows.forEach(e => { if (e) byEmail.set(e.toLowerCase(), { email: e }); });
  const recipients = [...byEmail.values()];
  if (!recipients.length) return;
  const blockedAt = ticket.blocked_at ? new Date(ticket.blocked_at) : null;
  const days = blockedAt ? Math.max(1, Math.ceil((Date.now() - blockedAt.getTime()) / 86400000)) : 1;
  const reason = ticket.blocked_reason ? `<div style="margin:0 0 14px;padding:12px 14px;background:#fdecea;border-left:3px solid #dc2626;font-size:14px;color:#5a1a1a;white-space:pre-wrap">${escapeHtml(ticket.blocked_reason)}</div>` : '';
  const body = `
    <p style="margin:0 0 14px">This ticket has been blocked for <strong>${days} day${days === 1 ? '' : 's'}</strong> waiting on <strong>${escapeHtml(ticket.blocked_by)}</strong>.</p>
    ${reason}
    ${ticket.assigned_to ? `<p style="margin:0 0 14px;color:#555">Assignee: <strong>${escapeHtml(ticket.assigned_to)}</strong></p>` : ''}
    <p style="margin:0 0 14px;color:#555;font-size:13px">Please action this or reply to let us know the timeline. We'll send another reminder in 2 days if it's still open.</p>
  `;
  const subject = `Reminder: [${ticket.ticket_id}] ${ticket.title} is still waiting on you`;
  const html = reviewEmailChrome({ headerLabel: `Blocked ${days} day${days === 1 ? '' : 's'}`, headerColor: '#dc2626', ticket, body });
  await dispatchReviewEmails(recipients, subject, html);
}

// Status-change broadcast. Goes to the assignee + every active super_admin,
// minus the actor (no self-notify) and deduped by email. Replaces the legacy
// single-recipient sendStatusChangeEmail in projects-routes.js.
async function sendTicketStatusEmail(pool, ticket, oldStatus, newStatus, actor) {
  if (!pool || !ticket) return;
  const actorEmail = (actor && actor.email ? String(actor.email).toLowerCase() : null);
  const targets = new Map();
  if (ticket.assigned_to) {
    const rows = await lookupEmailsByNames(pool, [ticket.assigned_to]);
    rows.forEach(r => { if (r && r.email) targets.set(r.email.toLowerCase(), { email: r.email }); });
  }
  const adminEmails = await getSuperAdminEmails(pool);
  adminEmails.forEach(e => { if (e) targets.set(e.toLowerCase(), { email: e }); });
  if (actorEmail) targets.delete(actorEmail);
  const recipients = [...targets.values()];
  if (!recipients.length) return;
  const isDone = newStatus === 'done';
  const headerColor = isDone ? '#2e7d32' : '#564D22';
  const headerLabel = isDone ? 'Completed' : `Moved to ${newStatus}`;
  const doneNote = isDone ? `<p style="margin:0 0 14px;color:#246426">✅ This ticket has been completed.</p>` : '';
  const body = `
    <p style="margin:0 0 14px"><strong>${escapeHtml((actor && actor.name) || 'Someone')}</strong> moved this ticket from <strong>${escapeHtml(oldStatus || '—')}</strong> to <strong>${escapeHtml(newStatus || '—')}</strong>.</p>
    ${doneNote}
    ${ticket.assigned_to ? `<p style="margin:0 0 14px;color:#555">Assigned to: <strong>${escapeHtml(ticket.assigned_to)}</strong></p>` : ''}
    ${ticket.priority ? `<p style="margin:0 0 14px;color:#555">Priority: <strong>${escapeHtml(ticket.priority)}</strong></p>` : ''}
  `;
  const subject = `[${ticket.ticket_id}] moved to ${newStatus} — ${ticket.title}`;
  const html = reviewEmailChrome({ headerLabel, headerColor, ticket, body });
  await dispatchReviewEmails(recipients, subject, html);
}

async function notifyNewSubmission(submission) {
  if (!submission) return;
  const results = await Promise.allSettled([
    sendSubmissionSMS(submission),
    sendSubmissionEmail(submission)
  ]);
  results.forEach((r, i) => {
    if (r.status === 'rejected') {
      console.error(`[notify] notifyNewSubmission [${i === 0 ? 'sms' : 'email'}] rejected:`, r.reason && r.reason.message);
    }
  });
}

// SMS body — must stay under 160 chars to land as a single segment.
function buildSubmissionSMSBody(s) {
  const formLabel = formatFormType(s.form_type);
  const name = s.name || [s.first_name, s.last_name].filter(Boolean).join(' ') || 'Anonymous';
  const phone = s.phone || 'No phone';
  const tail = s.stone_interest
    ? s.stone_interest
    : (s.message || '').slice(0, 30);
  const lines = [`🔔 Alpha Surfaces`, `New ${formLabel}`, `${name} · ${phone}`];
  if (tail) lines.push(tail);
  let body = lines.join('\n');
  if (body.length > 160) body = body.slice(0, 157) + '...';
  return body;
}

function formatFormType(t) {
  if (!t) return 'submission';
  // Existing DB values are e.g. "Sample Request", "Contact Enquiry" — keep
  // them as-is; for snake_case incoming ('sample_request') humanise.
  if (/[a-z]_[a-z]/.test(t)) {
    return t.split('_').map(w => w[0].toUpperCase() + w.slice(1)).join(' ');
  }
  return t;
}

function formatAEST(ts) {
  if (!ts) return '—';
  try {
    const d = new Date(ts);
    return d.toLocaleString('en-AU', {
      timeZone: 'Australia/Brisbane',
      day: 'numeric', month: 'long', year: 'numeric',
      hour: 'numeric', minute: '2-digit', hour12: true
    }).replace(/\s?(am|pm)/i, m => m.toLowerCase().trim()) + ' AEST';
  } catch { return String(ts); }
}

// HTML email — every populated column from form_submissions, grouped.
function buildSubmissionEmailHTML(s) {
  const groups = [
    { title: 'Enquiry Details', keys: [
      ['form_type',      'Form type',     v => formatFormType(v)],
      ['submitted_at',   'Submitted',     v => formatAEST(v)],
      ['source',         'Source'],
      ['reason',         'Reason'],
      ['status',         'Status']
    ]},
    { title: 'Contact Information', keys: [
      ['name',           'Name'],
      ['email',          'Email',         v => `<a href="mailto:${escapeAttr(v)}" style="color:#564D22">${escapeHtml(v)}</a>`],
      ['phone',          'Phone',         v => `<a href="tel:${escapeAttr(v)}" style="color:#564D22">${escapeHtml(v)}</a>`],
      ['company',        'Company'],
      ['role',           'Role / I am a']
    ]},
    { title: 'Address', keys: [
      ['unit',           'Unit / House no.'],
      ['street',         'Street'],
      ['suburb',         'Suburb'],
      ['postcode',       'Postcode'],
      ['state',          'State'],
      ['store_location', 'Store location']
    ]},
    { title: 'Request Details', keys: [
      ['stone_interest', 'Stone interest', v => formatStoneInterest(v)],
      ['message',        'Message',        v => escapeHtml(String(v)).replace(/\n/g, '<br>')],
      ['consent',        'Consent',        v => v ? '✓ Marketing consent given' : '— No marketing consent']
    ]}
  ];

  const knownKeys = new Set([
    'id','form_type','submitted_at','name','email','phone','company','role',
    'reason','unit','street','suburb','postcode','state','store_location',
    'stone_interest','message','source','consent','status','raw_data',
    // Warranty activation detail — rendered in its own group below instead of
    // being dumped into "Additional data" under raw snake_case keys. No other
    // form submits these, so every other form's email is unchanged.
    'batch_number','lot_number','application','coverage_type','warranty_type',
    'purchase_date','installation_date','fabricator','retailer','invoice_number',
    'installation_photos','photo_consent','stone_other'
  ]);

  const rowsOf = (src, entries) => entries.map(([key, label, formatter]) => {
    const val = src[key];
    if (val == null || val === '' || (typeof val === 'boolean' && key !== 'consent' && val === false)) return '';
    const formatted = formatter ? formatter(val) : escapeHtml(String(val));
    return `<tr>
      <td style="padding:10px 16px 10px 0;color:#777;font-size:13px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;width:160px;vertical-align:top">${escapeHtml(label)}</td>
      <td style="padding:10px 0;color:#222;font-size:15px;line-height:1.5;vertical-align:top">${formatted}</td>
    </tr>`;
  }).filter(Boolean).join('');
  const rows = (entries) => rowsOf(s, entries);

  const sections = groups.map(g => {
    const r = rows(g.keys);
    if (!r) return '';
    return `<tr><td style="padding:24px 32px 8px 32px">
      <h2 style="margin:0 0 8px;color:#564D22;font-size:14px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;border-bottom:1px solid #e8e3d3;padding-bottom:8px">${escapeHtml(g.title)}</h2>
      <table cellpadding="0" cellspacing="0" border="0" width="100%">${r}</table>
    </td></tr>`;
  }).filter(Boolean).join('');

  // Warranty activations carry product detail that form_submissions has no
  // dedicated columns for — it lives in raw_data. Given its own group so the
  // batch/lot numbers and the two dates read in order.
  let warrantySection = '';
  if (String(s.form_type || '') === 'Warranty Activation') {
    const rd = (s.raw_data && typeof s.raw_data === 'object') ? s.raw_data : {};
    const photos = Array.isArray(rd.installation_photos) ? rd.installation_photos : [];
    // House convention: DD/MM/YYYY customer-facing. These arrive as ISO from
    // the date inputs; anything unparseable is passed through untouched.
    const auDate = v => {
      const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(v || ''));
      return m ? `${m[3]}/${m[2]}/${m[1]}` : (v || '');
    };
    const w = {
      batch_number:      rd.batch_number || '',
      lot_number:        rd.lot_number   || '',
      application:       rd.application  || '',
      coverage_type:     rd.coverage_type || rd.warranty_type || '',
      purchase_date:     auDate(rd.purchase_date),
      installation_date: auDate(rd.installation_date),
      fabricator:        rd.fabricator || '',
      retailer:          rd.retailer || '',
      invoice_number:    rd.invoice_number || '',
      installation_photos: photos.length
        ? photos.map((u, i) => `<a href="${escapeAttr(u)}" style="color:#564D22">Photo ${i + 1}</a>`).join(' &middot; ')
        : 'None uploaded (optional)',
      photo_consent:     rd.photo_consent
        ? '\u2713 May be used on social media / marketing'
        : '\u2014 Not approved for social media use'
    };
    const wRows = rowsOf(w, [
      ['batch_number',       'Batch number'],
      ['lot_number',         'Lot number'],
      ['application',        'Application'],
      ['coverage_type',      'Warranty type'],
      ['purchase_date',      'Purchase date'],
      ['installation_date',  'Installation date'],
      ['fabricator',         'Fabricator / installer'],
      ['retailer',           'Retailer'],
      ['invoice_number',     'Invoice number'],
      ['installation_photos','Installation photos', v => v],
      ['photo_consent',      'Photo consent']
    ]);
    if (wRows) {
      warrantySection = `<tr><td style="padding:24px 32px 8px 32px">
        <h2 style="margin:0 0 8px;color:#564D22;font-size:14px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;border-bottom:1px solid #e8e3d3;padding-bottom:8px">Warranty Details</h2>
        <table cellpadding="0" cellspacing="0" border="0" width="100%">${wRows}</table>
      </td></tr>`;
    }
  }

  // Additional data — anything in raw_data not already in a known column,
  // and aliases like first_name/last_name that we already merged into `name`.
  let extraSection = '';
  if (s.raw_data && typeof s.raw_data === 'object') {
    const aliases = new Set(['first_name','last_name','i_am_a','i_am','type','enquiry_reason',
      'special_instructions','sampleItems','samples','stone_slug','stone_name','stone_collection']);
    const extras = Object.entries(s.raw_data).filter(([k, v]) => {
      if (knownKeys.has(k) || aliases.has(k)) return false;
      if (v == null || v === '') return false;
      if (Array.isArray(v) && v.length === 0) return false;
      return true;
    });
    if (extras.length) {
      const extraRows = extras.map(([k, v]) => {
        const disp = typeof v === 'object' ? JSON.stringify(v) : String(v);
        return `<tr>
          <td style="padding:10px 16px 10px 0;color:#777;font-size:13px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;width:160px;vertical-align:top">${escapeHtml(k)}</td>
          <td style="padding:10px 0;color:#222;font-size:15px;line-height:1.5;vertical-align:top">${escapeHtml(disp)}</td>
        </tr>`;
      }).join('');
      extraSection = `<tr><td style="padding:24px 32px 8px 32px">
        <h2 style="margin:0 0 8px;color:#564D22;font-size:14px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;border-bottom:1px solid #e8e3d3;padding-bottom:8px">Additional data</h2>
        <table cellpadding="0" cellspacing="0" border="0" width="100%">${extraRows}</table>
      </td></tr>`;
    }
  }

  const formsUrl = (process.env.SITE_URL || 'https://alphasurfaces.com.au') + '/forms';

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>New submission — Alpha Surfaces</title></head>
<body style="margin:0;padding:0;background:#f3f1e6;font-family:'Helvetica Neue',Arial,sans-serif">
<table cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#f3f1e6">
  <tr><td align="center" style="padding:32px 16px">
    <table cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:640px;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.06)">
      <tr><td style="background:#564D22;padding:28px 32px">
        <p style="margin:0;color:#f3f1e6;font-size:13px;letter-spacing:.12em;text-transform:uppercase">Alpha Surfaces</p>
        <h1 style="margin:6px 0 0;color:#fff;font-size:22px;font-weight:600">New ${escapeHtml(formatFormType(s.form_type))} #${s.id || ''}</h1>
      </td></tr>
      ${sections}${warrantySection}
      ${extraSection}
      <tr><td style="padding:24px 32px 32px 32px">
        <a href="${escapeAttr(formsUrl)}" style="display:inline-block;background:#564D22;color:#fff;padding:12px 24px;text-decoration:none;font-size:13px;letter-spacing:.06em;text-transform:uppercase;border-radius:4px">View in admin</a>
      </td></tr>
      <tr><td style="padding:20px 32px;background:#f7f4e8;color:#999;font-size:12px;text-align:center">
        This is an automated notification from alphasurfaces.com.au
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>`;
}

function formatStoneInterest(v) {
  if (!v) return '—';
  if (Array.isArray(v)) return v.map(escapeHtml).join(', ');
  return escapeHtml(String(v));
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function escapeAttr(s) { return escapeHtml(s); }

// ─── Customer confirmation emails ────────────────────────────────────────
//
// Transport is SendGrid, deliberately, and this is the first customer-facing
// mail in the app that uses it.
//
// The other candidate was the nodemailer/SMTP path that sends the newsletter
// welcome (sendEmailTo / getMailTransport above). That path is dead in this
// deployment: SMTP_USER, SMTP_PASS and SMTP_HOST are unset in BOTH the
// production and staging Railway environments, so getMailTransport() returns
// null and every send through it is skipped with a warning. The newsletter
// welcome has therefore never actually reached a subscriber. SendGrid, by
// contrast, delivered 266 of 266 attempts in August with one bounce, and is
// what already carries every staff notification. Building on the working
// transport is not a second mail stack — it is the only one.
//
// These are transactional service messages about something the person just
// did, not marketing, so they are NOT gated on the marketing consent checkbox
// and carry no unsubscribe link. Gating a "we received your request" receipt
// on a marketing opt-in would withhold it from exactly the people who ticked
// nothing, which is most of them.

function customerEmailChrome(heading, bodyHtml) {
  return `<!DOCTYPE html><html lang="en-AU"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(heading)} — Alpha Surfaces</title></head>
<body style="margin:0;padding:0;background:#f3f1e6;font-family:'Helvetica Neue',Arial,sans-serif">
<table cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#f3f1e6">
  <tr><td align="center" style="padding:48px 16px">
    <table cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:560px;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.06)">
      <tr><td style="background:#564D22;padding:28px 32px">
        <p style="margin:0;color:#f3f1e6;font-size:13px;letter-spacing:.12em;text-transform:uppercase">Alpha Surfaces</p>
        <h1 style="margin:6px 0 0;color:#fff;font-size:22px;font-weight:600">${escapeHtml(heading)}</h1>
      </td></tr>
      <tr><td style="padding:32px">${bodyHtml}</td></tr>
      <tr><td style="padding:20px 32px;background:#f7f4e8;color:#999;font-size:12px;line-height:1.6;text-align:center">
        Alpha Surfaces Pty Ltd &middot; ABN 21 677 729 350<br>
        13 Enterprise Street, Kunda Park QLD 4556<br>
        1300 257 420 &middot; info@alphasurfaces.com.au
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>`;
}

/** Recipient must be a real address — never hand SendGrid a blank or a typo. */
function validRecipient(email) {
  const v = String(email || '').trim();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) ? v : null;
}

function firstNameOf(submission) {
  const n = (submission && (submission.name || submission.first_name)) || '';
  const first = String(n).trim().split(/\s+/)[0];
  return first || null;
}

// Sample request — confirms receipt and lists the stones, because "your request
// has been received" without saying what was requested is not a receipt.
async function sendSampleConfirmationEmail(submission, sampleItems, reference) {
  const to = validRecipient(submission && submission.email);
  if (!to) { console.warn('[notify] sample confirmation skipped — no valid recipient'); return false; }
  if (!configureSendgrid()) {
    console.warn('[notify] SENDGRID_API_KEY not set — skipping sample confirmation');
    return false;
  }
  const first = firstNameOf(submission);
  const items = Array.isArray(sampleItems) ? sampleItems : [];
  const rows = items.map(i => {
    const qty = Math.max(1, parseInt(i && i.quantity, 10) || 1);
    const nm = escapeHtml((i && (i.name || i.slug)) || 'Sample');
    return `<li style="margin:0 0 6px">${nm}${qty > 1 ? ` <span style="color:#6b6759">&times; ${qty}</span>` : ''}</li>`;
  }).join('');
  const body = `
        <p style="margin:0 0 20px;color:#222;font-size:15px;line-height:1.6">${first ? `Hi ${escapeHtml(first)},` : 'Hello,'}</p>
        <p style="margin:0 0 20px;color:#222;font-size:15px;line-height:1.6">Thanks &mdash; we have your sample request.</p>
        ${rows ? `<p style="margin:0 0 8px;color:#222;font-size:15px;line-height:1.6">You asked for:</p>
        <ul style="margin:0 0 20px;padding-left:20px;color:#222;font-size:15px;line-height:1.6">${rows}</ul>` : ''}
        <p style="margin:0 0 20px;color:#222;font-size:15px;line-height:1.6">We will be in touch within 2&ndash;3 business days to confirm delivery.</p>
        ${reference ? `<p style="margin:0 0 20px;color:#6b6759;font-size:14px;line-height:1.6">Your reference is <strong style="color:#564D22">${escapeHtml(reference)}</strong>.</p>` : ''}
        <p style="margin:0;color:#6b6759;font-size:14px;line-height:1.6">If anything looks wrong, reply to this email or call us on 1300&nbsp;257&nbsp;420.</p>`;
  try {
    await sgMail.send({
      to,
      from: NOTIFY_EMAIL_FROM(),
      replyTo: NOTIFY_EMAIL_TO(),
      subject: 'We have your sample request — Alpha Surfaces',
      html: customerEmailChrome('Sample request received', body)
    });
    console.log('[notify] sample confirmation sent to', to, reference || '(no reference)');
    return true;
  } catch (err) {
    const detail = err.response?.body?.errors ? JSON.stringify(err.response.body.errors) : err.message;
    console.error('[notify] sample confirmation error:', detail);
    return false;
  }
}

// Warranty registration — the reference is the whole point. It is generated by
// insertTypedSubmission into warranty_activations as WA-NNNN and shown on screen
// once; without this email the customer has no durable copy of it. No new
// reference is minted here — if the typed insert did not return one, the receipt
// still goes out without that line rather than inventing a number that matches
// nothing in the database.
async function sendWarrantyConfirmationEmail(submission, reference) {
  const to = validRecipient(submission && submission.email);
  if (!to) { console.warn('[notify] warranty confirmation skipped — no valid recipient'); return false; }
  if (!configureSendgrid()) {
    console.warn('[notify] SENDGRID_API_KEY not set — skipping warranty confirmation');
    return false;
  }
  if (!reference) {
    console.warn('[notify] warranty confirmation has no WA- reference — sending receipt without it');
  }
  const first = firstNameOf(submission);
  const raw = (submission && submission.raw_data) || {};
  const stone = submission.stone_interest || raw.stone_name || '';
  const addr = [raw.street, raw.suburb, raw.state, raw.postcode].filter(Boolean).join(' ');
  const detail = [
    stone ? ['Stone', stone] : null,
    raw.batch_number ? ['Batch', raw.batch_number] : null,
    addr ? ['Installed at', addr] : null
  ].filter(Boolean).map(([k, v]) =>
    `<tr><td style="padding:4px 16px 4px 0;color:#6b6759;font-size:14px;vertical-align:top">${escapeHtml(k)}</td>` +
    `<td style="padding:4px 0;color:#222;font-size:14px">${escapeHtml(v)}</td></tr>`).join('');
  const body = `
        <p style="margin:0 0 20px;color:#222;font-size:15px;line-height:1.6">${first ? `Hi ${escapeHtml(first)},` : 'Hello,'}</p>
        <p style="margin:0 0 20px;color:#222;font-size:15px;line-height:1.6">Your Alpha Surfaces warranty registration has been received.</p>
        ${reference ? `<table cellpadding="0" cellspacing="0" border="0" style="margin:0 0 24px;background:#f7f4e8;border-radius:6px">
          <tr><td style="padding:16px 20px">
            <p style="margin:0 0 4px;color:#6b6759;font-size:12px;letter-spacing:.08em;text-transform:uppercase">Your reference</p>
            <p style="margin:0;color:#564D22;font-size:22px;font-weight:600;letter-spacing:.04em">${escapeHtml(reference)}</p>
          </td></tr></table>
        <p style="margin:0 0 20px;color:#222;font-size:15px;line-height:1.6">Keep this reference &mdash; quote it in any future warranty enquiry.</p>` : ''}
        ${detail ? `<table cellpadding="0" cellspacing="0" border="0" style="margin:0 0 24px">${detail}</table>` : ''}
        <p style="margin:0 0 20px;color:#222;font-size:15px;line-height:1.6">Nothing further is needed from you. We will be in touch if we have any questions about the registration.</p>
        <p style="margin:0;color:#6b6759;font-size:14px;line-height:1.6">If any detail is wrong, reply to this email or call us on 1300&nbsp;257&nbsp;420.</p>`;
  try {
    await sgMail.send({
      to,
      from: NOTIFY_EMAIL_FROM(),
      replyTo: NOTIFY_EMAIL_TO(),
      subject: reference
        ? `Warranty registered — ${reference} — Alpha Surfaces`
        : 'Warranty registration received — Alpha Surfaces',
      html: customerEmailChrome('Warranty registered', body)
    });
    console.log('[notify] warranty confirmation sent to', to, reference || '(no reference)');
    return true;
  } catch (err) {
    const d = err.response?.body?.errors ? JSON.stringify(err.response.body.errors) : err.message;
    console.error('[notify] warranty confirmation error:', d);
    return false;
  }
}

// Enquiry — the page promises a reply within 24 hours, so the receipt says the
// same thing. Echoes the reason and their own words back, because a receipt that
// doesn't say what was received is just an autoresponder. No reference is minted
// here; if the typed insert produced one it is shown, otherwise the line is
// omitted rather than inventing a number that matches nothing.
async function sendEnquiryConfirmationEmail(submission, reference) {
  const to = validRecipient(submission && submission.email);
  if (!to) { console.warn('[notify] enquiry confirmation skipped — no valid recipient'); return false; }
  if (!configureSendgrid()) {
    console.warn('[notify] SENDGRID_API_KEY not set — skipping enquiry confirmation');
    return false;
  }
  const first = firstNameOf(submission);
  const reason = (submission && submission.reason) || '';
  const message = (submission && submission.message) || '';
  const body = `
        <p style="margin:0 0 20px;color:#222;font-size:15px;line-height:1.6">${first ? `Hi ${escapeHtml(first)},` : 'Hello,'}</p>
        <p style="margin:0 0 20px;color:#222;font-size:15px;line-height:1.6">Thanks &mdash; we have your enquiry and will be in touch within 24 hours.</p>
        ${reason ? `<table cellpadding="0" cellspacing="0" border="0" style="margin:0 0 20px">
          <tr><td style="padding:4px 16px 4px 0;color:#6b6759;font-size:14px;vertical-align:top">Regarding</td>
              <td style="padding:4px 0;color:#222;font-size:14px">${escapeHtml(reason)}</td></tr></table>` : ''}
        ${message ? `<p style="margin:0 0 8px;color:#6b6759;font-size:13px;letter-spacing:.06em;text-transform:uppercase">Your message</p>
        <table cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 24px;background:#f7f4e8;border-radius:6px">
          <tr><td style="padding:16px 20px;color:#222;font-size:14px;line-height:1.6;white-space:pre-wrap">${escapeHtml(message)}</td></tr>
        </table>` : ''}
        ${reference ? `<p style="margin:0 0 20px;color:#6b6759;font-size:14px;line-height:1.6">Your reference is <strong style="color:#564D22">${escapeHtml(reference)}</strong>.</p>` : ''}
        <p style="margin:0;color:#6b6759;font-size:14px;line-height:1.6">If anything looks wrong, reply to this email or call us on 1300&nbsp;257&nbsp;420.</p>`;
  try {
    await sgMail.send({
      to,
      from: NOTIFY_EMAIL_FROM(),
      replyTo: NOTIFY_EMAIL_TO(),
      subject: 'We have your enquiry — Alpha Surfaces',
      html: customerEmailChrome('Enquiry received', body)
    });
    console.log('[notify] enquiry confirmation sent to', to, reference || '(no reference)');
    return true;
  } catch (err) {
    const d = err.response?.body?.errors ? JSON.stringify(err.response.body.errors) : err.message;
    console.error('[notify] enquiry confirmation error:', d);
    return false;
  }
}

function retiredNotifier(label) {
  console.log('[notify] suppressed — ' + label + ' (retired 2 Sep 2026)');
  return Promise.resolve({ sent: [], suppressed: true });
}

module.exports = {
  setSettingsPath,
  readSettings,
  writeSettings,
  notifyOrderSample,
  notifyContact,
  notifySubscribe,
  sendTestForForm,
  sendDailyDigest,
  generateWeeklyReport,
  isoWeekStringBrisbane,
  // New env-driven single-recipient path:
  sendSubmissionSMS,
  sendSubmissionEmail,
  notifyNewSubmission,
  // Customer-facing confirmations (SendGrid — see note above the definitions)
  sendSampleConfirmationEmail,
  sendWarrantyConfirmationEmail,
  sendEnquiryConfirmationEmail,
  sendFormsResetEmail,
  // Retired 2 Sep 2026 at client request. Stubbed at the export boundary so
  // no trigger path can reach a sender, whatever calls it. Hour logging from
  // commits is unaffected — only the alert email is suppressed.
  checkAndSendTimeAlert:    () => retiredNotifier('time cap alert'),
  notifyReviewersRequested: () => retiredNotifier('reviewers requested'),
  notifyApproverRequested:  () => retiredNotifier('approver requested'),
  notifyApproved:           () => retiredNotifier('approved'),
  notifyChangesRequested:   () => retiredNotifier('changes requested'),
  notifyReviewerFeedback:   () => retiredNotifier('reviewer feedback'),
  sendBlockerNotice:        () => retiredNotifier('blocker notice'),
  sendBlockerNagEmail:      () => retiredNotifier('blocker nag'),
  sendTicketStatusEmail:    () => retiredNotifier('ticket status')
};
