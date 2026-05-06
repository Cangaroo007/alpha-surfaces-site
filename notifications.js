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
    transport ? transport.sendMail({
      from: process.env.SMTP_USER,
      to: email,
      subject: 'Welcome to Alpha Surfaces',
      html: welcomeHtml,
      headers: {
        'List-Unsubscribe': `<${unsubUrl}>`,
        'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click'
      }
    }) : Promise.resolve()
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
    'stone_interest','message','source','consent','status','raw_data'
  ]);

  const rows = (entries) => entries.map(([key, label, formatter]) => {
    const val = s[key];
    if (val == null || val === '' || (typeof val === 'boolean' && key !== 'consent' && val === false)) return '';
    const formatted = formatter ? formatter(val) : escapeHtml(String(val));
    return `<tr>
      <td style="padding:10px 16px 10px 0;color:#777;font-size:13px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;width:160px;vertical-align:top">${escapeHtml(label)}</td>
      <td style="padding:10px 0;color:#222;font-size:15px;line-height:1.5;vertical-align:top">${formatted}</td>
    </tr>`;
  }).filter(Boolean).join('');

  const sections = groups.map(g => {
    const r = rows(g.keys);
    if (!r) return '';
    return `<tr><td style="padding:24px 32px 8px 32px">
      <h2 style="margin:0 0 8px;color:#564D22;font-size:14px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;border-bottom:1px solid #e8e3d3;padding-bottom:8px">${escapeHtml(g.title)}</h2>
      <table cellpadding="0" cellspacing="0" border="0" width="100%">${r}</table>
    </td></tr>`;
  }).filter(Boolean).join('');

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
      ${sections}
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

module.exports = {
  setSettingsPath,
  readSettings,
  writeSettings,
  notifyOrderSample,
  notifyContact,
  notifySubscribe,
  sendTestForForm,
  sendDailyDigest,
  // New env-driven single-recipient path:
  sendSubmissionSMS,
  sendSubmissionEmail,
  notifyNewSubmission,
  sendFormsResetEmail
};
