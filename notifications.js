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
const crypto     = require('crypto');

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
async function sendTestForForm(formId) {
  const cfg = readSettings();
  const formLabel = (cfg && cfg.notifications && cfg.notifications[formId] && cfg.notifications[formId].label) || formId;
  const sms = `[TEST] Alpha Surfaces notification for "${formLabel}". If you got this, instant alerts are wired up.`;
  const subject = `[TEST] Alpha Surfaces — ${formLabel}`;
  const html = `<h2 style="color:#564D22">Test notification</h2>
    <p>This is a test from the Alpha Surfaces admin. Form: <strong>${formLabel}</strong>.</p>
    <p>If you got this, your instant alerts for this form are wired up correctly.</p>`;
  const smsRecipients   = getRecipients(formId, 'sms',   null);
  const emailRecipients = getRecipients(formId, 'email', null);
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

module.exports = {
  setSettingsPath,
  readSettings,
  writeSettings,
  notifyOrderSample,
  notifyContact,
  notifySubscribe,
  sendTestForForm,
  sendDailyDigest
};
