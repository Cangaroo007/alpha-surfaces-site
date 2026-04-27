'use strict';
const nodemailer = require('nodemailer');
const twilio     = require('twilio');
const crypto     = require('crypto');
function generateUnsubscribeUrl(email) {
  const secret = process.env.SESSION_SECRET || 'alpha-surfaces-secret';
  const token  = crypto.createHmac('sha256', secret).update(email.toLowerCase().trim()).digest('hex').substring(0, 16);
  const base   = process.env.SITE_URL || 'https://alphasurfaces.com.au';
  return `${base}/unsubscribe?email=${encodeURIComponent(email)}&token=${token}`;
}
function getSMSClient() {
  const sid = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  if (!sid || !token) return null;
  return twilio(sid, token);
}
async function sendSMS(body) {
  const client = getSMSClient();
  if (!client) { console.warn('[notify] Twilio not configured — skipping SMS'); return; }
  try {
    await client.messages.create({ body, from: process.env.TWILIO_FROM, to: process.env.TWILIO_TO });
    console.log('[notify] SMS sent');
  } catch (err) { console.error('[notify] SMS error:', err.message); }
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
async function sendEmail(subject, html) {
  const transport = getMailTransport();
  if (!transport) { console.warn('[notify] SMTP not configured — skipping email'); return; }
  try {
    await transport.sendMail({ from: process.env.SMTP_USER, to: process.env.ALERT_EMAIL_TO, subject, html });
    console.log('[notify] Email sent');
  } catch (err) { console.error('[notify] Email error:', err.message); }
}
async function notifyOrderSample(fields, sampleItems, id, submittedAt) {
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
  await Promise.all([
    sendSMS(sms),
    sendEmail(`New Sample Request — ${fields.first_name} ${fields.last_name} (${fields.state})`, html)
  ]);
}
async function notifyContact(fields, id, submittedAt) {
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
  await Promise.all([
    sendSMS(sms),
    sendEmail(`New Enquiry — ${fields.name}${fields.store_location ? ' via ' + fields.store_location : ''}`, html)
  ]);
}
async function notifySubscribe(email, id, submittedAt) {
  const unsubUrl = generateUnsubscribeUrl(email);
  const sms = `New Newsletter Signup #${id}\n${email}`;
  const html = `<h2 style="color:#564D22">New Newsletter Signup #${id}</h2><p><strong>Email:</strong> ${email}</p>`;
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
  const transport = getMailTransport();
  await Promise.all([
    sendSMS(sms),
    sendEmail('New Newsletter Signup — ' + email, html),
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
module.exports = { notifyOrderSample, notifyContact, notifySubscribe };
