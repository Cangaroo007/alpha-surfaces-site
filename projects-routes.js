'use strict';

/**
 * Project ticketing system — self-contained route module.
 *
 * Mounted from server.js with `require('./projects-routes')(app, { pool, sessions, loginLimiter })`.
 * Owns its own migration, seed, session store, auth, CRUD, CSV export, stats,
 * activity log, user management, and optional ticket-status email.
 *
 * Required env vars:
 *   PROJECTS_PASSWORD - master fallback password (logs in as Admin pseudo-user)
 *   SENDGRID_API_KEY  - optional, enables status-change + reset emails
 *   NOTIFY_EMAIL_TO   - status-change recipient (default hello@alphasurfaces.com.au)
 *   NOTIFY_EMAIL_FROM - SendGrid verified sender (default noreply@alphasurfaces.com.au)
 *   SITE_URL          - used to build links in emails (default https://alphasurfaces.com.au)
 */

const express = require('express');
const crypto  = require('crypto');
const bcrypt  = require('bcryptjs');
const path    = require('path');

let sgMail = null;
try { sgMail = require('@sendgrid/mail'); } catch { /* email is optional */ }

// Time-tracking alert helper lives in notifications.js so it can share the
// SendGrid client + branded email template with the rest of the system.
let checkAndSendTimeAlert = null;
let notifyReviewersRequested = null;
let notifyApproverRequested  = null;
let notifyApproved           = null;
let notifyChangesRequested   = null;
let notifyReviewerFeedback   = null;
try {
  ({
    checkAndSendTimeAlert,
    notifyReviewersRequested,
    notifyApproverRequested,
    notifyApproved,
    notifyChangesRequested,
    notifyReviewerFeedback
  } = require('./notifications'));
}
catch { /* notifications module is optional in tests */ }

// Cloudinary is configured globally in server.js. We re-require the singleton
// here for ticket attachment uploads — config persists across the require
// boundary, so this is safe.
let cloudinary = null;
try { cloudinary = require('cloudinary').v2; } catch { /* optional in tests */ }
let multer = null;
try { multer = require('multer'); } catch { /* optional in tests */ }

// ─── Static config ────────────────────────────────────────────────────────
const ALLOWED_STATUSES   = ['backlog', 'in_progress', 'review', 'done', 'archived'];
const ALLOWED_PRIORITIES = ['high', 'medium', 'low'];
const ALLOWED_CATEGORIES = ['website','content','integration','consulting','showroom','print','process','meeting','feature'];
// Role hierarchy:
//   super_admin → full access (tickets, forms, /admin CMS, user management)
//   operator    → assigned tickets only + full forms access (no CMS, no users)
//   viewer      → assigned tickets only, read-only, no forms
const ALLOWED_ROLES      = ['super_admin', 'operator', 'viewer'];

const UPDATABLE_TICKET_COLS = [
  'title','description','category','priority','status',
  'assigned_to','requested_by','due_date','source',
  'reviewers','approver'
  // 'notes' is NOT in this list — notes are append-only via dedicated endpoint
  // 'approval_status' is set by status transitions and the review endpoint, not by users
];
const TRACKED_COLS = ['title','description','category','priority','status','assigned_to','requested_by','due_date','reviewers','approver'];

// Defaults for new tickets — Jay + Jana review (advisory), Belinda approves
// (blocking). Creators can override or clear per ticket.
const DEFAULT_REVIEWERS = ['Jay', 'Jana'];
const DEFAULT_APPROVER  = 'Belinda';
// 24h after entering pending_review, the ticket auto-advances to the approver
// even if no reviewer left feedback. Reviewers are advisory, not blocking.
const REVIEW_AUTO_ADVANCE_MS = 24 * 60 * 60 * 1000;

const DEFAULT_USER_PASSWORD = 'AlphaSurfaces2026';

// ─── Seed data ────────────────────────────────────────────────────────────
const SEED_TICKETS = [
  { title: 'Include Jay, Jana & Belinda on all email comms', category: 'process', priority: 'high', status: 'in_progress', requested_by: 'Belinda', assigned_to: 'Sean', source: 'client_email', description: 'All project communication to include Jay, Jana, and Belinda. Belinda will forward to relevant team members.' },
  { title: 'CMS & website training session', category: 'meeting', priority: 'medium', status: 'backlog', requested_by: 'Belinda', assigned_to: 'Sean', source: 'client_email', description: 'Training for Jay, Jana, Jess & Belinda on the website CMS. Sean to propose available times.' },
  { title: 'Pipedrive → Odoo recommendation', category: 'consulting', priority: 'medium', status: 'backlog', requested_by: 'Belinda', assigned_to: 'Sean', source: 'client_email', description: 'Provide feedback and recommendation on Pipedrive and transition to Odoo.' },
  { title: 'Social links on website', category: 'integration', priority: 'high', status: 'backlog', requested_by: 'Belinda', assigned_to: 'Sean', source: 'client_email', description: 'Sam Southam has emailed about connecting Instagram/Facebook links to website. Waiting on Sean availability.' },
  { title: 'Centerhouse Media social strategy meeting', category: 'meeting', priority: 'medium', status: 'backlog', requested_by: 'Belinda', assigned_to: 'Sean', source: 'client_email', description: 'Meeting with Sam from Centerhouse Media — Friday 10:30am EST re social strategy. Can be moved to next week.' },
  { title: 'Showroom iPad links', category: 'showroom', priority: 'high', status: 'backlog', requested_by: 'Jess', assigned_to: 'Sean', source: 'client_email', description: 'See email from Jess with requirements for iPad display links in the showroom.' },
  { title: 'QR codes for Bondi & Viola Ligera', category: 'print', priority: 'medium', status: 'backlog', requested_by: 'Belinda', assigned_to: 'Sean', source: 'client_email', description: 'Generate QR codes for two missing stone colours.' },
  { title: 'Upload updated fabrication manual PDF', category: 'content', priority: 'high', status: 'backlog', requested_by: 'Belinda', assigned_to: 'Sean', source: 'client_email', description: 'Replace current fabrication manual PDF on the site with updated version from Belinda.' },
  { title: 'Fix Carrara kitchen image on collections page', category: 'content', priority: 'high', status: 'backlog', requested_by: 'Belinda', assigned_to: 'Sean', source: 'client_email', description: 'Green kitchen labelled Carrara at bottom of collections page shows wrong image. Replace with correct Carrara kitchen from Figma.' },
  { title: 'Build enquiry web form', category: 'feature', priority: 'medium', status: 'backlog', requested_by: 'Belinda', assigned_to: 'Sean', source: 'client_email', description: 'New general enquiry form for the website.' },
  { title: 'Build warranty activation form', category: 'feature', priority: 'medium', status: 'backlog', requested_by: 'Belinda', assigned_to: 'Sean', source: 'client_email', description: 'New form for customers to activate their product warranty after purchase/installation.' },
  { title: 'Brochure FlippingBook animation + upload', category: 'content', priority: 'medium', status: 'backlog', requested_by: 'Belinda', assigned_to: 'Sean', source: 'client_email', description: 'Animate the brochure in FlippingBook and embed on the website.' },
  { title: 'SMS notifications on form submission', category: 'feature', priority: 'high', status: 'done', requested_by: 'Sean', assigned_to: 'Sean', source: 'internal', description: 'Twilio SMS to +61417764689 on every form submission.' },
  { title: 'Email notifications on form submission', category: 'feature', priority: 'high', status: 'done', requested_by: 'Sean', assigned_to: 'Sean', source: 'internal', description: 'SendGrid email with all columns to hello@alphasurfaces.com.au on every form submission.' },
  { title: 'Forms-only login portal at /forms', category: 'feature', priority: 'high', status: 'done', requested_by: 'Sean', assigned_to: 'Sean', source: 'internal', description: 'Separate login for viewing/managing form submissions without admin access.' }
];

// NOTE: Pam is seeded with pam@thisisikon.com.au — flip to pam@alphasurfaces.com.au
// once we've actually confirmed the address with her. Until then leave it
// to avoid silently locking her out.
const SEED_USERS = [
  { email: 'sean@cangaroo.ai',                name: 'Sean Stone',      role: 'super_admin' },
  { email: 'belinda@alphasurfaces.com.au',    name: 'Belinda Kelaher', role: 'super_admin' },
  { email: 'jay@alphasurfaces.com.au',        name: 'Jay',             role: 'super_admin' },
  { email: 'jana@northcoaststone.com.au',     name: 'Jana Zemanova',   role: 'super_admin' },
  { email: 'hello@alphasurfaces.com.au',      name: 'Jess Connelly',   role: 'operator' },
  { email: 'sam@alphasurfaces.com.au',        name: 'Sam Southam',     role: 'operator' },
  { email: 'pam@thisisikon.com.au',           name: 'Pam',             role: 'operator' }
];

// One-time role + active flag re-mapping for production rows that predate the
// role overhaul. Idempotent: each query is a no-op once the data already
// matches. Kate's row is deactivated rather than deleted so we keep her
// activity-log attribution.
const ROLE_REMAP_SUPER_ADMIN = [
  'sean@cangaroo.ai',
  'belinda@alphasurfaces.com.au',
  'jay@alphasurfaces.com.au',
  'jana@northcoaststone.com.au'
];
const ROLE_REMAP_OPERATOR = [
  'hello@alphasurfaces.com.au',
  'sam@alphasurfaces.com.au',
  'pam@alphasurfaces.com.au',
  'pam@thisisikon.com.au'
];
const DEACTIVATE_EMAILS = ['kate@thisisikon.com.au'];

// ─── DB migration + seed ──────────────────────────────────────────────────
async function initSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tickets (
      id            SERIAL PRIMARY KEY,
      ticket_id     VARCHAR(10) UNIQUE NOT NULL,
      title         VARCHAR(255) NOT NULL,
      description   TEXT,
      category      VARCHAR(50),
      priority      VARCHAR(10) DEFAULT 'medium',
      status        VARCHAR(20) DEFAULT 'backlog',
      assigned_to   VARCHAR(100),
      requested_by  VARCHAR(100),
      created_at    TIMESTAMPTZ DEFAULT NOW(),
      updated_at    TIMESTAMPTZ DEFAULT NOW(),
      due_date      DATE,
      notes         TEXT,
      source        VARCHAR(100)
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_tickets_status   ON tickets(status)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_tickets_priority ON tickets(priority)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_tickets_assigned ON tickets(assigned_to)`);

  // Track C/F: review + approval workflow columns. Idempotent — each column is
  // ADD COLUMN IF NOT EXISTS. reviewers is a text array so a single ticket can
  // route to multiple advisory reviewers (Jay + Jana by default); approver is a
  // single name (Belinda by default) and is the only blocking sign-off.
  // approval_status: NULL (not in review), 'pending_review', 'pending_approval',
  // 'approved', 'changes_requested'.
  await pool.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS reviewers       TEXT[] DEFAULT '{}'`);
  await pool.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS approver        VARCHAR(100)`);
  await pool.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS approval_status VARCHAR(20)`);
  await pool.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS review_started_at TIMESTAMPTZ`);

  // Per-action audit trail for review cycles. Captures both reviewer notes
  // (advisory) and approver decisions (binding). One row per action — multiple
  // rounds of changes_requested produce multiple rows so the full history is
  // preserved.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ticket_reviews (
      id            SERIAL PRIMARY KEY,
      ticket_id     VARCHAR(10) NOT NULL REFERENCES tickets(ticket_id) ON DELETE CASCADE,
      reviewer_id   INTEGER REFERENCES project_users(id) ON DELETE SET NULL,
      reviewer_name VARCHAR(100) NOT NULL,
      action        VARCHAR(20) NOT NULL,
      feedback      TEXT,
      role          VARCHAR(20) NOT NULL,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_reviews_ticket ON ticket_reviews(ticket_id)`);

  // File attachments on tickets. Files are uploaded to Cloudinary (already
  // configured in server.js) and only the URL is stored here. context lets
  // us distinguish a casual drag-drop ('general') from a file attached
  // alongside a review note ('review_feedback') or pulled in from inbound
  // email ('email_import', wired in Track C).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ticket_attachments (
      id          SERIAL PRIMARY KEY,
      ticket_id   VARCHAR(10) NOT NULL REFERENCES tickets(ticket_id) ON DELETE CASCADE,
      user_id     INTEGER REFERENCES project_users(id) ON DELETE SET NULL,
      user_name   VARCHAR(100) NOT NULL,
      filename    VARCHAR(255) NOT NULL,
      url         TEXT NOT NULL,
      mime_type   VARCHAR(100),
      size_bytes  INTEGER,
      context     VARCHAR(30) DEFAULT 'general',
      created_at  TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_attachments_ticket ON ticket_attachments(ticket_id)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS project_users (
      id                   SERIAL PRIMARY KEY,
      email                VARCHAR(255) UNIQUE NOT NULL,
      name                 VARCHAR(100) NOT NULL,
      role                 VARCHAR(20)  DEFAULT 'member',
      password_hash        VARCHAR(255) NOT NULL,
      last_login           TIMESTAMPTZ,
      created_at           TIMESTAMPTZ DEFAULT NOW(),
      active               BOOLEAN      DEFAULT TRUE,
      must_change_password BOOLEAN      DEFAULT TRUE
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_email ON project_users(LOWER(email))`);
  // Backfill the flag on existing production DBs that were created before
  // Track G — every existing seeded user is on the shared default password.
  await pool.query(
    `ALTER TABLE project_users
       ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT TRUE`
  );

  // Role overhaul: re-map legacy roles (admin/member/viewer) to the new
  // hierarchy. Idempotent — once rows match the new values, these UPDATEs
  // change nothing.
  await pool.query(
    `UPDATE project_users SET role = 'super_admin'
      WHERE role <> 'super_admin' AND LOWER(email) = ANY($1::text[])`,
    [ROLE_REMAP_SUPER_ADMIN]
  );
  await pool.query(
    `UPDATE project_users SET role = 'operator'
      WHERE role <> 'operator' AND LOWER(email) = ANY($1::text[])`,
    [ROLE_REMAP_OPERATOR]
  );
  await pool.query(
    `UPDATE project_users SET active = FALSE
      WHERE active = TRUE AND LOWER(email) = ANY($1::text[])`,
    [DEACTIVATE_EMAILS]
  );

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ticket_activity (
      id          SERIAL PRIMARY KEY,
      ticket_id   VARCHAR(10) NOT NULL REFERENCES tickets(ticket_id) ON DELETE CASCADE,
      user_id     INTEGER REFERENCES project_users(id) ON DELETE SET NULL,
      user_name   VARCHAR(100) NOT NULL,
      action      VARCHAR(50)  NOT NULL,
      detail      TEXT,
      created_at  TIMESTAMPTZ  DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_activity_ticket ON ticket_activity(ticket_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_activity_user   ON ticket_activity(user_id)`);

  // Audit trail for form submissions — who changed status, who exported, etc.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS form_activity (
      id            SERIAL PRIMARY KEY,
      submission_id INTEGER NOT NULL,
      user_id       INTEGER REFERENCES project_users(id) ON DELETE SET NULL,
      user_name     VARCHAR(100) NOT NULL,
      action        VARCHAR(50)  NOT NULL,
      detail        TEXT,
      created_at    TIMESTAMPTZ  DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_form_activity_submission ON form_activity(submission_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_form_activity_user       ON form_activity(user_id)`);

  // ── Time tracking (Track F) ────────────────────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS time_entries (
      id          SERIAL PRIMARY KEY,
      ticket_id   VARCHAR(10) REFERENCES tickets(ticket_id) ON DELETE CASCADE,
      user_id     INTEGER NOT NULL REFERENCES project_users(id) ON DELETE CASCADE,
      date        DATE NOT NULL DEFAULT CURRENT_DATE,
      minutes     INTEGER NOT NULL CHECK (minutes > 0),
      description TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_time_user   ON time_entries(user_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_time_ticket ON time_entries(ticket_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_time_date   ON time_entries(date)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_time_settings (
      id                SERIAL PRIMARY KEY,
      user_id           INTEGER UNIQUE NOT NULL REFERENCES project_users(id) ON DELETE CASCADE,
      monthly_hours_cap INTEGER DEFAULT 20,
      warning_hours     INTEGER DEFAULT 15,
      alert_email       VARCHAR(255) DEFAULT 'belinda@alphasurfaces.com.au'
    )
  `);

  // Per (user, month, alert_type) row — UNIQUE prevents the alert from
  // re-firing once it's been sent for the month.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS time_alerts (
      id          SERIAL PRIMARY KEY,
      user_id     INTEGER NOT NULL REFERENCES project_users(id) ON DELETE CASCADE,
      month       VARCHAR(7) NOT NULL,
      alert_type  VARCHAR(30) NOT NULL,
      sent_at     TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (user_id, month, alert_type)
    )
  `);

  // Seed Sean's allocation. Idempotent — ON CONFLICT keeps any manual
  // overrides intact.
  await pool.query(
    `INSERT INTO user_time_settings (user_id, monthly_hours_cap, warning_hours, alert_email)
     SELECT id, 20, 15, 'belinda@alphasurfaces.com.au'
       FROM project_users WHERE LOWER(email) = 'sean@cangaroo.ai'
     ON CONFLICT (user_id) DO NOTHING`
  );

  // Idempotent May 2026 backfill — populate Sean's first-month effort only
  // when he has zero May entries already. Avoids double-seeding on redeploy.
  const seanRow = await pool.query(
    `SELECT id FROM project_users WHERE LOWER(email) = 'sean@cangaroo.ai' LIMIT 1`
  );
  if (seanRow.rows.length) {
    const seanId = seanRow.rows[0].id;
    const mayCount = await pool.query(
      `SELECT COUNT(*)::int AS c FROM time_entries
        WHERE user_id = $1 AND date >= '2026-05-01' AND date < '2026-06-01'`,
      [seanId]
    );
    if (mayCount.rows[0].c === 0) {
      const MAY_TIME_SEED = [
        { date: '2026-05-01', minutes: 120, desc: 'Infrastructure planning, Railway setup' },
        { date: '2026-05-02', minutes:  90, desc: 'Twilio/SendGrid notification architecture' },
        { date: '2026-05-03', minutes:  60, desc: 'SendGrid DNS authentication via Cloudflare' },
        { date: '2026-05-04', minutes:  90, desc: 'Postgres provisioning, form handler integration' },
        { date: '2026-05-05', minutes:  60, desc: 'Stakeholder alignment, email comms' },
        { date: '2026-05-06', minutes: 120, desc: 'SMS+email notifications build, forms portal' },
        { date: '2026-05-07', minutes: 240, desc: 'Project tracker build, user logins, Kanban, time tracking, activity log' },
      ];
      for (const e of MAY_TIME_SEED) {
        await pool.query(
          `INSERT INTO time_entries (ticket_id, user_id, date, minutes, description)
           VALUES (NULL, $1, $2, $3, $4)`,
          [seanId, e.date, e.minutes, e.desc]
        );
      }
      const totalHrs = MAY_TIME_SEED.reduce((s, e) => s + e.minutes, 0) / 60;
      console.log(`[projects/time] seeded May 2026 — ${totalHrs} hours for Sean`);
    }
  }

  // Seed tickets — only when table is empty.
  const tk = await pool.query('SELECT COUNT(*)::int AS c FROM tickets');
  if (tk.rows[0].c === 0 && SEED_TICKETS.length) {
    for (let i = 0; i < SEED_TICKETS.length; i++) {
      const t = SEED_TICKETS[i];
      const ticketId = formatTicketId(i + 1);
      await pool.query(
        `INSERT INTO tickets
           (ticket_id, title, description, category, priority, status,
            assigned_to, requested_by, source)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [ticketId, t.title, t.description || null, t.category || null,
         t.priority || 'medium', t.status || 'backlog',
         t.assigned_to || null, t.requested_by || null, t.source || null]
      );
    }
    console.log(`[projects] seeded ${SEED_TICKETS.length} tickets`);
  }

  // Seed users — only when table is empty. All start with the same default
  // password so members can sign in once and change it from the UI.
  const u = await pool.query('SELECT COUNT(*)::int AS c FROM project_users');
  if (u.rows[0].c === 0 && SEED_USERS.length) {
    const hash = await bcrypt.hash(DEFAULT_USER_PASSWORD, 10);
    for (const su of SEED_USERS) {
      await pool.query(
        `INSERT INTO project_users (email, name, role, password_hash, must_change_password)
         VALUES (LOWER($1), $2, $3, $4, TRUE)
         ON CONFLICT (email) DO NOTHING`,
        [su.email, su.name, su.role, hash]
      );
    }
    console.log(`[projects] seeded ${SEED_USERS.length} users (default password: ${DEFAULT_USER_PASSWORD})`);
  }
}

function formatTicketId(n) { return 'AS-' + String(n).padStart(3, '0'); }
async function nextTicketId(pool) {
  const { rows } = await pool.query(
    `SELECT ticket_id FROM tickets WHERE ticket_id ~ '^AS-[0-9]+$'
     ORDER BY CAST(SUBSTRING(ticket_id FROM 4) AS INTEGER) DESC LIMIT 1`
  );
  if (!rows.length) return formatTicketId(1);
  const last = parseInt(rows[0].ticket_id.slice(3), 10);
  return formatTicketId(last + 1);
}

function initialsFromName(name) {
  return String(name || '').trim().split(/\s+/).map(w => w[0] || '').join('').slice(0, 2).toUpperCase();
}
function nowAEST() {
  return new Date().toLocaleString('en-AU', {
    timeZone: 'Australia/Brisbane',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false
  }).replace(/(\d+)\/(\d+)\/(\d+),?\s*/, '$3-$2-$1 ') + ' AEST';
}

// ─── SendGrid email helpers ───────────────────────────────────────────────
let sendgridReady = false;
function ensureSendgrid() {
  if (sendgridReady) return true;
  if (!sgMail || !process.env.SENDGRID_API_KEY) return false;
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  sendgridReady = true;
  return true;
}
async function sendStatusChangeEmail(ticket, oldStatus, newStatus, actorName) {
  if (!ensureSendgrid()) return;
  const to   = process.env.NOTIFY_EMAIL_TO   || 'hello@alphasurfaces.com.au';
  const from = process.env.NOTIFY_EMAIL_FROM || 'noreply@alphasurfaces.com.au';
  const base = process.env.SITE_URL          || 'https://alphasurfaces.com.au';
  const url  = `${base}/projects`;
  const html = `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#f3f1e6;font-family:'Helvetica Neue',Arial,sans-serif">
<table cellpadding="0" cellspacing="0" width="100%" style="background:#f3f1e6"><tr><td align="center" style="padding:32px 16px">
  <table cellpadding="0" cellspacing="0" width="100%" style="max-width:560px;background:#fff;border-radius:8px;overflow:hidden">
    <tr><td style="background:#564D22;padding:24px 28px">
      <p style="margin:0;color:#f3f1e6;font-size:12px;letter-spacing:.12em;text-transform:uppercase">Alpha Surfaces · Project Tracker</p>
      <h1 style="margin:6px 0 0;color:#fff;font-size:20px;font-weight:600">${esc(ticket.ticket_id)} — ${esc(ticket.title)}</h1>
    </td></tr>
    <tr><td style="padding:24px 28px;color:#222;font-size:15px;line-height:1.6">
      <p style="margin:0 0 14px"><strong>${esc(actorName || 'Someone')}</strong> changed status <strong>${esc(oldStatus)}</strong> → <strong>${esc(newStatus)}</strong>.</p>
      ${ticket.assigned_to ? `<p style="margin:0 0 14px;color:#555">Assigned to: <strong>${esc(ticket.assigned_to)}</strong></p>` : ''}
      ${ticket.priority ? `<p style="margin:0 0 14px;color:#555">Priority: <strong>${esc(ticket.priority)}</strong></p>` : ''}
      <p style="margin:24px 0 0"><a href="${esc(url)}" style="display:inline-block;background:#564D22;color:#fff;padding:11px 22px;text-decoration:none;font-size:13px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;border-radius:4px">Open project tracker</a></p>
    </td></tr>
  </table>
</td></tr></table>
</body></html>`;
  try {
    await sgMail.send({
      to, from,
      subject: `[${ticket.ticket_id}] Status changed to ${newStatus} — ${ticket.title}`,
      html
    });
  } catch (err) {
    const detail = err.response?.body?.errors ? JSON.stringify(err.response.body.errors) : err.message;
    console.error('[projects] status email error:', detail);
  }
}
async function sendPasswordResetEmail(toEmail, name, resetUrl) {
  if (!ensureSendgrid()) return false;
  const from = process.env.NOTIFY_EMAIL_FROM || 'noreply@alphasurfaces.com.au';
  const html = `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#f3f1e6;font-family:'Helvetica Neue',Arial,sans-serif">
<table cellpadding="0" cellspacing="0" width="100%" style="background:#f3f1e6"><tr><td align="center" style="padding:48px 16px">
  <table cellpadding="0" cellspacing="0" width="100%" style="max-width:560px;background:#fff;border-radius:8px;overflow:hidden">
    <tr><td style="background:#564D22;padding:28px 32px">
      <p style="margin:0;color:#f3f1e6;font-size:12px;letter-spacing:.12em;text-transform:uppercase">Alpha Surfaces · Project Tracker</p>
      <h1 style="margin:6px 0 0;color:#fff;font-size:22px;font-weight:600">Password reset</h1>
    </td></tr>
    <tr><td style="padding:32px;color:#222;font-size:15px;line-height:1.6">
      <p style="margin:0 0 18px">Hi ${esc(name || 'there')},</p>
      <p style="margin:0 0 18px">Click the button below to set a new password for the project tracker. This link expires in 1 hour and can only be used once.</p>
      <p style="margin:0 0 24px"><a href="${esc(resetUrl)}" style="display:inline-block;background:#564D22;color:#fff;padding:13px 26px;text-decoration:none;font-size:14px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;border-radius:4px">Reset password</a></p>
      <p style="margin:0 0 8px;color:#777;font-size:13px">Or paste this link into your browser:</p>
      <p style="margin:0 0 24px;color:#564D22;font-size:13px;word-break:break-all">${esc(resetUrl)}</p>
      <p style="margin:0;color:#999;font-size:13px">If you didn't request this, you can ignore this email.</p>
    </td></tr>
  </table>
</td></tr></table>
</body></html>`;
  try {
    await sgMail.send({
      to: toEmail,
      from,
      subject: 'Alpha Surfaces — Project Tracker password reset',
      html
    });
    return true;
  } catch (err) {
    const detail = err.response?.body?.errors ? JSON.stringify(err.response.body.errors) : err.message;
    console.error('[projects] reset email error:', detail);
    return false;
  }
}

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ─── Activity logging ─────────────────────────────────────────────────────
async function logActivity(pool, ticketId, user, action, detail) {
  try {
    await pool.query(
      `INSERT INTO ticket_activity (ticket_id, user_id, user_name, action, detail)
       VALUES ($1, $2, $3, $4, $5)`,
      [ticketId, user.userId || null, user.name || 'Unknown', action, detail || null]
    );
  } catch (err) {
    // Activity log failure should never break the underlying CRUD action.
    console.error('[projects] activity log error:', err.message);
  }
}

function describeFieldChange(col, oldVal, newVal) {
  const labelMap = {
    status: 'Status', priority: 'Priority', assigned_to: 'Assigned',
    title: 'Title', description: 'Description', due_date: 'Due date',
    requested_by: 'Requested by', category: 'Category',
    reviewers: 'Reviewers', approver: 'Approver'
  };
  const label = labelMap[col] || col;
  // Long fields (description) — collapse to "Updated description"
  if (col === 'description' || col === 'title') {
    return { action: 'edited', detail: `Updated ${label.toLowerCase()}` };
  }
  const fmt = (v) => {
    if (v == null || v === '') return '—';
    if (Array.isArray(v)) return v.length ? v.join(', ') : '—';
    return String(v);
  };
  const before = fmt(oldVal);
  const after  = fmt(newVal);
  let action = 'edited';
  if (col === 'status') action = 'status_changed';
  else if (col === 'priority') action = 'priority_changed';
  else if (col === 'assigned_to') action = 'assigned';
  else if (col === 'reviewers' || col === 'approver') action = 'review_routing_changed';
  return { action, detail: `${label}: ${before} → ${after}` };
}

// Normalise the reviewers field — accepts an array, comma-separated string, or
// null. Returns a clean string array (deduped, trimmed) or null when the
// caller wants to clear it.
function normaliseReviewers(input) {
  if (input == null) return [];
  let arr = input;
  if (typeof input === 'string') {
    arr = input.split(',');
  }
  if (!Array.isArray(arr)) return [];
  const seen = new Set();
  const out = [];
  for (const v of arr) {
    const s = String(v || '').trim();
    if (!s) continue;
    const k = s.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(s);
  }
  return out;
}

// Did the reviewers array actually change? Postgres returns text[] as JS array.
function reviewersEqual(a, b) {
  const aa = Array.isArray(a) ? [...a].map(String).sort() : [];
  const bb = Array.isArray(b) ? [...b].map(String).sort() : [];
  if (aa.length !== bb.length) return false;
  for (let i = 0; i < aa.length; i++) if (aa[i] !== bb[i]) return false;
  return true;
}

// ─── Module factory ───────────────────────────────────────────────────────
module.exports = function mountProjects(app, { pool, sessions, loginLimiter }) {
  if (!app || !pool || !sessions) {
    throw new Error('mountProjects requires { pool, sessions, loginLimiter }');
  }

  // Map<token, { userId, email, name, role, source }>
  const projectsSessions = new Map();
  // Map<token, { userId, created }>
  const projectsResetTokens = new Map();
  const RESET_TTL_MS = 60 * 60 * 1000;

  initSchema(pool).catch(err => console.error('[projects] schema init error:', err.message));

  // Resolve the request to a user object. Returns null when not authenticated.
  function resolveUser(req) {
    const projectsToken = req.cookies?.projects_session;
    if (projectsToken && projectsSessions.has(projectsToken)) {
      return projectsSessions.get(projectsToken);
    }
    const adminToken = req.cookies?.alpha_session;
    if (adminToken && sessions.has(adminToken)) {
      // Admin session — pseudo-user for activity attribution
      return { userId: null, email: '', name: 'Admin', role: 'super_admin', source: 'admin_session' };
    }
    return null;
  }

  // Build the role-aware visibility filter for tickets. Returns a SQL fragment
  // and an array of values to be appended to the caller's `vals`. The fragment
  // is empty for super_admin (full visibility). Operators also see unassigned
  // tickets so they can pick work up off the backlog.
  function ticketRoleFilter(user, startIndex) {
    if (!user || user.role === 'super_admin') return { sql: '', vals: [] };
    const fullName  = (user.name  || '').trim();
    const firstName = fullName.split(/\s+/)[0] || fullName;
    const email     = (user.email || '').trim();
    const vals = [];
    const orParts = [];
    if (firstName) { vals.push(firstName); orParts.push(`assigned_to ILIKE $${startIndex + vals.length - 1}`); }
    if (fullName && fullName !== firstName) { vals.push(fullName); orParts.push(`assigned_to ILIKE $${startIndex + vals.length - 1}`); }
    if (email)     { vals.push(email);     orParts.push(`assigned_to ILIKE $${startIndex + vals.length - 1}`); }
    if (user.role === 'operator') orParts.push('assigned_to IS NULL');
    if (!orParts.length) return { sql: '1=0', vals: [] };
    return { sql: '(' + orParts.join(' OR ') + ')', vals };
  }

  function requireAuth(req, res, next) {
    const user = resolveUser(req);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    // Force first-login password change. Block every route except the
    // change-password endpoint itself and the /me probe (UI uses it to
    // confirm session state when rendering the force-change view).
    if (user.must_change_password && req.path !== '/change-password' && req.path !== '/me') {
      return res.status(403).json({ code: 'MUST_CHANGE_PASSWORD', error: 'Password change required before continuing.' });
    }
    req.user = user;
    next();
  }
  function requireRole(...roles) {
    return (req, res, next) => {
      if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
      if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden — admin access required' });
      next();
    };
  }
  // member or admin (writes); viewers blocked.
  function requireWrite(req, res, next) {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    if (req.user.role === 'viewer') return res.status(403).json({ error: 'Read-only role — no write access' });
    next();
  }

  const authLimiter = loginLimiter || ((req, res, n) => n());

  // ── Auth routes ──────────────────────────────────────────────────────
  app.post('/api/projects-login', authLimiter, async (req, res) => {
    const { email, password } = req.body || {};
    const supplied = String(password || '');

    // Try email-based login first
    if (email && typeof email === 'string') {
      try {
        const { rows } = await pool.query(
          'SELECT id, email, name, role, password_hash, active, must_change_password FROM project_users WHERE LOWER(email) = LOWER($1)',
          [email.trim()]
        );
        if (rows.length) {
          const u = rows[0];
          if (!u.active) return res.status(403).json({ error: 'Account is deactivated' });
          let valid = false;
          try { valid = await bcrypt.compare(supplied, u.password_hash); } catch { valid = false; }
          if (valid) {
            await pool.query('UPDATE project_users SET last_login = NOW() WHERE id = $1', [u.id]);
            return issueSession(res, {
              userId: u.id, email: u.email, name: u.name, role: u.role, source: 'user',
              must_change_password: !!u.must_change_password
            });
          }
        }
      } catch (err) {
        console.error('[projects-login] db error:', err.message);
      }
    }

    // Master password fallback (legacy single-password mode). Logs in as Admin.
    const master = process.env.PROJECTS_PASSWORD;
    if (master) {
      let valid = false;
      try { valid = await bcrypt.compare(supplied, master); } catch { valid = false; }
      if (!valid && !master.startsWith('$2')) valid = supplied === master;
      if (valid) {
        return issueSession(res, {
          userId: null, email: 'admin@alphasurfaces.com.au', name: 'Admin', role: 'super_admin', source: 'master',
          must_change_password: false
        });
      }
    }

    return res.status(401).json({ error: 'Wrong email or password' });
  });

  function issueSession(res, payload) {
    const token = crypto.randomBytes(32).toString('hex');
    projectsSessions.set(token, { ...payload, created: Date.now() });
    res.cookie('projects_session', token, {
      httpOnly: true, sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production', maxAge: 86400000
    });
    res.json({
      ok: true,
      user: { email: payload.email, name: payload.name, role: payload.role },
      must_change_password: !!payload.must_change_password
    });
  }

  app.post('/api/projects-logout', (req, res) => {
    const token = req.cookies?.projects_session;
    if (token) projectsSessions.delete(token);
    res.clearCookie('projects_session');
    res.json({ ok: true });
  });

  app.get('/api/projects-auth-check', (req, res) => {
    const user = resolveUser(req);
    if (!user) return res.json({ authenticated: false });
    res.json({
      authenticated: true,
      user: { email: user.email, name: user.name, role: user.role,
              initials: initialsFromName(user.name) },
      must_change_password: !!user.must_change_password
    });
  });

  // ── Forgot / reset password ──────────────────────────────────────────
  app.post('/api/projects-forgot', authLimiter, async (req, res) => {
    const generic = { ok: true, message: 'If that email is registered, a reset link has been sent.' };
    try {
      const supplied = String(req.body?.email || '').trim().toLowerCase();
      if (!supplied) return res.json(generic);
      const { rows } = await pool.query(
        'SELECT id, email, name, active FROM project_users WHERE LOWER(email) = $1',
        [supplied]
      );
      if (rows.length && rows[0].active) {
        const u = rows[0];
        const token = crypto.randomBytes(32).toString('hex');
        projectsResetTokens.set(token, { userId: u.id, created: Date.now() });
        const base = process.env.SITE_URL || 'https://alphasurfaces.com.au';
        const resetUrl = `${base}/projects/reset?token=${token}`;
        sendPasswordResetEmail(u.email, u.name, resetUrl).catch(err =>
          console.error('[projects-forgot] email dispatch:', err.message)
        );
      }
    } catch (err) {
      console.error('[projects-forgot] error:', err.message);
    }
    res.json(generic);
  });

  app.get('/projects/reset', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'projects.html'));
  });

  app.post('/api/projects-reset', authLimiter, async (req, res) => {
    try {
      const { token, password } = req.body || {};
      if (!token || !password) return res.status(400).json({ ok: false, error: 'Missing token or password.' });
      if (typeof password !== 'string' || password.length < 8) {
        return res.status(400).json({ ok: false, error: 'Password must be at least 8 characters.' });
      }
      const entry = projectsResetTokens.get(token);
      if (!entry || (Date.now() - entry.created) > RESET_TTL_MS) {
        projectsResetTokens.delete(token);
        return res.status(400).json({ ok: false, error: 'Invalid or expired reset link. Please request a new one.' });
      }
      const hash = await bcrypt.hash(password, 10);
      await pool.query(
        'UPDATE project_users SET password_hash = $1, must_change_password = FALSE WHERE id = $2',
        [hash, entry.userId]
      );
      projectsResetTokens.delete(token);
      // Drop any active sessions for this user so they re-authenticate
      for (const [tok, sess] of projectsSessions) {
        if (sess.userId === entry.userId) projectsSessions.delete(tok);
      }
      res.json({ ok: true, message: 'Password updated. You can now sign in.' });
    } catch (err) {
      console.error('[projects-reset] error:', err.message);
      res.status(500).json({ ok: false, error: 'Could not update password. Please try again.' });
    }
  });

  // ── Authenticated routes ─────────────────────────────────────────────
  const router = express.Router();
  router.use(requireAuth);

  router.get('/me', (req, res) => {
    res.json({
      ok: true,
      user: {
        email: req.user.email, name: req.user.name, role: req.user.role,
        initials: initialsFromName(req.user.name), source: req.user.source
      }
    });
  });

  router.post('/change-password', async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body || {};
      if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 8) {
        return res.status(400).json({ ok: false, error: 'New password must be at least 8 characters.' });
      }
      if (newPassword === DEFAULT_USER_PASSWORD) {
        return res.status(400).json({ ok: false, error: 'Please choose a password different from the shared default.' });
      }
      if (!req.user.userId) {
        return res.status(400).json({ ok: false, error: 'The Admin master account has no individual password to change. Use a real user account.' });
      }
      const { rows } = await pool.query(
        'SELECT password_hash FROM project_users WHERE id = $1', [req.user.userId]
      );
      if (!rows.length) return res.status(404).json({ ok: false, error: 'User not found' });
      const ok = await bcrypt.compare(String(currentPassword || ''), rows[0].password_hash);
      if (!ok) return res.status(401).json({ ok: false, error: 'Current password is incorrect.' });
      const hash = await bcrypt.hash(newPassword, 10);
      await pool.query(
        'UPDATE project_users SET password_hash = $1, must_change_password = FALSE WHERE id = $2',
        [hash, req.user.userId]
      );
      // Clear the flag on the live session record so subsequent requests stop
      // hitting the MUST_CHANGE_PASSWORD gate without a fresh login.
      const token = req.cookies?.projects_session;
      if (token && projectsSessions.has(token)) {
        const sess = projectsSessions.get(token);
        sess.must_change_password = false;
        projectsSessions.set(token, sess);
      }
      res.json({ ok: true, message: 'Password updated.' });
    } catch (err) {
      console.error('[projects] change-password error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── User management (admin only) ─────────────────────────────────────
  router.get('/users', requireRole('super_admin'), async (req, res) => {
    try {
      const { rows } = await pool.query(
        `SELECT id, email, name, role, last_login, created_at, active
           FROM project_users ORDER BY active DESC, name ASC`
      );
      res.json({ ok: true, users: rows });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  router.post('/users', requireRole('super_admin'), async (req, res) => {
    try {
      const { email, name, role, password } = req.body || {};
      if (!email || !name) return res.status(400).json({ ok: false, error: 'Email and name are required.' });
      if (role && !ALLOWED_ROLES.includes(role)) {
        return res.status(400).json({ ok: false, error: 'Invalid role.' });
      }
      const tempPassword = password && password.length >= 8 ? password : crypto.randomBytes(8).toString('base64').slice(0, 12);
      const hash = await bcrypt.hash(tempPassword, 10);
      const { rows } = await pool.query(
        `INSERT INTO project_users (email, name, role, password_hash)
         VALUES (LOWER($1), $2, $3, $4)
         RETURNING id, email, name, role, created_at, active`,
        [email.trim(), name.trim(), role || 'member', hash]
      );
      res.json({ ok: true, user: rows[0], temporary_password: tempPassword });
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({ ok: false, error: 'A user with that email already exists.' });
      }
      console.error('[projects] create-user error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  router.patch('/users/:id', requireRole('super_admin'), async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!id) return res.status(400).json({ ok: false, error: 'Invalid user id.' });
      const sets = [];
      const vals = [];
      let tempPassword = null;
      const b = req.body || {};
      if (b.name)  { vals.push(String(b.name).trim()); sets.push(`name = $${vals.length}`); }
      if (b.role)  {
        if (!ALLOWED_ROLES.includes(b.role)) return res.status(400).json({ ok: false, error: 'Invalid role.' });
        vals.push(b.role); sets.push(`role = $${vals.length}`);
      }
      if (typeof b.active === 'boolean') {
        vals.push(b.active); sets.push(`active = $${vals.length}`);
      }
      if (b.email) {
        vals.push(String(b.email).trim().toLowerCase()); sets.push(`email = $${vals.length}`);
      }
      if (b.reset_password) {
        tempPassword = crypto.randomBytes(8).toString('base64').slice(0, 12);
        const hash = await bcrypt.hash(tempPassword, 10);
        vals.push(hash); sets.push(`password_hash = $${vals.length}`);
        // Drop active sessions for this user
        for (const [tok, sess] of projectsSessions) {
          if (sess.userId === id) projectsSessions.delete(tok);
        }
      }
      if (!sets.length) return res.status(400).json({ ok: false, error: 'No updatable fields supplied.' });
      vals.push(id);
      const { rows } = await pool.query(
        `UPDATE project_users SET ${sets.join(', ')} WHERE id = $${vals.length}
         RETURNING id, email, name, role, last_login, created_at, active`,
        vals
      );
      if (!rows.length) return res.status(404).json({ ok: false, error: 'User not found' });
      res.json({ ok: true, user: rows[0], temporary_password: tempPassword });
    } catch (err) {
      console.error('[projects] update-user error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  router.delete('/users/:id', requireRole('super_admin'), async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!id) return res.status(400).json({ ok: false, error: 'Invalid user id.' });
      const { rows } = await pool.query(
        `UPDATE project_users SET active = FALSE WHERE id = $1
         RETURNING id, email, name, role, active`, [id]
      );
      if (!rows.length) return res.status(404).json({ ok: false, error: 'User not found' });
      // Drop active sessions for this user
      for (const [tok, sess] of projectsSessions) {
        if (sess.userId === id) projectsSessions.delete(tok);
      }
      res.json({ ok: true, user: rows[0] });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── Form submissions (gated to super_admin + operator) ───────────────
  // Viewer is denied. Status changes and exports are written to form_activity
  // for audit. Routes intentionally mirror /api/admin/submissions in server.js
  // so the embedded UI in projects.html doesn't need a separate code path,
  // but the auth surface here is the project_users session — once /forms is
  // deprecated, the server.js /api/admin/submissions routes can be retired.
  const ALLOWED_SUBMISSION_STATUSES = ['new', 'read', 'actioned', 'archived'];

  function requireFormsAccess(req, res, next) {
    if (!req.user) return res.status(401).json({ ok: false, error: 'Unauthorized' });
    if (req.user.role === 'viewer') {
      return res.status(403).json({ ok: false, error: 'Forms access not permitted for read-only users.' });
    }
    next();
  }

  async function logFormActivity(submissionId, user, action, detail) {
    try {
      await pool.query(
        `INSERT INTO form_activity (submission_id, user_id, user_name, action, detail)
         VALUES ($1, $2, $3, $4, $5)`,
        [submissionId, user.userId || null, user.name || 'Unknown', action, detail || null]
      );
    } catch (err) {
      console.error('[projects/forms] activity log error:', err.message);
    }
  }

  router.get('/forms', requireFormsAccess, async (req, res) => {
    try {
      const limit  = Math.min(parseInt(req.query.limit  || '50', 10) || 50, 200);
      const offset = Math.max(parseInt(req.query.offset || '0',  10) || 0,  0);
      const vals = [];
      const where = [];
      if (req.query.form_type) { vals.push(req.query.form_type); where.push(`form_type = $${vals.length}`); }
      if (req.query.category === 'sample') {
        where.push(`form_type = 'Sample Request'`);
      } else if (req.query.category === 'contact') {
        where.push(`form_type = 'Contact Enquiry' AND (store_location IS NULL OR store_location = '')`);
      } else if (req.query.category === 'partner') {
        where.push(`form_type = 'Contact Enquiry' AND store_location IS NOT NULL AND store_location <> ''`);
      }
      if (req.query.status) { vals.push(req.query.status); where.push(`status = $${vals.length}`); }
      if (req.query.q) {
        vals.push('%' + req.query.q + '%');
        const i = vals.length;
        where.push(`(name ILIKE $${i} OR email ILIKE $${i} OR phone ILIKE $${i} OR message ILIKE $${i} OR company ILIKE $${i})`);
      }
      const whereSql = where.length ? ' WHERE ' + where.join(' AND ') : '';
      const dataQ = `
        SELECT s.*,
               COALESCE(
                 (SELECT STRING_AGG(stone_name, ', ' ORDER BY id)
                    FROM sample_request_items WHERE submission_id = s.id),
                 ''
               ) AS samples,
               (SELECT COUNT(*)::int FROM sample_request_items WHERE submission_id = s.id) AS sample_count
          FROM form_submissions s${whereSql}
         ORDER BY submitted_at DESC
         LIMIT $${vals.length+1} OFFSET $${vals.length+2}
      `;
      const { rows } = await pool.query(dataQ, [...vals, limit, offset]);
      const { rows: cr } = await pool.query(
        `SELECT COUNT(*) FROM form_submissions${whereSql}`, vals
      );
      const { rows: counts } = await pool.query(`
        SELECT
          COUNT(*) FILTER (WHERE status='new') AS new_total,
          COUNT(*) FILTER (WHERE form_type='Sample Request' AND status='new') AS new_sample,
          COUNT(*) FILTER (WHERE form_type='Contact Enquiry' AND (store_location IS NULL OR store_location='') AND status='new') AS new_contact,
          COUNT(*) FILTER (WHERE form_type='Contact Enquiry' AND store_location IS NOT NULL AND store_location<>'' AND status='new') AS new_partner
        FROM form_submissions
      `);
      res.json({
        ok: true,
        submissions: rows,
        total: parseInt(cr[0].count, 10),
        counts: counts[0]
      });
    } catch (err) {
      console.error('[projects/forms] list error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // Export must come before /:id so Express doesn't match "export" as :id.
  router.get('/forms/export', requireFormsAccess, async (req, res) => {
    try {
      const vals = [];
      const conditions = [];
      if (req.query.ids) {
        const idList = String(req.query.ids).split(',').map(Number).filter(n => !isNaN(n) && n > 0);
        if (!idList.length) return res.status(400).json({ ok: false, error: 'No valid IDs provided' });
        vals.push(idList);
        conditions.push(`id = ANY($${vals.length}::int[])`);
      }
      if (req.query.form_type) { vals.push(req.query.form_type); conditions.push(`form_type = $${vals.length}`); }
      let query = 'SELECT * FROM form_submissions';
      if (conditions.length) query += ' WHERE ' + conditions.join(' AND ');
      query += ' ORDER BY submitted_at DESC';
      const { rows } = await pool.query(query, vals);

      const sampleRows = rows.filter(r => r.form_type === 'Sample Request');
      const sampleMap = {};
      if (sampleRows.length) {
        const ids = sampleRows.map(r => r.id);
        const sr = await pool.query(
          `SELECT submission_id, stone_name FROM sample_request_items
            WHERE submission_id = ANY($1::int[]) ORDER BY id`, [ids]
        );
        sr.rows.forEach(it => { (sampleMap[it.submission_id] ||= []).push(it.stone_name); });
      }

      const cols = ['id','form_type','submitted_at','name','email','phone',
                    'company','role','reason',
                    'unit','street','suburb','postcode','state','store_location',
                    'stone_interest','message','source','consent','status'];
      const skip = new Set(['name','first_name','last_name','email','phone','company',
                            'stone_interest','message','special_instructions','postcode',
                            'state','store_location','source','consent','status',
                            'i_am_a','role','type','reason','enquiry_reason',
                            'street','suburb','unit','sampleItems','samples']);
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

      // One audit row covering the whole export. submission_id is set to 0
      // since the action spans multiple rows; the detail field captures the
      // count and the id list when selective.
      const detail = req.query.ids
        ? `Exported ${rows.length} selected submissions (ids: ${req.query.ids})`
        : `Exported ${rows.length} submissions`;
      logFormActivity(0, req.user, 'export', detail);

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="submissions-${Date.now()}.csv"`);
      res.send(csv);
    } catch (err) {
      console.error('[projects/forms] export error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  router.get('/forms/:id', requireFormsAccess, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!id) return res.status(400).json({ ok: false, error: 'Invalid id' });
      const { rows } = await pool.query('SELECT * FROM form_submissions WHERE id = $1', [id]);
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
      console.error('[projects/forms] detail error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  router.patch('/forms/:id', requireFormsAccess, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!id) return res.status(400).json({ ok: false, error: 'Invalid id' });
      const status = req.body?.status;
      if (!ALLOWED_SUBMISSION_STATUSES.includes(status)) {
        return res.status(400).json({ ok: false, error: `status must be one of ${ALLOWED_SUBMISSION_STATUSES.join(', ')}` });
      }
      const before = await pool.query('SELECT status FROM form_submissions WHERE id = $1', [id]);
      if (!before.rows.length) return res.status(404).json({ ok: false, error: 'Not found' });
      const oldStatus = before.rows[0].status;
      if (oldStatus === status) return res.json({ ok: true, status, unchanged: true });
      await pool.query('UPDATE form_submissions SET status = $1 WHERE id = $2', [status, id]);
      logFormActivity(id, req.user, 'status_changed', `Status: ${oldStatus} → ${status}`);
      res.json({ ok: true, status });
    } catch (err) {
      console.error('[projects/forms] patch error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── Time tracking (Track F) ──────────────────────────────────────────
  // Helpers shared by the routes below.
  function currentMonth() {
    const d = new Date();
    return d.toISOString().slice(0, 7); // YYYY-MM (UTC is fine for monthly buckets)
  }
  function monthRange(month) {
    if (!/^\d{4}-\d{2}$/.test(month)) return null;
    const [y, m] = month.split('-').map(Number);
    const start = `${month}-01`;
    const end   = m === 12 ? `${y + 1}-01-01` : `${y}-${String(m + 1).padStart(2, '0')}-01`;
    return { start, end };
  }
  // Operators/viewers can only ever read their own time. Super_admin sees
  // all users by default but can scope by ?user_id=. Returns the user_id to
  // filter on (number) or null for "no filter".
  function resolveTimeUserScope(req) {
    if (req.user.role === 'super_admin') {
      const q = req.query.user_id;
      if (q) {
        const id = parseInt(q, 10);
        return Number.isFinite(id) ? id : null;
      }
      return null;
    }
    return req.user.userId || -1; // -1 sentinel never matches a real id
  }

  // POST: log a time entry. Operator + super_admin only (viewers blocked
  // by requireWrite). Optional ticket_id is validated for visibility so
  // operators can't log time against tickets they can't see.
  router.post('/time/entries', requireWrite, async (req, res) => {
    try {
      if (!req.user.userId) {
        return res.status(400).json({ ok: false, error: 'Time can only be logged by individual user accounts (not the master admin session).' });
      }
      const b = req.body || {};
      const minutes = parseInt(b.minutes, 10);
      if (!Number.isFinite(minutes) || minutes <= 0) {
        return res.status(400).json({ ok: false, error: 'Minutes must be a positive integer.' });
      }
      const date = b.date && /^\d{4}-\d{2}-\d{2}$/.test(b.date) ? b.date : new Date().toISOString().slice(0, 10);
      let ticketId = null;
      if (b.ticket_id) {
        ticketId = String(b.ticket_id).trim();
        const tk = await pool.query('SELECT * FROM tickets WHERE ticket_id = $1', [ticketId]);
        if (!tk.rows.length) return res.status(404).json({ ok: false, error: 'Ticket not found' });
        if (!canAccessTicket(req.user, tk.rows[0])) {
          return res.status(403).json({ ok: false, error: 'You can only log time on tickets assigned to you.' });
        }
      }
      const desc = b.description ? String(b.description).trim() : null;
      const { rows } = await pool.query(
        `INSERT INTO time_entries (ticket_id, user_id, date, minutes, description)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING *`,
        [ticketId, req.user.userId, date, minutes, desc]
      );
      const entry = rows[0];
      // Mirror the entry into the ticket activity feed so it surfaces in the
      // drawer alongside status changes and notes.
      if (ticketId) {
        const hrs = (minutes / 60).toFixed(2).replace(/\.?0+$/, '');
        logActivity(pool, ticketId, req.user, 'time_logged', `${hrs}h${desc ? ' — ' + desc : ''}`);
      }
      // Fire the threshold alert in the background — the response should not
      // block on SendGrid latency or failure.
      if (typeof checkAndSendTimeAlert === 'function') {
        const month = String(date).slice(0, 7);
        checkAndSendTimeAlert(pool, req.user.userId, month).catch(err =>
          console.error('[projects/time] alert error:', err.message)
        );
      }
      res.json({ ok: true, entry });
    } catch (err) {
      console.error('[projects/time] create error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // GET: list time entries (paginated). Filters: user_id, ticket_id, month.
  router.get('/time/entries', async (req, res) => {
    try {
      const limit  = Math.min(parseInt(req.query.limit  || '100', 10) || 100, 500);
      const offset = Math.max(parseInt(req.query.offset || '0',   10) || 0,   0);
      const where = [];
      const vals = [];
      const scopeUserId = resolveTimeUserScope(req);
      if (scopeUserId != null) { vals.push(scopeUserId); where.push(`te.user_id = $${vals.length}`); }
      if (req.query.ticket_id) { vals.push(String(req.query.ticket_id)); where.push(`te.ticket_id = $${vals.length}`); }
      if (req.query.month) {
        const range = monthRange(req.query.month);
        if (!range) return res.status(400).json({ ok: false, error: 'month must be YYYY-MM' });
        vals.push(range.start); vals.push(range.end);
        where.push(`te.date >= $${vals.length - 1}::date AND te.date < $${vals.length}::date`);
      }
      const whereSql = where.length ? ' WHERE ' + where.join(' AND ') : '';
      const { rows } = await pool.query(
        `SELECT te.id, te.ticket_id, te.user_id, te.date, te.minutes, te.description, te.created_at,
                u.name AS user_name, u.email AS user_email,
                t.title AS ticket_title
           FROM time_entries te
           LEFT JOIN project_users u ON u.id = te.user_id
           LEFT JOIN tickets t       ON t.ticket_id = te.ticket_id
           ${whereSql}
          ORDER BY te.date DESC, te.id DESC
          LIMIT $${vals.length + 1} OFFSET $${vals.length + 2}`,
        [...vals, limit, offset]
      );
      const { rows: cr } = await pool.query(
        `SELECT COUNT(*)::int AS c FROM time_entries te${whereSql}`, vals
      );
      res.json({ ok: true, entries: rows, total: cr[0].c });
    } catch (err) {
      console.error('[projects/time] list error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // GET: monthly summary. super_admin sees everyone in the month; others
  // see only their own row. Defaults to current month.
  router.get('/time/summary', async (req, res) => {
    try {
      const month = req.query.month || currentMonth();
      const range = monthRange(month);
      if (!range) return res.status(400).json({ ok: false, error: 'month must be YYYY-MM' });
      const vals = [range.start, range.end];
      let userScopeSql = '';
      if (req.user.role !== 'super_admin') {
        if (!req.user.userId) {
          return res.json({ ok: true, month, summary: [], totalHours: 0 });
        }
        vals.push(req.user.userId);
        userScopeSql = `AND te.user_id = $${vals.length}`;
      }
      const { rows } = await pool.query(
        `SELECT u.id AS user_id, u.name, u.email, u.role,
                COALESCE(s.monthly_hours_cap, 20) AS monthly_hours_cap,
                COALESCE(s.warning_hours, 15)     AS warning_hours,
                COALESCE(SUM(te.minutes), 0)::int AS total_minutes
           FROM project_users u
           LEFT JOIN user_time_settings s ON s.user_id = u.id
           LEFT JOIN time_entries te
             ON te.user_id = u.id AND te.date >= $1::date AND te.date < $2::date
          ${req.user.role === 'super_admin'
              ? 'WHERE u.active = TRUE'
              : 'WHERE u.id = $3'}
          GROUP BY u.id, u.name, u.email, u.role, s.monthly_hours_cap, s.warning_hours
          ORDER BY total_minutes DESC, u.name ASC`,
        vals
      );
      const summary = rows.map(r => {
        const hours = r.total_minutes / 60;
        return {
          user_id: r.user_id,
          name: r.name,
          email: r.email,
          role: r.role,
          monthly_hours_cap: r.monthly_hours_cap,
          warning_hours: r.warning_hours,
          total_minutes: r.total_minutes,
          total_hours: Math.round(hours * 100) / 100,
          percent: r.monthly_hours_cap > 0 ? Math.round((hours / r.monthly_hours_cap) * 100) : 0
        };
      });
      const totalHours = summary.reduce((s, r) => s + r.total_hours, 0);
      res.json({ ok: true, month, summary, totalHours });
    } catch (err) {
      console.error('[projects/time] summary error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // GET: single user's monthly summary, with daily + per-ticket breakdowns.
  router.get('/time/summary/:userId', async (req, res) => {
    try {
      const userId = parseInt(req.params.userId, 10);
      if (!Number.isFinite(userId)) return res.status(400).json({ ok: false, error: 'Invalid user id' });
      // Operator/viewer can only request their own breakdown.
      if (req.user.role !== 'super_admin' && req.user.userId !== userId) {
        return res.status(403).json({ ok: false, error: 'You can only view your own time summary.' });
      }
      const month = req.query.month || currentMonth();
      const range = monthRange(month);
      if (!range) return res.status(400).json({ ok: false, error: 'month must be YYYY-MM' });

      const userQ = await pool.query(
        `SELECT u.id, u.name, u.email, u.role,
                COALESCE(s.monthly_hours_cap, 20) AS monthly_hours_cap,
                COALESCE(s.warning_hours, 15)     AS warning_hours,
                COALESCE(s.alert_email, 'belinda@alphasurfaces.com.au') AS alert_email
           FROM project_users u
           LEFT JOIN user_time_settings s ON s.user_id = u.id
          WHERE u.id = $1`,
        [userId]
      );
      if (!userQ.rows.length) return res.status(404).json({ ok: false, error: 'User not found' });
      const user = userQ.rows[0];

      const totalQ = await pool.query(
        `SELECT COALESCE(SUM(minutes), 0)::int AS total FROM time_entries
          WHERE user_id = $1 AND date >= $2::date AND date < $3::date`,
        [userId, range.start, range.end]
      );
      const totalMinutes = totalQ.rows[0].total;

      const byDayQ = await pool.query(
        `SELECT date, COALESCE(SUM(minutes), 0)::int AS minutes
           FROM time_entries
          WHERE user_id = $1 AND date >= $2::date AND date < $3::date
          GROUP BY date ORDER BY date ASC`,
        [userId, range.start, range.end]
      );
      const byTicketQ = await pool.query(
        `SELECT te.ticket_id, t.title, COALESCE(SUM(te.minutes), 0)::int AS minutes
           FROM time_entries te
           LEFT JOIN tickets t ON t.ticket_id = te.ticket_id
          WHERE te.user_id = $1 AND te.date >= $2::date AND te.date < $3::date
          GROUP BY te.ticket_id, t.title ORDER BY minutes DESC`,
        [userId, range.start, range.end]
      );
      const entriesQ = await pool.query(
        `SELECT te.id, te.ticket_id, te.date, te.minutes, te.description, te.created_at,
                t.title AS ticket_title
           FROM time_entries te
           LEFT JOIN tickets t ON t.ticket_id = te.ticket_id
          WHERE te.user_id = $1 AND te.date >= $2::date AND te.date < $3::date
          ORDER BY te.date DESC, te.id DESC`,
        [userId, range.start, range.end]
      );

      const totalHours = totalMinutes / 60;
      res.json({
        ok: true,
        month,
        user: {
          id: user.id, name: user.name, email: user.email, role: user.role,
          monthly_hours_cap: user.monthly_hours_cap,
          warning_hours: user.warning_hours,
          alert_email: user.alert_email
        },
        total_minutes: totalMinutes,
        total_hours: Math.round(totalHours * 100) / 100,
        percent: user.monthly_hours_cap > 0 ? Math.round((totalHours / user.monthly_hours_cap) * 100) : 0,
        by_day: byDayQ.rows.map(r => ({ date: r.date, minutes: r.minutes, hours: Math.round((r.minutes / 60) * 100) / 100 })),
        by_ticket: byTicketQ.rows.map(r => ({
          ticket_id: r.ticket_id, title: r.title,
          minutes: r.minutes, hours: Math.round((r.minutes / 60) * 100) / 100
        })),
        entries: entriesQ.rows
      });
    } catch (err) {
      console.error('[projects/time] user summary error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // GET: CSV export of time entries. Filters: month (default current), user_id (super_admin only).
  router.get('/time/export', async (req, res) => {
    try {
      const month = req.query.month || currentMonth();
      const range = monthRange(month);
      if (!range) return res.status(400).json({ ok: false, error: 'month must be YYYY-MM' });
      const vals = [range.start, range.end];
      const where = [`te.date >= $1::date AND te.date < $2::date`];
      const scopeUserId = resolveTimeUserScope(req);
      if (scopeUserId != null) { vals.push(scopeUserId); where.push(`te.user_id = $${vals.length}`); }
      const { rows } = await pool.query(
        `SELECT te.date, u.name AS user_name, te.ticket_id,
                t.title AS ticket_title, te.minutes, te.description
           FROM time_entries te
           LEFT JOIN project_users u ON u.id = te.user_id
           LEFT JOIN tickets t       ON t.ticket_id = te.ticket_id
          WHERE ${where.join(' AND ')}
          ORDER BY te.date ASC, te.id ASC`,
        vals
      );
      const escapeCSV = v => {
        if (v == null) return '';
        const s = v instanceof Date ? v.toISOString().slice(0, 10) : String(v);
        return (s.includes(',') || s.includes('"') || s.includes('\n'))
          ? `"${s.replace(/"/g, '""')}"` : s;
      };
      const header = ['Date','User','Ticket ID','Ticket Title','Hours','Description'];
      const lines = rows.map(r => [
        escapeCSV(r.date),
        escapeCSV(r.user_name),
        escapeCSV(r.ticket_id),
        escapeCSV(r.ticket_title),
        escapeCSV((r.minutes / 60).toFixed(2)),
        escapeCSV(r.description)
      ].join(','));
      const csv = [header.join(','), ...lines].join('\n');
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="timesheet-${month}.csv"`);
      res.send(csv);
    } catch (err) {
      console.error('[projects/time] export error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── Stats ────────────────────────────────────────────────────────────
  router.get('/stats', async (req, res) => {
    try {
      const f = ticketRoleFilter(req.user, 1);
      const baseFilter = f.sql ? ` WHERE ${f.sql}` : '';
      const baseFilterAnd = f.sql ? ` AND ${f.sql}` : '';
      const byStatus = await pool.query(
        `SELECT status, COUNT(*)::int AS c FROM tickets${baseFilter} GROUP BY status`,
        f.vals
      );
      const byPriority = await pool.query(
        `SELECT priority, COUNT(*)::int AS c FROM tickets
          WHERE status NOT IN ('done','archived')${baseFilterAnd} GROUP BY priority`,
        f.vals
      );
      const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
      // The role filter for the completed-this-week count starts at $2 since
      // $1 is `since`; rebuild it to keep param numbering coherent.
      const fWeek = ticketRoleFilter(req.user, 2);
      const completedThisWeek = await pool.query(
        `SELECT COUNT(*)::int AS c FROM tickets
          WHERE status='done' AND updated_at >= $1${fWeek.sql ? ' AND ' + fWeek.sql : ''}`,
        [since, ...fWeek.vals]
      );
      const counts = { status: {}, priority: {} };
      byStatus.rows.forEach(r   => { counts.status[r.status] = r.c; });
      byPriority.rows.forEach(r => { counts.priority[r.priority] = r.c; });
      const totalOpen = (counts.status.backlog || 0) + (counts.status.in_progress || 0) + (counts.status.review || 0);
      res.json({
        ok: true,
        totalOpen,
        highPriority: counts.priority.high || 0,
        inProgress: counts.status.in_progress || 0,
        completedThisWeek: completedThisWeek.rows[0].c,
        byStatus: counts.status,
        byPriority: counts.priority
      });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── CSV export ───────────────────────────────────────────────────────
  router.get('/tickets/export', async (req, res) => {
    try {
      // Viewers can read but the spec doesn't grant them export — keep parity
      // with the export button being hidden client-side.
      if (req.user.role === 'viewer') return res.status(403).json({ ok: false, error: 'Export not permitted for read-only users.' });
      const f = ticketRoleFilter(req.user, 1);
      const filterClause = f.sql ? ` AND ${f.sql}` : '';
      const { rows } = await pool.query(
        `SELECT ticket_id, title, description, category, priority, status,
                assigned_to, requested_by, due_date, source, created_at, updated_at, notes
           FROM tickets WHERE status <> 'archived'${filterClause}
          ORDER BY CAST(SUBSTRING(ticket_id FROM 4) AS INTEGER) ASC`,
        f.vals
      );
      const cols = ['ticket_id','title','description','category','priority','status',
                    'assigned_to','requested_by','due_date','source','created_at','updated_at','notes'];
      const escapeCSV = v => {
        if (v == null) return '';
        const s = v instanceof Date ? v.toISOString() : String(v);
        return (s.includes(',') || s.includes('"') || s.includes('\n'))
          ? `"${s.replace(/"/g, '""')}"` : s;
      };
      const csv = [
        cols.join(','),
        ...rows.map(r => cols.map(c => escapeCSV(r[c])).join(','))
      ].join('\n');
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="tickets-${Date.now()}.csv"`);
      res.send(csv);
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── Tickets list ─────────────────────────────────────────────────────
  router.get('/tickets', async (req, res) => {
    // Lazy sweep — rate-limited internally so it's fine to fire on every
    // request. Runs in the background; we don't await it.
    autoAdvanceReviews().catch(() => {});
    try {
      const where = [];
      const vals = [];
      const csv = (s) => String(s || '').split(',').map(x => x.trim()).filter(Boolean);
      const statuses    = csv(req.query.status);
      const categories  = csv(req.query.category);
      const priorities  = csv(req.query.priority);
      const assignees   = csv(req.query.assigned_to);
      if (statuses.length)   { vals.push(statuses);   where.push(`status      = ANY($${vals.length}::text[])`); }
      if (categories.length) { vals.push(categories); where.push(`category    = ANY($${vals.length}::text[])`); }
      if (priorities.length) { vals.push(priorities); where.push(`priority    = ANY($${vals.length}::text[])`); }
      if (assignees.length)  { vals.push(assignees);  where.push(`assigned_to = ANY($${vals.length}::text[])`); }
      if (req.query.search) {
        vals.push('%' + req.query.search + '%');
        const i = vals.length;
        where.push(`(title ILIKE $${i} OR description ILIKE $${i} OR notes ILIKE $${i} OR ticket_id ILIKE $${i})`);
      }
      // Role-based visibility: operator/viewer only see their own tickets.
      const f = ticketRoleFilter(req.user, vals.length + 1);
      if (f.sql) { where.push(f.sql); vals.push(...f.vals); }
      const sortMap = {
        created_at: 'created_at', updated_at: 'updated_at', due_date: 'due_date',
        title: 'title',
        priority: `CASE priority WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`,
        status:   `CASE status WHEN 'in_progress' THEN 1 WHEN 'review' THEN 2 WHEN 'backlog' THEN 3 WHEN 'done' THEN 4 ELSE 5 END`,
        ticket_id: 'CAST(SUBSTRING(ticket_id FROM 4) AS INTEGER)'
      };
      const sortKey = sortMap[req.query.sort] || 'updated_at';
      const order = (req.query.order || '').toLowerCase() === 'asc' ? 'ASC' : 'DESC';
      const sql = `SELECT * FROM tickets
                   ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
                   ORDER BY ${sortKey} ${order}, id ASC`;
      const { rows } = await pool.query(sql, vals);
      res.json({ ok: true, tickets: rows, total: rows.length });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // Returns true when the user is allowed to see/touch the ticket. Operators
  // and viewers are limited to their own assignments; operators may also
  // touch unassigned tickets so they can pick up backlog work.
  function canAccessTicket(user, ticket) {
    if (!user || !ticket) return false;
    if (user.role === 'super_admin') return true;
    const assigned = (ticket.assigned_to || '').trim().toLowerCase();
    if (!assigned) return user.role === 'operator';
    const fullName  = (user.name  || '').trim().toLowerCase();
    const firstName = fullName.split(/\s+/)[0] || fullName;
    const email     = (user.email || '').trim().toLowerCase();
    return (firstName && assigned.includes(firstName))
        || (fullName  && assigned.includes(fullName))
        || (email     && assigned.includes(email));
  }

  // ── Ticket detail ────────────────────────────────────────────────────
  router.get('/tickets/:id', async (req, res) => {
    try {
      const id = req.params.id;
      const { rows } = /^\d+$/.test(id)
        ? await pool.query('SELECT * FROM tickets WHERE id = $1', [parseInt(id, 10)])
        : await pool.query('SELECT * FROM tickets WHERE ticket_id = $1', [id]);
      if (!rows.length) return res.status(404).json({ ok: false, error: 'Ticket not found' });
      if (!canAccessTicket(req.user, rows[0])) {
        return res.status(404).json({ ok: false, error: 'Ticket not found' });
      }
      res.json({ ok: true, ticket: rows[0] });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── Activity feed for a ticket ───────────────────────────────────────
  router.get('/tickets/:id/activity', async (req, res) => {
    try {
      const id = req.params.id;
      // Resolve to ticket_id (supports both AS-XXX and numeric id)
      const tk = /^\d+$/.test(id)
        ? await pool.query('SELECT * FROM tickets WHERE id = $1', [parseInt(id, 10)])
        : await pool.query('SELECT * FROM tickets WHERE ticket_id = $1', [id]);
      if (!tk.rows.length) return res.status(404).json({ ok: false, error: 'Ticket not found' });
      if (!canAccessTicket(req.user, tk.rows[0])) {
        return res.status(404).json({ ok: false, error: 'Ticket not found' });
      }
      const ticketId = tk.rows[0].ticket_id;
      const { rows } = await pool.query(
        `SELECT id, ticket_id, user_id, user_name, action, detail, created_at
           FROM ticket_activity WHERE ticket_id = $1 ORDER BY created_at DESC, id DESC`,
        [ticketId]
      );
      res.json({ ok: true, activity: rows });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── Create ───────────────────────────────────────────────────────────
  router.post('/tickets', requireWrite, async (req, res) => {
    try {
      const b = req.body || {};
      if (!b.title || !String(b.title).trim()) {
        return res.status(400).json({ ok: false, error: 'Title is required.' });
      }
      if (b.priority && !ALLOWED_PRIORITIES.includes(b.priority)) {
        return res.status(400).json({ ok: false, error: 'Invalid priority.' });
      }
      if (b.status && !ALLOWED_STATUSES.includes(b.status)) {
        return res.status(400).json({ ok: false, error: 'Invalid status.' });
      }
      // Reviewers + approver — explicit null/empty array clears the defaults,
      // anything else falls back to Jay+Jana / Belinda. Distinguish "not
      // supplied" from "supplied empty" so the create form can opt out.
      const reviewers = Object.prototype.hasOwnProperty.call(b, 'reviewers')
        ? normaliseReviewers(b.reviewers)
        : DEFAULT_REVIEWERS.slice();
      const approver = Object.prototype.hasOwnProperty.call(b, 'approver')
        ? (b.approver ? String(b.approver).trim() : null)
        : DEFAULT_APPROVER;
      const ticketId = await nextTicketId(pool);
      const { rows } = await pool.query(
        `INSERT INTO tickets
           (ticket_id, title, description, category, priority, status,
            assigned_to, requested_by, due_date, notes, source,
            reviewers, approver)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
         RETURNING *`,
        [
          ticketId,
          String(b.title).trim(),
          b.description || null,
          b.category || null,
          b.priority || 'medium',
          b.status || 'backlog',
          b.assigned_to || null,
          b.requested_by || req.user.name || null,
          b.due_date || null,
          null,
          b.source || 'internal',
          reviewers,
          approver || null
        ]
      );
      const ticket = rows[0];
      logActivity(pool, ticket.ticket_id, req.user, 'created', `Created ticket "${ticket.title}"`);
      // If a starting note was supplied, append it via the note path so it's
      // attributed and surfaces in the activity feed.
      if (b.notes && String(b.notes).trim()) {
        await appendNote(pool, ticket.ticket_id, req.user, String(b.notes));
        const refresh = await pool.query('SELECT * FROM tickets WHERE id = $1', [ticket.id]);
        return res.json({ ok: true, ticket: refresh.rows[0] });
      }
      res.json({ ok: true, ticket });
    } catch (err) {
      console.error('[projects] create error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── Append-only note (separate endpoint so notes can't be overwritten) ─
  async function appendNote(pool, ticketId, user, message) {
    const stamp = nowAEST();
    const line = `[${stamp}] ${user.name}: ${String(message).trim()}`;
    const { rows } = await pool.query(
      `UPDATE tickets
          SET notes = CASE WHEN notes IS NULL OR notes = ''
                           THEN $2
                           ELSE notes || E'\n' || $2 END,
              updated_at = NOW()
        WHERE ticket_id = $1
        RETURNING *`,
      [ticketId, line]
    );
    if (rows.length) {
      await logActivity(pool, ticketId, user, 'note_added', String(message).trim());
    }
    return rows[0] || null;
  }

  router.post('/tickets/:id/notes', requireWrite, async (req, res) => {
    try {
      const id = req.params.id;
      const message = String(req.body?.message || '').trim();
      if (!message) return res.status(400).json({ ok: false, error: 'Note text is required.' });
      const tk = /^\d+$/.test(id)
        ? await pool.query('SELECT * FROM tickets WHERE id = $1', [parseInt(id, 10)])
        : await pool.query('SELECT * FROM tickets WHERE ticket_id = $1', [id]);
      if (!tk.rows.length) return res.status(404).json({ ok: false, error: 'Ticket not found' });
      if (!canAccessTicket(req.user, tk.rows[0])) {
        return res.status(403).json({ ok: false, error: 'You can only add notes to tickets assigned to you.' });
      }
      const ticket = await appendNote(pool, tk.rows[0].ticket_id, req.user, message);
      res.json({ ok: true, ticket });
    } catch (err) {
      console.error('[projects] note error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── Update ───────────────────────────────────────────────────────────
  router.patch('/tickets/:id', requireWrite, async (req, res) => {
    try {
      const id = req.params.id;
      // Look up the existing row first so we can diff for activity.
      const existing = /^\d+$/.test(id)
        ? await pool.query('SELECT * FROM tickets WHERE id = $1', [parseInt(id, 10)])
        : await pool.query('SELECT * FROM tickets WHERE ticket_id = $1', [id]);
      if (!existing.rows.length) return res.status(404).json({ ok: false, error: 'Ticket not found' });
      const oldRow = existing.rows[0];
      if (!canAccessTicket(req.user, oldRow)) {
        return res.status(403).json({ ok: false, error: 'You can only edit tickets assigned to you.' });
      }
      // Operators can't reassign a ticket away from themselves — keeps audit
      // trail honest.
      if (req.user.role === 'operator' && Object.prototype.hasOwnProperty.call(req.body || {}, 'assigned_to')) {
        const next = req.body.assigned_to == null ? null : String(req.body.assigned_to).trim();
        const synthetic = { ...oldRow, assigned_to: next };
        if (!canAccessTicket(req.user, synthetic)) {
          return res.status(403).json({ ok: false, error: 'Operators cannot reassign tickets to another user.' });
        }
      }

      const sets = [];
      const vals = [];
      const changed = [];
      for (const col of UPDATABLE_TICKET_COLS) {
        if (req.body && Object.prototype.hasOwnProperty.call(req.body, col)) {
          let newVal = req.body[col] === '' ? null : req.body[col];
          if (col === 'priority' && newVal && !ALLOWED_PRIORITIES.includes(newVal)) {
            return res.status(400).json({ ok: false, error: 'Invalid priority.' });
          }
          if (col === 'status' && newVal && !ALLOWED_STATUSES.includes(newVal)) {
            return res.status(400).json({ ok: false, error: 'Invalid status.' });
          }
          if (col === 'reviewers') newVal = normaliseReviewers(newVal);
          if (col === 'approver' && newVal != null) newVal = String(newVal).trim() || null;
          // Normalise dates for comparison — Postgres returns Date objects.
          let oldVal = oldRow[col];
          let normNew = newVal;
          let normOld = oldVal;
          if (col === 'due_date') {
            normNew = newVal ? String(newVal).slice(0, 10) : null;
            normOld = oldVal ? new Date(oldVal).toISOString().slice(0, 10) : null;
          }
          // Reviewers compare as sets — unchanged order shouldn't log an edit.
          let didChange;
          if (col === 'reviewers') {
            didChange = !reviewersEqual(normOld, normNew);
          } else {
            didChange = (normOld || '') !== (normNew || '');
          }
          if (didChange) {
            changed.push({ col, oldVal: normOld, newVal: normNew });
          }
          vals.push(newVal);
          sets.push(`${col} = $${vals.length}`);
        }
      }

      // Status transition → review/approval state machine. Only run when
      // status itself is in the patch payload — otherwise the existing
      // approval_status stays as-is. The request must reflect the *current*
      // ticket including any reviewers/approver edits in this same call, so
      // we look at the in-flight values rather than oldRow.
      const statusInPatch = Object.prototype.hasOwnProperty.call(req.body, 'status');
      const newStatus = statusInPatch ? req.body.status : oldRow.status;
      const oldStatus = oldRow.status;
      const effectiveReviewers = Object.prototype.hasOwnProperty.call(req.body, 'reviewers')
        ? normaliseReviewers(req.body.reviewers)
        : (Array.isArray(oldRow.reviewers) ? oldRow.reviewers : []);
      const effectiveApprover = Object.prototype.hasOwnProperty.call(req.body, 'approver')
        ? (req.body.approver ? String(req.body.approver).trim() : null)
        : oldRow.approver;
      const hasReviewRouting = effectiveReviewers.length > 0 || !!effectiveApprover;

      // Block direct backlog/in_progress → done when an approver is set and
      // the ticket hasn't been approved yet. The only path to done in that
      // case is via the review endpoint.
      if (statusInPatch && newStatus === 'done' && newStatus !== oldStatus
          && effectiveApprover && oldRow.approval_status !== 'approved') {
        return res.status(400).json({
          ok: false,
          error: `This ticket has an approver (${effectiveApprover}). Move it to "review" first — ${effectiveApprover} must approve before it can be marked done.`
        });
      }

      // Approval status side-effects driven by the status transition.
      let nextApprovalStatus = oldRow.approval_status;
      let triggerReviewerEmail = false;
      let triggerApproverEmail = false;
      let setReviewStartedAt = false;
      if (statusInPatch && newStatus !== oldStatus) {
        if (newStatus === 'review' && hasReviewRouting) {
          if (effectiveReviewers.length) {
            nextApprovalStatus = 'pending_review';
            triggerReviewerEmail = true;
            setReviewStartedAt = true;
          } else {
            // No reviewers — go straight to the approver.
            nextApprovalStatus = 'pending_approval';
            triggerApproverEmail = true;
          }
        } else if (newStatus === 'review' && !hasReviewRouting) {
          // No reviewers and no approver — ticket sits in review with no
          // workflow attached. Clear any prior approval_status state.
          nextApprovalStatus = null;
        } else if (newStatus === 'in_progress' || newStatus === 'backlog') {
          // Pulling back out of review/done → reset workflow state.
          nextApprovalStatus = null;
        } else if (newStatus === 'done') {
          // Reaching done means we either had no approver, or the approver
          // approved (gate above). Either way, mark the cycle finished.
          nextApprovalStatus = oldRow.approval_status === 'approved' ? 'approved' : null;
        }

        if (nextApprovalStatus !== oldRow.approval_status) {
          vals.push(nextApprovalStatus);
          sets.push(`approval_status = $${vals.length}`);
        }
        if (setReviewStartedAt) {
          sets.push(`review_started_at = NOW()`);
        } else if (newStatus !== 'review') {
          // Clear the auto-advance timer once we leave review.
          sets.push(`review_started_at = NULL`);
        }
      }

      if (!sets.length) return res.status(400).json({ ok: false, error: 'No updatable fields supplied.' });
      sets.push(`updated_at = NOW()`);
      vals.push(oldRow.id);
      const { rows } = await pool.query(
        `UPDATE tickets SET ${sets.join(', ')} WHERE id = $${vals.length} RETURNING *`,
        vals
      );
      const newRow = rows[0];

      // Log only fields that actually changed.
      for (const c of changed) {
        if (!TRACKED_COLS.includes(c.col)) continue;
        const desc = describeFieldChange(c.col, c.oldVal, c.newVal);
        logActivity(pool, newRow.ticket_id, req.user, desc.action, desc.detail);
      }

      // Status email — only when status actually moved.
      const statusChange = changed.find(c => c.col === 'status');
      if (statusChange) {
        sendStatusChangeEmail(newRow, statusChange.oldVal, statusChange.newVal, req.user.name).catch(err =>
          console.error('[projects] status email dispatch:', err.message)
        );
      }

      // Review/approval emails — fire-and-forget, never block the response.
      if (triggerReviewerEmail && notifyReviewersRequested) {
        notifyReviewersRequested(pool, newRow, req.user.name)
          .catch(err => console.error('[projects/review] reviewer email dispatch:', err.message));
        logActivity(pool, newRow.ticket_id, req.user, 'review_requested',
          `Submitted for review — notified ${effectiveReviewers.join(', ')}`);
      }
      if (triggerApproverEmail && notifyApproverRequested) {
        notifyApproverRequested(pool, newRow, null)
          .catch(err => console.error('[projects/review] approver email dispatch:', err.message));
        logActivity(pool, newRow.ticket_id, req.user, 'approval_requested',
          `Sent to ${effectiveApprover} for approval`);
      }

      res.json({ ok: true, ticket: newRow });
    } catch (err) {
      console.error('[projects] update error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── Review/approval action ───────────────────────────────────────────
  //
  // POST /api/projects/tickets/:id/review
  // Body: { action: 'approve'|'request_changes'|'reviewer_feedback', feedback }
  //
  // - 'approve' is approver-only and ends the cycle (sets status='done').
  // - 'request_changes' is approver-only and sends the ticket back to
  //   in_progress for the assignee to address.
  // - 'reviewer_feedback' is a non-blocking advisory note from a reviewer.
  //
  // The current user must match the role they're acting in: only the named
  // approver can approve/request_changes; only a named reviewer (or super_admin)
  // can leave reviewer_feedback. Super_admin can act in any role to keep
  // operations unblocked when someone is OOO.
  router.post('/tickets/:id/review', requireWrite, async (req, res) => {
    try {
      const id = req.params.id;
      const tk = /^\d+$/.test(id)
        ? await pool.query('SELECT * FROM tickets WHERE id = $1', [parseInt(id, 10)])
        : await pool.query('SELECT * FROM tickets WHERE ticket_id = $1', [id]);
      if (!tk.rows.length) return res.status(404).json({ ok: false, error: 'Ticket not found' });
      const ticket = tk.rows[0];
      // Visibility check — anyone who can see the ticket can act on it if
      // they hold the relevant role; viewers blocked at requireWrite already.
      if (!canAccessTicket(req.user, ticket) && req.user.role !== 'super_admin') {
        return res.status(403).json({ ok: false, error: 'You cannot act on this ticket.' });
      }
      const action = String(req.body?.action || '').trim();
      const feedback = req.body?.feedback ? String(req.body.feedback).trim() : '';
      const isApproveAction = action === 'approve' || action === 'request_changes';
      const isReviewerAction = action === 'reviewer_feedback';
      if (!isApproveAction && !isReviewerAction) {
        return res.status(400).json({ ok: false, error: 'Invalid action.' });
      }
      // Feedback is mandatory for changes_requested — assignee needs to know
      // what's wrong. Optional for approve and reviewer_feedback.
      if (action === 'request_changes' && !feedback) {
        return res.status(400).json({ ok: false, error: 'Feedback is required when requesting changes.' });
      }

      // Role check — match against the ticket's named approver/reviewers.
      const userName = (req.user.name || '').trim();
      const userFirst = userName.split(/\s+/)[0] || userName;
      const matchesName = (label) => {
        if (!label) return false;
        const t = String(label).trim().toLowerCase();
        return t && (t === userName.toLowerCase() || t === userFirst.toLowerCase());
      };
      const isApprover = matchesName(ticket.approver) || req.user.role === 'super_admin';
      const isReviewer = (Array.isArray(ticket.reviewers) && ticket.reviewers.some(matchesName))
                         || req.user.role === 'super_admin';
      if (isApproveAction && !isApprover) {
        return res.status(403).json({ ok: false, error: 'Only the named approver can perform this action.' });
      }
      if (isReviewerAction && !isReviewer) {
        return res.status(403).json({ ok: false, error: 'Only a named reviewer can leave reviewer feedback.' });
      }

      const role = isApproveAction ? 'approver' : 'reviewer';
      const reviewAction = action === 'approve' ? 'approved'
                         : action === 'request_changes' ? 'changes_requested'
                         : 'feedback';

      // Insert the audit row first — never lose history even if downstream
      // status update fails.
      await pool.query(
        `INSERT INTO ticket_reviews (ticket_id, reviewer_id, reviewer_name, action, feedback, role)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [ticket.ticket_id, req.user.userId || null, req.user.name || 'Unknown', reviewAction, feedback || null, role]
      );

      let updated = ticket;
      if (action === 'approve') {
        const upd = await pool.query(
          `UPDATE tickets SET status = 'done', approval_status = 'approved',
                              review_started_at = NULL, updated_at = NOW()
            WHERE id = $1 RETURNING *`,
          [ticket.id]
        );
        updated = upd.rows[0];
        logActivity(pool, ticket.ticket_id, req.user, 'approved',
          feedback ? `Approved: ${feedback}` : 'Approved — moved to done');
        if (notifyApproved) {
          notifyApproved(pool, updated, req.user.name, feedback)
            .catch(err => console.error('[projects/review] approved email dispatch:', err.message));
        }
      } else if (action === 'request_changes') {
        const upd = await pool.query(
          `UPDATE tickets SET status = 'in_progress', approval_status = 'changes_requested',
                              review_started_at = NULL, updated_at = NOW()
            WHERE id = $1 RETURNING *`,
          [ticket.id]
        );
        updated = upd.rows[0];
        logActivity(pool, ticket.ticket_id, req.user, 'changes_requested', feedback);
        if (notifyChangesRequested) {
          notifyChangesRequested(pool, updated, req.user.name, feedback)
            .catch(err => console.error('[projects/review] changes_requested email dispatch:', err.message));
        }
      } else {
        // reviewer_feedback: advisory only, doesn't change status. But it
        // does advance pending_review → pending_approval per the spec
        // ("after 24h OR when any reviewer leaves feedback, whichever first").
        if (ticket.approval_status === 'pending_review' && ticket.approver) {
          const upd = await pool.query(
            `UPDATE tickets SET approval_status = 'pending_approval',
                                review_started_at = NULL, updated_at = NOW()
              WHERE id = $1 RETURNING *`,
            [ticket.id]
          );
          updated = upd.rows[0];
          logActivity(pool, ticket.ticket_id, req.user, 'reviewer_feedback',
            `${req.user.name} left feedback — advanced to ${ticket.approver} for approval`);
          // Pass the feedback into the approver's email so they have context.
          if (notifyApproverRequested) {
            const summary = `<strong>${esc(req.user.name)}:</strong> ${esc(feedback)}`;
            notifyApproverRequested(pool, updated, summary)
              .catch(err => console.error('[projects/review] approver email dispatch:', err.message));
          }
        } else {
          logActivity(pool, ticket.ticket_id, req.user, 'reviewer_feedback', feedback);
        }
        if (notifyReviewerFeedback) {
          notifyReviewerFeedback(pool, updated, req.user.name, feedback)
            .catch(err => console.error('[projects/review] reviewer feedback email:', err.message));
        }
      }

      res.json({ ok: true, ticket: updated });
    } catch (err) {
      console.error('[projects] review error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── List reviews for a ticket ────────────────────────────────────────
  router.get('/tickets/:id/reviews', async (req, res) => {
    try {
      const id = req.params.id;
      const tk = /^\d+$/.test(id)
        ? await pool.query('SELECT * FROM tickets WHERE id = $1', [parseInt(id, 10)])
        : await pool.query('SELECT * FROM tickets WHERE ticket_id = $1', [id]);
      if (!tk.rows.length) return res.status(404).json({ ok: false, error: 'Ticket not found' });
      if (!canAccessTicket(req.user, tk.rows[0])) {
        return res.status(404).json({ ok: false, error: 'Ticket not found' });
      }
      const ticketId = tk.rows[0].ticket_id;
      const { rows } = await pool.query(
        `SELECT id, ticket_id, reviewer_id, reviewer_name, action, feedback, role, created_at
           FROM ticket_reviews WHERE ticket_id = $1
          ORDER BY created_at DESC, id DESC`,
        [ticketId]
      );
      // Pull the attachments tagged as review_feedback so the UI can
      // surface them inline with the corresponding review entry. Matching
      // is done by created_at proximity (within 5s) to keep the schema flat.
      const att = await pool.query(
        `SELECT id, ticket_id, user_name, filename, url, mime_type, size_bytes, context, created_at
           FROM ticket_attachments WHERE ticket_id = $1 AND context = 'review_feedback'`,
        [ticketId]
      );
      res.json({ ok: true, reviews: rows, review_attachments: att.rows });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── Attachments ──────────────────────────────────────────────────────
  // Reuse the same memoryStorage + 10MB limit pattern used elsewhere in the
  // codebase. multer/cloudinary may not be available in test contexts —
  // the upload routes degrade to a 503 when so.
  const attachmentUpload = multer
    ? multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } })
    : null;

  router.post('/tickets/:id/attachments',
    requireWrite,
    (req, res, next) => {
      if (!attachmentUpload) return res.status(503).json({ ok: false, error: 'File upload not available.' });
      attachmentUpload.single('file')(req, res, next);
    },
    async (req, res) => {
      try {
        if (!cloudinary) return res.status(503).json({ ok: false, error: 'Cloudinary not configured.' });
        if (!req.file) return res.status(400).json({ ok: false, error: 'No file uploaded.' });
        const id = req.params.id;
        const tk = /^\d+$/.test(id)
          ? await pool.query('SELECT * FROM tickets WHERE id = $1', [parseInt(id, 10)])
          : await pool.query('SELECT * FROM tickets WHERE ticket_id = $1', [id]);
        if (!tk.rows.length) return res.status(404).json({ ok: false, error: 'Ticket not found' });
        if (!canAccessTicket(req.user, tk.rows[0])) {
          return res.status(403).json({ ok: false, error: 'You cannot attach files to this ticket.' });
        }
        const ticketId = tk.rows[0].ticket_id;
        const context = ['general', 'review_feedback', 'email_import'].includes(req.body?.context)
          ? req.body.context : 'general';

        // resource_type: 'auto' lets Cloudinary pick image/video/raw based on
        // MIME — handles screenshots, PDFs, docs uniformly.
        const result = await new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream({
            folder: `alpha-surfaces/tickets/${ticketId}`,
            resource_type: 'auto',
            use_filename: true,
            unique_filename: true
          }, (err, r) => err ? reject(err) : resolve(r));
          stream.end(req.file.buffer);
        });

        const ins = await pool.query(
          `INSERT INTO ticket_attachments
             (ticket_id, user_id, user_name, filename, url, mime_type, size_bytes, context)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
          [ticketId, req.user.userId || null, req.user.name || 'Unknown',
           req.file.originalname || 'file', result.secure_url,
           req.file.mimetype || null, req.file.size || null, context]
        );
        logActivity(pool, ticketId, req.user, 'attachment_added',
          `Attached ${req.file.originalname || 'file'} (${context})`);
        res.json({ ok: true, attachment: ins.rows[0] });
      } catch (err) {
        console.error('[projects] attachment upload error:', err.message);
        res.status(500).json({ ok: false, error: err.message });
      }
    }
  );

  router.get('/tickets/:id/attachments', async (req, res) => {
    try {
      const id = req.params.id;
      const tk = /^\d+$/.test(id)
        ? await pool.query('SELECT * FROM tickets WHERE id = $1', [parseInt(id, 10)])
        : await pool.query('SELECT * FROM tickets WHERE ticket_id = $1', [id]);
      if (!tk.rows.length) return res.status(404).json({ ok: false, error: 'Ticket not found' });
      if (!canAccessTicket(req.user, tk.rows[0])) {
        return res.status(404).json({ ok: false, error: 'Ticket not found' });
      }
      const { rows } = await pool.query(
        `SELECT id, ticket_id, user_id, user_name, filename, url, mime_type,
                size_bytes, context, created_at
           FROM ticket_attachments WHERE ticket_id = $1
          ORDER BY created_at DESC, id DESC`,
        [tk.rows[0].ticket_id]
      );
      res.json({ ok: true, attachments: rows });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  router.delete('/tickets/:id/attachments/:attachmentId',
    requireRole('super_admin'),
    async (req, res) => {
      try {
        const att = parseInt(req.params.attachmentId, 10);
        if (!att) return res.status(400).json({ ok: false, error: 'Invalid attachment id.' });
        const { rows } = await pool.query(
          `DELETE FROM ticket_attachments WHERE id = $1 RETURNING ticket_id, filename`,
          [att]
        );
        if (!rows.length) return res.status(404).json({ ok: false, error: 'Attachment not found.' });
        logActivity(pool, rows[0].ticket_id, req.user, 'attachment_removed',
          `Removed ${rows[0].filename}`);
        res.json({ ok: true });
      } catch (err) {
        res.status(500).json({ ok: false, error: err.message });
      }
    }
  );

  // ── Auto-advance from pending_review to pending_approval ─────────────
  //
  // Lazy sweep — runs on each tickets-list call but rate-limited to once
  // every 60 seconds across the whole process. Idempotent: any ticket whose
  // review_started_at is older than 24h and is still in 'pending_review'
  // gets moved to 'pending_approval' and the approver is emailed.
  let lastSweep = 0;
  async function autoAdvanceReviews() {
    const now = Date.now();
    if (now - lastSweep < 60_000) return;
    lastSweep = now;
    try {
      const cutoff = new Date(now - REVIEW_AUTO_ADVANCE_MS);
      const { rows } = await pool.query(
        `UPDATE tickets
            SET approval_status = 'pending_approval',
                review_started_at = NULL,
                updated_at = NOW()
          WHERE approval_status = 'pending_review'
            AND review_started_at IS NOT NULL
            AND review_started_at < $1
            AND approver IS NOT NULL AND approver <> ''
          RETURNING *`,
        [cutoff]
      );
      for (const ticket of rows) {
        logActivity(pool, ticket.ticket_id,
          { userId: null, name: 'System' },
          'auto_advanced_to_approver',
          `24h elapsed without reviewer feedback — sent to ${ticket.approver}`);
        if (notifyApproverRequested) {
          notifyApproverRequested(pool, ticket, '<em>Auto-advanced after 24h with no reviewer feedback.</em>')
            .catch(err => console.error('[projects/review] auto-advance approver email:', err.message));
        }
      }
      // Tickets in pending_review with no approver are stranded — clear
      // their approval_status so they don't loop forever. Rare edge case
      // (someone removed the approver after submitting for review).
      await pool.query(
        `UPDATE tickets
            SET approval_status = NULL, review_started_at = NULL, updated_at = NOW()
          WHERE approval_status = 'pending_review'
            AND review_started_at < $1
            AND (approver IS NULL OR approver = '')`,
        [cutoff]
      );
    } catch (err) {
      console.error('[projects/review] auto-advance sweep error:', err.message);
    }
  }
  // Run once at module start so we don't wait 60s for the first sweep,
  // then on every tickets-list request (rate-limited internally).
  setTimeout(() => autoAdvanceReviews(), 5_000);

  // ── Soft delete (super_admin only) ──────────────────────────────────
  router.delete('/tickets/:id', requireRole('super_admin'), async (req, res) => {
    try {
      const id = req.params.id;
      const { rows } = /^\d+$/.test(id)
        ? await pool.query(`UPDATE tickets SET status='archived', updated_at=NOW() WHERE id=$1 RETURNING *`, [parseInt(id, 10)])
        : await pool.query(`UPDATE tickets SET status='archived', updated_at=NOW() WHERE ticket_id=$1 RETURNING *`, [id]);
      if (!rows.length) return res.status(404).json({ ok: false, error: 'Ticket not found' });
      logActivity(pool, rows[0].ticket_id, req.user, 'archived', 'Ticket archived');
      res.json({ ok: true, ticket: rows[0] });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.use('/api/projects', router);

  app.get('/projects', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'projects.html'));
  });

  console.log('[projects] routes mounted (user auth + activity log)');

  // Export the session resolver so server.js can extend admin/forms gating
  // without duplicating the session map.
  return { resolveUser };
};

module.exports.ALLOWED_STATUSES   = ALLOWED_STATUSES;
module.exports.ALLOWED_PRIORITIES = ALLOWED_PRIORITIES;
module.exports.ALLOWED_CATEGORIES = ALLOWED_CATEGORIES;
module.exports.ALLOWED_ROLES      = ALLOWED_ROLES;
