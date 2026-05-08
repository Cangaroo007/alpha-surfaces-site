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

// ─── Static config ────────────────────────────────────────────────────────
const ALLOWED_STATUSES   = ['backlog', 'in_progress', 'review', 'done', 'archived'];
const ALLOWED_PRIORITIES = ['high', 'medium', 'low'];
const ALLOWED_CATEGORIES = ['website','content','integration','consulting','showroom','print','process','meeting','feature'];
const ALLOWED_ROLES      = ['admin', 'member', 'viewer'];

const UPDATABLE_TICKET_COLS = [
  'title','description','category','priority','status',
  'assigned_to','requested_by','due_date','source'
  // 'notes' is NOT in this list — notes are append-only via dedicated endpoint
];
const TRACKED_COLS = ['title','description','category','priority','status','assigned_to','requested_by','due_date'];

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

const SEED_USERS = [
  { email: 'sean@cangaroo.ai',                name: 'Sean Stone',      role: 'admin' },
  { email: 'belinda@alphasurfaces.com.au',    name: 'Belinda Kelaher', role: 'admin' },
  { email: 'jay@alphasurfaces.com.au',        name: 'Jay',             role: 'member' },
  { email: 'jana@northcoaststone.com.au',     name: 'Jana Zemanova',   role: 'member' },
  { email: 'hello@alphasurfaces.com.au',      name: 'Jess Connelly',   role: 'member' },
  { email: 'sam@alphasurfaces.com.au',        name: 'Sam Southam',     role: 'member' },
  { email: 'kate@thisisikon.com.au',          name: 'Kate',            role: 'viewer' },
  { email: 'pam@thisisikon.com.au',           name: 'Pam',             role: 'viewer' }
];

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
    requested_by: 'Requested by', category: 'Category'
  };
  const label = labelMap[col] || col;
  // Long fields (description) — collapse to "Updated description"
  if (col === 'description' || col === 'title') {
    return { action: 'edited', detail: `Updated ${label.toLowerCase()}` };
  }
  const before = oldVal == null || oldVal === '' ? '—' : String(oldVal);
  const after  = newVal == null || newVal === '' ? '—' : String(newVal);
  let action = 'edited';
  if (col === 'status') action = 'status_changed';
  else if (col === 'priority') action = 'priority_changed';
  else if (col === 'assigned_to') action = 'assigned';
  return { action, detail: `${label}: ${before} → ${after}` };
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
      return { userId: null, email: '', name: 'Admin', role: 'admin', source: 'admin_session' };
    }
    return null;
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
          userId: null, email: 'admin@alphasurfaces.com.au', name: 'Admin', role: 'admin', source: 'master',
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
  router.get('/users', requireRole('admin'), async (req, res) => {
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

  router.post('/users', requireRole('admin'), async (req, res) => {
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

  router.patch('/users/:id', requireRole('admin'), async (req, res) => {
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

  router.delete('/users/:id', requireRole('admin'), async (req, res) => {
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

  // ── Stats ────────────────────────────────────────────────────────────
  router.get('/stats', async (req, res) => {
    try {
      const byStatus = await pool.query(`SELECT status, COUNT(*)::int AS c FROM tickets GROUP BY status`);
      const byPriority = await pool.query(
        `SELECT priority, COUNT(*)::int AS c FROM tickets WHERE status NOT IN ('done','archived') GROUP BY priority`
      );
      const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
      const completedThisWeek = await pool.query(
        `SELECT COUNT(*)::int AS c FROM tickets WHERE status='done' AND updated_at >= $1`, [since]
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
      const { rows } = await pool.query(
        `SELECT ticket_id, title, description, category, priority, status,
                assigned_to, requested_by, due_date, source, created_at, updated_at, notes
           FROM tickets WHERE status <> 'archived'
          ORDER BY CAST(SUBSTRING(ticket_id FROM 4) AS INTEGER) ASC`
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

  // ── Ticket detail ────────────────────────────────────────────────────
  router.get('/tickets/:id', async (req, res) => {
    try {
      const id = req.params.id;
      const { rows } = /^\d+$/.test(id)
        ? await pool.query('SELECT * FROM tickets WHERE id = $1', [parseInt(id, 10)])
        : await pool.query('SELECT * FROM tickets WHERE ticket_id = $1', [id]);
      if (!rows.length) return res.status(404).json({ ok: false, error: 'Ticket not found' });
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
        ? await pool.query('SELECT ticket_id FROM tickets WHERE id = $1', [parseInt(id, 10)])
        : await pool.query('SELECT ticket_id FROM tickets WHERE ticket_id = $1', [id]);
      if (!tk.rows.length) return res.status(404).json({ ok: false, error: 'Ticket not found' });
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
      const ticketId = await nextTicketId(pool);
      const { rows } = await pool.query(
        `INSERT INTO tickets
           (ticket_id, title, description, category, priority, status,
            assigned_to, requested_by, due_date, notes, source)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
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
          b.source || 'internal'
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
      // Resolve to ticket_id
      const tk = /^\d+$/.test(id)
        ? await pool.query('SELECT ticket_id FROM tickets WHERE id = $1', [parseInt(id, 10)])
        : await pool.query('SELECT ticket_id FROM tickets WHERE ticket_id = $1', [id]);
      if (!tk.rows.length) return res.status(404).json({ ok: false, error: 'Ticket not found' });
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

      const sets = [];
      const vals = [];
      const changed = [];
      for (const col of UPDATABLE_TICKET_COLS) {
        if (req.body && Object.prototype.hasOwnProperty.call(req.body, col)) {
          const newVal = req.body[col] === '' ? null : req.body[col];
          if (col === 'priority' && newVal && !ALLOWED_PRIORITIES.includes(newVal)) {
            return res.status(400).json({ ok: false, error: 'Invalid priority.' });
          }
          if (col === 'status' && newVal && !ALLOWED_STATUSES.includes(newVal)) {
            return res.status(400).json({ ok: false, error: 'Invalid status.' });
          }
          // Normalise dates for comparison — Postgres returns Date objects.
          let oldVal = oldRow[col];
          let normNew = newVal;
          let normOld = oldVal;
          if (col === 'due_date') {
            normNew = newVal ? String(newVal).slice(0, 10) : null;
            normOld = oldVal ? new Date(oldVal).toISOString().slice(0, 10) : null;
          }
          if ((normOld || '') !== (normNew || '')) {
            changed.push({ col, oldVal: normOld, newVal: normNew });
          }
          vals.push(newVal);
          sets.push(`${col} = $${vals.length}`);
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

      res.json({ ok: true, ticket: newRow });
    } catch (err) {
      console.error('[projects] update error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── Soft delete ──────────────────────────────────────────────────────
  router.delete('/tickets/:id', requireWrite, async (req, res) => {
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
};

module.exports.ALLOWED_STATUSES   = ALLOWED_STATUSES;
module.exports.ALLOWED_PRIORITIES = ALLOWED_PRIORITIES;
module.exports.ALLOWED_CATEGORIES = ALLOWED_CATEGORIES;
module.exports.ALLOWED_ROLES      = ALLOWED_ROLES;
