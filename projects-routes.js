'use strict';

/**
 * Project ticketing system — self-contained route module.
 *
 * Mounted from server.js with `require('./projects-routes')(app, { pool, sessions, loginLimiter })`.
 * Owns its own migration, seed, session store, auth, CRUD, CSV export, stats,
 * and optional ticket-status email. Does not modify server.js beyond the
 * single mount line so parallel work on server.js stays conflict-free.
 *
 * Required env vars:
 *   PROJECTS_PASSWORD - bcrypt hash (or plaintext for bootstrap) of the /projects password
 *   SENDGRID_API_KEY  - optional, enables status-change email
 *   NOTIFY_EMAIL_TO   - status-change email recipient (default hello@alphasurfaces.com.au)
 *   NOTIFY_EMAIL_FROM - SendGrid verified sender (default noreply@alphasurfaces.com.au)
 *   SITE_URL          - used to build the "View ticket" link (default https://alphasurfaces.com.au)
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
const ALLOWED_ASSIGNEES  = ['Sean','Belinda','Jess','Sam','Jay','Jana','Kate','Pam'];

// Updatable column allowlist for PATCH — anything else in the body is ignored.
const UPDATABLE_COLS = [
  'title','description','category','priority','status',
  'assigned_to','requested_by','due_date','notes','source'
];

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

  // One-time seed: only inserts if the table is empty so re-runs are safe.
  const { rows } = await pool.query('SELECT COUNT(*)::int AS c FROM tickets');
  if (rows[0].c === 0 && SEED_TICKETS.length) {
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
}

function formatTicketId(n) {
  return 'AS-' + String(n).padStart(3, '0');
}

// Generate the next AS-XXX by reading max numeric suffix, not max(id), so a
// gap from a deleted row never causes a collision.
async function nextTicketId(pool) {
  const { rows } = await pool.query(
    `SELECT ticket_id FROM tickets WHERE ticket_id ~ '^AS-[0-9]+$'
     ORDER BY CAST(SUBSTRING(ticket_id FROM 4) AS INTEGER) DESC LIMIT 1`
  );
  if (!rows.length) return formatTicketId(1);
  const last = parseInt(rows[0].ticket_id.slice(3), 10);
  return formatTicketId(last + 1);
}

// ─── Optional status-change email (SendGrid) ──────────────────────────────
let sendgridReady = false;
function ensureSendgrid() {
  if (sendgridReady) return true;
  if (!sgMail || !process.env.SENDGRID_API_KEY) return false;
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  sendgridReady = true;
  return true;
}
async function sendStatusChangeEmail(ticket, oldStatus, newStatus) {
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
      <p style="margin:0 0 14px">Status changed <strong>${esc(oldStatus)}</strong> → <strong>${esc(newStatus)}</strong>.</p>
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

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ─── Module factory ───────────────────────────────────────────────────────
module.exports = function mountProjects(app, { pool, sessions, loginLimiter }) {
  if (!app || !pool || !sessions) {
    throw new Error('mountProjects requires { pool, sessions, loginLimiter }');
  }

  // Own session store, separate from admin and forms sessions.
  const projectsSessions = new Map();

  // Run migration + seed once; never block server boot if it fails.
  initSchema(pool).catch(err => console.error('[projects] schema init error:', err.message));

  function requireProjectsOrAdmin(req, res, next) {
    const adminToken = req.cookies?.alpha_session;
    if (adminToken && sessions.has(adminToken)) return next();
    const projectsToken = req.cookies?.projects_session;
    if (projectsToken && projectsSessions.has(projectsToken)) return next();
    res.status(401).json({ error: 'Unauthorized' });
  }

  // ── Auth routes ──────────────────────────────────────────────────────
  const authLimiter = loginLimiter || ((req, res, n) => n());

  app.post('/api/projects-login', authLimiter, async (req, res) => {
    const supplied = (req.body && req.body.password) || '';
    const stored = process.env.PROJECTS_PASSWORD;
    if (!stored) {
      console.warn('[projects-login] PROJECTS_PASSWORD not set');
      return res.status(503).json({ error: 'Projects login not configured' });
    }
    let valid = false;
    try { valid = await bcrypt.compare(supplied, stored); } catch { valid = false; }
    if (!valid && !stored.startsWith('$2')) valid = supplied === stored;
    if (!valid) return res.status(401).json({ error: 'Wrong password' });
    const token = crypto.randomBytes(32).toString('hex');
    projectsSessions.set(token, { created: Date.now() });
    res.cookie('projects_session', token, {
      httpOnly: true, sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production', maxAge: 86400000
    });
    res.json({ ok: true });
  });

  app.post('/api/projects-logout', (req, res) => {
    const token = req.cookies?.projects_session;
    if (token) projectsSessions.delete(token);
    res.clearCookie('projects_session');
    res.json({ ok: true });
  });

  app.get('/api/projects-auth-check', (req, res) => {
    const projectsToken = req.cookies?.projects_session;
    const adminToken = req.cookies?.alpha_session;
    res.json({
      authenticated: !!((projectsToken && projectsSessions.has(projectsToken)) ||
                        (adminToken && sessions.has(adminToken)))
    });
  });

  // ── CRUD routes ──────────────────────────────────────────────────────
  const router = express.Router();
  router.use(requireProjectsOrAdmin);

  // Stats — counts by status and priority for the metric cards
  router.get('/stats', async (req, res) => {
    try {
      const byStatus = await pool.query(
        `SELECT status, COUNT(*)::int AS c FROM tickets GROUP BY status`
      );
      const byPriority = await pool.query(
        `SELECT priority, COUNT(*)::int AS c FROM tickets
          WHERE status NOT IN ('done','archived') GROUP BY priority`
      );
      const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
      const completedThisWeek = await pool.query(
        `SELECT COUNT(*)::int AS c FROM tickets WHERE status='done' AND updated_at >= $1`,
        [since]
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
      console.error('[projects] stats error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // CSV export of all non-archived tickets
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
      console.error('[projects] export error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // List with filters
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

      const search = req.query.search;
      if (search) {
        vals.push('%' + search + '%');
        const i = vals.length;
        where.push(`(title ILIKE $${i} OR description ILIKE $${i} OR notes ILIKE $${i} OR ticket_id ILIKE $${i})`);
      }

      // Sorting — explicit allowlist; anything else falls back to updated_at desc.
      const sortMap = {
        created_at: 'created_at', updated_at: 'updated_at',
        due_date: 'due_date',
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
      console.error('[projects] list error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // Detail by ticket_id (e.g. AS-001) or numeric id
  router.get('/tickets/:id', async (req, res) => {
    try {
      const id = req.params.id;
      const { rows } = /^\d+$/.test(id)
        ? await pool.query('SELECT * FROM tickets WHERE id = $1', [parseInt(id, 10)])
        : await pool.query('SELECT * FROM tickets WHERE ticket_id = $1', [id]);
      if (!rows.length) return res.status(404).json({ ok: false, error: 'Ticket not found' });
      res.json({ ok: true, ticket: rows[0] });
    } catch (err) {
      console.error('[projects] get error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // Create
  router.post('/tickets', async (req, res) => {
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
          b.requested_by || null,
          b.due_date || null,
          b.notes || null,
          b.source || 'internal'
        ]
      );
      res.json({ ok: true, ticket: rows[0] });
    } catch (err) {
      console.error('[projects] create error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // Update — only allowlisted columns; any unknown keys silently dropped.
  router.patch('/tickets/:id', async (req, res) => {
    try {
      const id = req.params.id;
      const sets = [];
      const vals = [];
      for (const col of UPDATABLE_COLS) {
        if (req.body && Object.prototype.hasOwnProperty.call(req.body, col)) {
          if (col === 'priority' && req.body[col] && !ALLOWED_PRIORITIES.includes(req.body[col])) {
            return res.status(400).json({ ok: false, error: 'Invalid priority.' });
          }
          if (col === 'status' && req.body[col] && !ALLOWED_STATUSES.includes(req.body[col])) {
            return res.status(400).json({ ok: false, error: 'Invalid status.' });
          }
          vals.push(req.body[col] === '' ? null : req.body[col]);
          sets.push(`${col} = $${vals.length}`);
        }
      }
      if (!sets.length) return res.status(400).json({ ok: false, error: 'No updatable fields supplied.' });
      sets.push(`updated_at = NOW()`);

      // Look up the existing row first so we can detect status changes.
      const existing = /^\d+$/.test(id)
        ? await pool.query('SELECT * FROM tickets WHERE id = $1', [parseInt(id, 10)])
        : await pool.query('SELECT * FROM tickets WHERE ticket_id = $1', [id]);
      if (!existing.rows.length) return res.status(404).json({ ok: false, error: 'Ticket not found' });
      const oldRow = existing.rows[0];

      vals.push(oldRow.id);
      const sql = `UPDATE tickets SET ${sets.join(', ')} WHERE id = $${vals.length} RETURNING *`;
      const { rows } = await pool.query(sql, vals);
      const newRow = rows[0];

      if (req.body.status && req.body.status !== oldRow.status) {
        sendStatusChangeEmail(newRow, oldRow.status, newRow.status).catch(err =>
          console.error('[projects] status email dispatch:', err.message)
        );
      }
      res.json({ ok: true, ticket: newRow });
    } catch (err) {
      console.error('[projects] update error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // Soft delete — sets status='archived' so the row stays available for audit.
  router.delete('/tickets/:id', async (req, res) => {
    try {
      const id = req.params.id;
      const { rows } = /^\d+$/.test(id)
        ? await pool.query(`UPDATE tickets SET status='archived', updated_at=NOW() WHERE id=$1 RETURNING *`, [parseInt(id, 10)])
        : await pool.query(`UPDATE tickets SET status='archived', updated_at=NOW() WHERE ticket_id=$1 RETURNING *`, [id]);
      if (!rows.length) return res.status(404).json({ ok: false, error: 'Ticket not found' });
      res.json({ ok: true, ticket: rows[0] });
    } catch (err) {
      console.error('[projects] delete error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.use('/api/projects', router);

  app.get('/projects', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'projects.html'));
  });

  console.log('[projects] routes mounted at /api/projects, /api/projects-login, /projects');
};

// Expose constants for tests / future imports without making them part of the
// default factory return.
module.exports.ALLOWED_STATUSES   = ALLOWED_STATUSES;
module.exports.ALLOWED_PRIORITIES = ALLOWED_PRIORITIES;
module.exports.ALLOWED_CATEGORIES = ALLOWED_CATEGORIES;
module.exports.ALLOWED_ASSIGNEES  = ALLOWED_ASSIGNEES;
