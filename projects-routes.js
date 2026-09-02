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
const fs      = require('fs');

// Ticket attachments live on Railway's persistent volume so they survive
// container restarts. Same DATA_DIR convention as server.js — env override
// for prod, fallback to ./data for local dev.
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const ATTACHMENTS_DIR = path.join(DATA_DIR, 'attachments');
const LEGACY_FORMS_PASSWORD_FILE = path.join(DATA_DIR, 'forms-password.json');

function readLegacyFormsPasswordHash() {
  try {
    if (!fs.existsSync(LEGACY_FORMS_PASSWORD_FILE)) return null;
    const data = JSON.parse(fs.readFileSync(LEGACY_FORMS_PASSWORD_FILE, 'utf8'));
    return data && typeof data.hash === 'string' ? data.hash : null;
  } catch (err) {
    console.error('[projects-login] legacy forms password read error:', err.message);
    return null;
  }
}

async function passwordMatches(supplied, stored) {
  if (!stored) return false;
  let valid = false;
  try { valid = await bcrypt.compare(supplied, stored); } catch { valid = false; }
  if (!valid && !stored.startsWith('$2')) valid = supplied === stored;
  return valid;
}

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
let sendBlockerNotice        = null;
let sendBlockerNagEmail      = null;
let sendTicketStatusEmail    = null;
try {
  ({
    checkAndSendTimeAlert,
    notifyReviewersRequested,
    notifyApproverRequested,
    notifyApproved,
    notifyChangesRequested,
    notifyReviewerFeedback,
    sendBlockerNotice,
    sendBlockerNagEmail,
    sendTicketStatusEmail
  } = require('./notifications'));
}
catch { /* notifications module is optional in tests */ }

// Cloudinary is configured globally in server.js. We re-require the singleton
// here for ticket attachment uploads — config persists across the require
// boundary, so this is safe.
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
const ALLOWED_DEFAULT_VIEWS = ['kanban', 'list', 'forms', 'time'];

// Track E: work-category taxonomy for time entries. Server-side enforces
// allowed values; the front-end mirrors this list with labels + colours.
const TIME_CATEGORIES = [
  { key: 'development',    label: 'Development',    short: 'Dev',    color: '#564D22' },
  { key: 'infrastructure', label: 'Infrastructure', short: 'Infra',  color: '#4A6741' },
  { key: 'design',         label: 'Design',         short: 'Design', color: '#8B6914' },
  { key: 'communications', label: 'Communications', short: 'Comms',  color: '#2563EB' },
  { key: 'planning',       label: 'Planning',       short: 'Plan',   color: '#7C3AED' },
  { key: 'project-mgmt',   label: 'Project Mgmt',   short: 'PM',     color: '#6B7280' }
];
const ALLOWED_TIME_CATEGORIES = TIME_CATEGORIES.map(c => c.key);
const TIME_CATEGORY_LABEL = TIME_CATEGORIES.reduce((acc, c) => { acc[c.key] = c.label; return acc; }, {});
const TIME_CATEGORY_COLOR = TIME_CATEGORIES.reduce((acc, c) => { acc[c.key] = c.color; return acc; }, {});

const UPDATABLE_TICKET_COLS = [
  'title','description','category','priority','status',
  'assigned_to','requested_by','due_date','source',
  'reviewers','approver',
  'blocked_by','blocked_reason'
  // 'notes' is NOT in this list — notes are append-only via dedicated endpoint
  // 'approval_status' is set by status transitions and the review endpoint, not by users
  // 'blocked_at' / 'blocker_last_nagged' / 'blocked_set_by_user_id' are derived
  // server-side from blocked_by transitions, not user-editable directly
];
const TRACKED_COLS = ['title','description','category','priority','status','assigned_to','requested_by','due_date','reviewers','approver','blocked_by','blocked_reason'];

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
  { title: 'Manage form submissions in Projects', category: 'feature', priority: 'high', status: 'done', requested_by: 'Sean', assigned_to: 'Sean', source: 'internal', description: 'Operators view and manage form submissions through the Project Tracker forms tab.' }
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

// ─── Track G: knowledge-base seed ─────────────────────────────────────────
// Articles seeded only on the very first deploy (when knowledge_articles is
// empty). Edits from the Docs UI persist; a redeploy never overwrites them.
const KB_SEED = [
  {
    slug: 'system-overview',
    title: 'System Overview',
    category: 'Getting Started',
    content: `# System Overview

Alpha Surfaces uses a custom-built platform to manage its website, customer enquiries, and project work. Everything is accessed through the Project Tracker at alphasurfaces.com.au/projects.

## What's in the system

- **Project Tracker** (Kanban Board) — manage tasks, bugs, and feature requests
- **Form Submissions** — view and action sample requests, enquiries, warranty activations, contact form messages, and partner enquiries
- **Time Tracking** — consultant hours tracking with monthly caps (admin only)
- **Website CMS** — edit stone products, collections, and page content
- **Knowledge Base** — you're reading it

## User roles

| Role | Access |
|------|--------|
| Super Admin | Everything — tickets, all forms, CMS, time tracking, user management, docs editing |
| Operator | Assigned tickets, form submissions |
| Viewer | Read-only access to assigned tickets |

## Key URLs

| URL | Purpose |
|-----|---------|
| alphasurfaces.com.au/projects | Project Tracker |
| alphasurfaces.com.au/admin | Website CMS (super_admin only) |
| alphasurfaces.com.au | Public website |
| review.alphasurfaces.com.au | Staging site for reviewing changes |
`
  },
  {
    slug: 'logging-in',
    title: 'Logging In',
    category: 'Getting Started',
    content: `# Logging In

1. Go to **alphasurfaces.com.au/projects**
2. Enter your Alpha Surfaces email address
3. Enter your password
4. First time? You'll be asked to set a new password

## Forgot your password?

Click "Forgot Password" on the login screen. A reset link will be sent to your email (expires after 1 hour).

## Your default view

After your first login you'll choose a default view (Kanban, List, Forms, or Time). You can change this anytime from the user menu — click your avatar in the top right.
`
  },
  {
    slug: 'kanban-board',
    title: 'Understanding the Kanban Board',
    category: 'Project Tracker',
    content: `# Understanding the Kanban Board

The board shows tickets in four columns:

| Column | Meaning |
|--------|---------|
| Backlog | Identified but not started |
| In Progress | Currently being worked on |
| Review | Done, waiting for check/approval |
| Done | Completed and signed off |

## Moving tickets

Drag and drop between columns, or click a ticket and change status in the detail drawer.

## Priority levels

- **High** (red) — needs attention today
- **Medium** (amber) — important but not urgent
- **Low** (green) — do when time allows

## Blockers

If a ticket is blocked (waiting on someone), it shows a red "BLOCKED" banner with the person's name. That person receives reminder emails every 2 days until it's cleared.

## Review & Approval

Tickets with a reviewer and/or approver go through a review cycle before completion:
1. Move to Review → reviewers are notified (Jay, Jana by default)
2. Reviewers check and leave feedback
3. After 24 hours or reviewer feedback, the approver is notified (Belinda by default)
4. Approver either approves (→ Done) or requests changes (→ back to In Progress)
`
  },
  {
    slug: 'creating-tickets',
    title: 'Creating Tickets',
    category: 'Project Tracker',
    content: `# Creating Tickets

1. Click **+ New Ticket**
2. Fill in: title, description, category, priority, assigned to
3. Optionally set reviewer (Jay, Jana) and approver (Belinda) — leave blank to skip review
4. Click Create

## Categories

| Category | Use for |
|----------|---------|
| Feature | New functionality |
| Content | Text, image, or page updates |
| Infrastructure | Server, DNS, security, deployment |
| Process | Workflows, communications, training |
| Print | Physical materials, QR codes |
| Showroom | In-store displays, iPad setup |

## Tips

- Every action is logged in the Activity tab
- Attach files via the Files tab (screenshots, PDFs, up to 10MB)
- Reference other tickets by typing AS-XXX — they become clickable links
`
  },
  {
    slug: 'sample-requests',
    title: 'Processing Sample Requests',
    category: 'Forms',
    content: `# Processing Sample Requests

Sample requests come from the website's Order Sample page. Each gets a reference number (SR-0001, SR-0002, etc.).

## Workflow

1. Customer submits → status: **New** → you get an SMS + email alert
2. Review the request → change status to **Processing**
3. Pack and send samples → change status to **Shipped**
4. Confirm delivery → change status to **Completed**

## Fields captured

Name, email, phone, company, role (homeowner/builder/architect/etc.), stone interest, shipping address, message, and how they found us.

## Exporting

Click "Export CSV" to download all sample requests as a spreadsheet. Filter by status or date range first to export a subset.
`
  },
  {
    slug: 'warranty-activations',
    title: 'Warranty Activations',
    category: 'Forms',
    content: `# Warranty Activations

Customers submit warranty activation forms after purchasing and installing Alpha Surfaces products. Each gets a reference number (WA-0001).

## Workflow

1. Customer submits with installation details + photos → **New**
2. Review the submission → **Under Review**
3. Verify purchase and installation → **Approved** (auto-assigns warranty number AW-YYYY-XXXX)
4. Or if details are incomplete → **Rejected** with feedback

## Fields captured

Contact details, installation address (street, suburb, state, postcode), stone name, purchase date, fabricator, retailer, invoice number, and up to 3 installation photos.

## Installation photos

Photos are stored in Cloudinary. Click thumbnails to view full size.
`
  },
  {
    slug: 'editing-content',
    title: 'Editing Website Content',
    category: 'Website CMS',
    content: `# Editing Website Content

The CMS is at **alphasurfaces.com.au/admin** (super_admin only).

## What you can edit

- Stone product details (name, description, specs, images)
- Collections (groupings of stones)
- Page content (hero text, about sections)
- Images (upload via Cloudinary)

## After making changes

The website caches aggressively. If changes don't appear:
1. Hard refresh: **Cmd+Shift+R** (Mac) or **Ctrl+Shift+R** (Windows)
2. Try incognito/private browsing
3. If still stale, ask for a Cloudflare cache purge

## Stone catalogue

47 products across 6 collections, driven by stones.json. Each stone has: name, collection, description, specifications, and images.
`
  },
  {
    slug: 'architecture',
    title: 'System Architecture',
    category: 'Technical Reference',
    content: `# System Architecture

## Stack

| Component | Technology |
|-----------|-----------|
| Server | Node.js + Express on Railway |
| Database | PostgreSQL on Railway |
| CDN/DNS | Cloudflare |
| Images | Cloudinary |
| Transactional email | SendGrid (Twilio) |
| Company email | Microsoft 365 |
| Marketing email | Klaviyo |
| SMS | Twilio |
| Source code | GitHub (cangaroo007/alpha-surfaces-site) |
| Domain | GoDaddy → Cloudflare nameservers |
| Analytics | GA4 + GTM + Microsoft Clarity |
| Consent | Cookiebot |

## Environments

| Environment | Branch | URL |
|-------------|--------|-----|
| Staging | main | review.alphasurfaces.com.au |
| Production | production | alphasurfaces.com.au |

## Deploy process

1. Push to \`main\` → auto-deploys to staging
2. Test at review.alphasurfaces.com.au
3. Merge \`main\` into \`production\` → auto-deploys to live
4. Purge Cloudflare cache
`
  },
  {
    slug: 'database-tables',
    title: 'Database Tables',
    category: 'Technical Reference',
    content: `# Database Tables

## Tickets & Projects
| Table | Purpose |
|-------|---------|
| tickets | Project tracker tickets |
| project_users | User accounts and roles |
| ticket_activity | Audit log of ticket actions |
| ticket_reviews | Review/approval feedback trail |
| ticket_attachments | Files attached to tickets |

## Forms
| Table | Purpose |
|-------|---------|
| sample_requests | Stone sample order requests |
| enquiries | General enquiry form submissions |
| warranty_activations | Warranty activation submissions |
| contact_submissions | Contact form messages |
| partner_enquiries | Trade/partner enquiries |
| newsletter_subscribers | Email newsletter signups |
| form_activity_log | Audit log of form actions |
| form_submissions | Legacy archive (all old submissions) |

## Time Tracking
| Table | Purpose |
|-------|---------|
| time_entries | Hours logged per user per ticket |
| time_alerts | Record of sent hour-cap alerts |
| user_time_settings | Monthly caps and thresholds |

## Other
| Table | Purpose |
|-------|---------|
| knowledge_articles | This knowledge base |
`
  },
  {
    slug: 'troubleshooting',
    title: 'Troubleshooting',
    category: 'Technical Reference',
    content: `# Troubleshooting

## Website changes not showing
1. Hard refresh: Cmd+Shift+R (Mac) / Ctrl+Shift+R (Windows)
2. Try incognito/private browsing
3. Ask for Cloudflare cache purge

## Can't log in
1. Check you're using your @alphasurfaces.com.au email
2. Try "Forgot Password" to reset
3. Contact sean@cangaroo.ai

## Form submissions missing
1. Check the correct form tab (Samples, Enquiries, etc.)
2. Check status filter — new submissions default to "New"
3. Check Railway logs for errors

## Emails not sending
1. Verify SENDGRID_API_KEY in Railway environment variables
2. Check SendGrid dashboard for bounces
3. Verify Cloudflare DNS records (DKIM, SPF, DMARC)

## Deployment failed
1. Check Railway dashboard → build logs
2. Run \`node -c filename.js\` locally to find syntax errors
3. Check package.json for missing dependencies
`
  }
];

// ─── DB migration + seed ──────────────────────────────────────────────────
async function initSchema(pool) {
  // project_users MUST be created first: tickets.blocked_set_by_user_id,
  // ticket_reviews.reviewer_id and ticket_attachments.user_id all carry a
  // foreign key to it. Created later, those FKs fail on a virgin database and
  // — because initSchema is fire-and-forget at the mount site — everything
  // after the first failure is silently skipped, leaving the app running with
  // no typed form tables at all.
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

  // Track B-Slim: blocker fields. blocked_by is a name (matched against
  // project_users to resolve email for nag); blocked_reason is free text.
  // blocked_at marks when the block went on; blocker_last_nagged tracks the
  // 2-day cadence so the cron doesn't re-fire on every tick.
  await pool.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS blocked_by         VARCHAR(100)`);
  await pool.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS blocked_reason     TEXT`);
  await pool.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS blocked_at         TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS blocker_last_nagged TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS blocked_set_by_user_id INTEGER REFERENCES project_users(id) ON DELETE SET NULL`);

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

  // Per-user landing view preference (Track D). 'kanban' is the historical
  // default and matches what the front-end falls back to. Allowed values
  // mirror the four nav buttons.
  await pool.query(
    `ALTER TABLE project_users
       ADD COLUMN IF NOT EXISTS default_view VARCHAR(20) DEFAULT 'kanban'`
  );

  // GitHub commit-author emails used by the auto time-tracker to map a
  // commit back to a project_users row. Array so a user can claim multiple
  // identities (their own email + bot emails like noreply@anthropic.com
  // for Claude-assisted commits they triggered).
  await pool.query(
    `ALTER TABLE project_users
       ADD COLUMN IF NOT EXISTS github_emails TEXT[] DEFAULT '{}'`
  );
  // Seed Sean's GitHub identities. Idempotent — only overwrites when the
  // current value is NULL or empty so manual edits stick.
  await pool.query(
    `UPDATE project_users
        SET github_emails = ARRAY['sean@cangaroo.ai', 'noreply@anthropic.com']
      WHERE LOWER(email) = 'sean@cangaroo.ai'
        AND (github_emails IS NULL OR array_length(github_emails, 1) IS NULL)`
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

  // ── Track I: per-form-type tables ──────────────────────────────────
  // The legacy form_submissions table still receives every submission for
  // backwards compatibility (search, archive, audit). These typed tables
  // give each form its own schema so columns aren't NULL-padded with
  // raw_data overflow, and so each form can have its own status flow.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sample_requests (
      id              SERIAL PRIMARY KEY,
      reference       VARCHAR(20) UNIQUE NOT NULL,
      name            VARCHAR(255) NOT NULL,
      email           VARCHAR(255) NOT NULL,
      phone           VARCHAR(50),
      company         VARCHAR(255),
      role            VARCHAR(100),
      stone_interest  TEXT,
      message         TEXT,
      street          VARCHAR(255),
      suburb          VARCHAR(100),
      unit            VARCHAR(50),
      source          VARCHAR(100),
      consent         BOOLEAN DEFAULT FALSE,
      status          VARCHAR(20) DEFAULT 'new',
      notes           TEXT,
      created_at      TIMESTAMPTZ DEFAULT NOW(),
      updated_at      TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_sr_status  ON sample_requests(status)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_sr_created ON sample_requests(created_at DESC)`);
  // Address completeness — older deployments are missing postcode/state.
  await pool.query(`ALTER TABLE sample_requests ADD COLUMN IF NOT EXISTS postcode VARCHAR(10)`);
  await pool.query(`ALTER TABLE sample_requests ADD COLUMN IF NOT EXISTS state    VARCHAR(20)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS enquiries (
      id              SERIAL PRIMARY KEY,
      reference       VARCHAR(20) UNIQUE NOT NULL,
      name            VARCHAR(255) NOT NULL,
      email           VARCHAR(255) NOT NULL,
      phone           VARCHAR(50),
      company         VARCHAR(255),
      role            VARCHAR(100),
      reason          VARCHAR(100),
      message         TEXT NOT NULL,
      consent         BOOLEAN DEFAULT FALSE,
      status          VARCHAR(20) DEFAULT 'new',
      notes           TEXT,
      created_at      TIMESTAMPTZ DEFAULT NOW(),
      updated_at      TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_en_status  ON enquiries(status)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_en_created ON enquiries(created_at DESC)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS warranty_activations (
      id                  SERIAL PRIMARY KEY,
      reference           VARCHAR(20) UNIQUE NOT NULL,
      name                VARCHAR(255) NOT NULL,
      email               VARCHAR(255) NOT NULL,
      phone               VARCHAR(50) NOT NULL,
      street              VARCHAR(255) NOT NULL,
      suburb              VARCHAR(100) NOT NULL,
      state               VARCHAR(10) NOT NULL,
      postcode            VARCHAR(10) NOT NULL,
      stone_name          VARCHAR(255) NOT NULL,
      purchase_date       DATE,
      fabricator          VARCHAR(255) NOT NULL,
      retailer            VARCHAR(255),
      invoice_number      VARCHAR(100),
      installation_photos TEXT[],
      consent             BOOLEAN DEFAULT FALSE,
      status              VARCHAR(20) DEFAULT 'new',
      warranty_number     VARCHAR(20),
      approved_at         TIMESTAMPTZ,
      approved_by         VARCHAR(100),
      notes               TEXT,
      created_at          TIMESTAMPTZ DEFAULT NOW(),
      updated_at          TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_wa_status  ON warranty_activations(status)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_wa_created ON warranty_activations(created_at DESC)`);

  // Warranty detail captured from mid-2026 onward. All nullable so the rows
  // activated before these fields existed still read and render. Note
  // coverage_type (Residential / Commercial) is the cover the customer is
  // claiming — NOT warranty_number (AW-YYYY-XXXX), which is assigned by
  // Belinda on approval.
  await pool.query(`ALTER TABLE warranty_activations ADD COLUMN IF NOT EXISTS batch_number      VARCHAR(100)`);
  await pool.query(`ALTER TABLE warranty_activations ADD COLUMN IF NOT EXISTS lot_number        VARCHAR(100)`);
  await pool.query(`ALTER TABLE warranty_activations ADD COLUMN IF NOT EXISTS application      VARCHAR(50)`);
  await pool.query(`ALTER TABLE warranty_activations ADD COLUMN IF NOT EXISTS coverage_type    VARCHAR(20)`);
  await pool.query(`ALTER TABLE warranty_activations ADD COLUMN IF NOT EXISTS installation_date DATE`);
  await pool.query(`ALTER TABLE warranty_activations ADD COLUMN IF NOT EXISTS photo_consent     BOOLEAN DEFAULT FALSE`);
  // Claim tracking + CRM links, read by the RoadRunner warranty register at
  // /warranties. Added here rather than in RoadRunner because this table
  // belongs to the website — RoadRunner holds a read-only connection to it and
  // must never migrate a schema it does not own.
  //
  // stonemason_org_id: the customer types their stonemason as free text, so it
  // cannot be resolved at submit time. pipedrive.js already attempts a name
  // match and writes the outcome into the note; this column is where Jess's
  // confirmed match lands once someone has actually checked it.
  //
  // pipedrive_project_id stays null: /api/v2/projects returns 402
  // "Required suites missing" under both auth schemes, so the Projects add-on
  // is not on the plan and nothing can populate it yet.
  await pool.query(`ALTER TABLE warranty_activations ADD COLUMN IF NOT EXISTS stonemason_org_id    BIGINT`);
  await pool.query(`ALTER TABLE warranty_activations ADD COLUMN IF NOT EXISTS pipedrive_person_id  BIGINT`);
  await pool.query(`ALTER TABLE warranty_activations ADD COLUMN IF NOT EXISTS pipedrive_project_id BIGINT`);
  await pool.query(`ALTER TABLE warranty_activations ADD COLUMN IF NOT EXISTS claim_status         TEXT DEFAULT 'registered'`);
  await pool.query(`ALTER TABLE warranty_activations ADD COLUMN IF NOT EXISTS claim_opened_at      TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE warranty_activations ADD COLUMN IF NOT EXISTS claim_notes          TEXT`);
  // Existing rows predate the column and would otherwise sit at NULL, which
  // reads as "no claim state" rather than the true "registered, no claim".
  await pool.query(`UPDATE warranty_activations SET claim_status = 'registered' WHERE claim_status IS NULL`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_wa_claim_status ON warranty_activations(claim_status)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_wa_batch        ON warranty_activations(batch_number)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_wa_lot          ON warranty_activations(lot_number)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_wa_stonemason_org ON warranty_activations(stonemason_org_id)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS contact_submissions (
      id              SERIAL PRIMARY KEY,
      reference       VARCHAR(20) UNIQUE NOT NULL,
      name            VARCHAR(255) NOT NULL,
      email           VARCHAR(255) NOT NULL,
      phone           VARCHAR(50),
      message         TEXT NOT NULL,
      consent         BOOLEAN DEFAULT FALSE,
      status          VARCHAR(20) DEFAULT 'new',
      notes           TEXT,
      created_at      TIMESTAMPTZ DEFAULT NOW(),
      updated_at      TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_ct_status  ON contact_submissions(status)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_ct_created ON contact_submissions(created_at DESC)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS partner_enquiries (
      id              SERIAL PRIMARY KEY,
      reference       VARCHAR(20) UNIQUE NOT NULL,
      name            VARCHAR(255) NOT NULL,
      email           VARCHAR(255) NOT NULL,
      phone           VARCHAR(50),
      company         VARCHAR(255) NOT NULL,
      role            VARCHAR(100),
      reason          VARCHAR(100),
      message         TEXT,
      consent         BOOLEAN DEFAULT FALSE,
      status          VARCHAR(20) DEFAULT 'new',
      notes           TEXT,
      created_at      TIMESTAMPTZ DEFAULT NOW(),
      updated_at      TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_pa_status  ON partner_enquiries(status)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_pa_created ON partner_enquiries(created_at DESC)`);

  // Showroom walk-in check-ins (Jess fills these on the iPad while talking to
  // visitors). Email is optional — many walk-ins won't share one — so the
  // schema permits NULL there. Status flow: new → followed_up → converted /
  // no_response.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS showroom_checkins (
      id              SERIAL PRIMARY KEY,
      reference       VARCHAR(20) UNIQUE NOT NULL,
      name            VARCHAR(255) NOT NULL,
      email           VARCHAR(255),
      phone           VARCHAR(50) NOT NULL,
      interests       TEXT,
      source          VARCHAR(100),
      notes           TEXT,
      consent         BOOLEAN DEFAULT TRUE,
      status          VARCHAR(20) DEFAULT 'new',
      follow_up_date  DATE,
      created_at      TIMESTAMPTZ DEFAULT NOW(),
      updated_at      TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_sc_status  ON showroom_checkins(status)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_sc_created ON showroom_checkins(created_at DESC)`);
  // `interests` was carrying the visitor's role as the literal string
  // "I am a: Homeowner" — there was never a product-interest field on the
  // iPad. Visitor type now has its own column and `interests` holds what the
  // visitor is actually interested in (Engineered Stone / Porcelain Tiles),
  // which is what Belinda's report needs. State added so walk-ins can join
  // the same state breakdown as sample requests and warranties.
  await pool.query(`ALTER TABLE showroom_checkins ADD COLUMN IF NOT EXISTS visitor_type VARCHAR(100)`);
  await pool.query(`ALTER TABLE showroom_checkins ADD COLUMN IF NOT EXISTS state        VARCHAR(10)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_sc_interests ON showroom_checkins(interests)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_sc_state     ON showroom_checkins(state)`);
  // One-off, idempotent: lift legacy "I am a: X" values out of `interests`
  // into visitor_type so historic walk-ins report alongside new ones.
  try {
    await pool.query(`
      UPDATE showroom_checkins
         SET visitor_type = TRIM(SUBSTRING(interests FROM 'I am a:(.*)')),
             interests    = NULL
       WHERE interests LIKE 'I am a:%'
         AND visitor_type IS NULL`);
  } catch (err) {
    console.error('[projects/backfill] showroom visitor_type error:', err.message);
  }

  // Polymorphic activity log — one row covers any of the typed form tables
  // above. The (form_type, record_id) composite index keeps the per-record
  // history fetch cheap.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS form_activity_log (
      id            SERIAL PRIMARY KEY,
      form_type     VARCHAR(30) NOT NULL,
      record_id     INTEGER NOT NULL,
      user_id       INTEGER REFERENCES project_users(id) ON DELETE SET NULL,
      user_name     VARCHAR(100) NOT NULL,
      action        VARCHAR(50) NOT NULL,
      detail        TEXT,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_fal_type_record ON form_activity_log(form_type, record_id)`);

  // ── Track G: knowledge base articles ────────────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS knowledge_articles (
      id          SERIAL PRIMARY KEY,
      slug        VARCHAR(100) UNIQUE NOT NULL,
      title       VARCHAR(255) NOT NULL,
      category    VARCHAR(50) NOT NULL,
      content     TEXT NOT NULL,
      sort_order  INTEGER DEFAULT 0,
      author      VARCHAR(100) DEFAULT 'Sean Stone',
      updated_by  VARCHAR(100),
      created_at  TIMESTAMPTZ DEFAULT NOW(),
      updated_at  TIMESTAMPTZ DEFAULT NOW(),
      published   BOOLEAN DEFAULT TRUE
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_kb_category ON knowledge_articles(category)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_kb_slug     ON knowledge_articles(slug)`);

  // ── One-time migration: copy existing form_submissions into typed tables ──
  // Only fires when the typed tables are empty AND form_submissions has data.
  // Idempotent guard: a redeploy after migration finds non-empty typed tables
  // and skips. We never DROP form_submissions — it stays as the archive.
  try {
    const oldCountQ = await pool.query(`SELECT COUNT(*)::int AS c FROM form_submissions`);
    const oldCount  = oldCountQ.rows[0].c;
    if (oldCount > 0) {
      const counts = await pool.query(`
        SELECT
          (SELECT COUNT(*)::int FROM sample_requests)      AS sr,
          (SELECT COUNT(*)::int FROM enquiries)            AS en,
          (SELECT COUNT(*)::int FROM warranty_activations) AS wa,
          (SELECT COUNT(*)::int FROM contact_submissions)  AS ct,
          (SELECT COUNT(*)::int FROM partner_enquiries)    AS pa
      `);
      const total = counts.rows[0].sr + counts.rows[0].en + counts.rows[0].wa + counts.rows[0].ct + counts.rows[0].pa;
      if (total === 0) {
        await migrateFormSubmissionsIntoTypedTables(pool);
      }
    }
  } catch (err) {
    console.error('[projects/migrate] form_submissions copy error:', err.message);
  }

  // Self-healing backfill for sample_requests.stone_interest. Idempotent —
  // only touches rows that are still blank — so it's safe to run on every
  // boot. Catches rows that the original migration created with NULL stones
  // before sample_request_items was being joined.
  try {
    await backfillSampleRequestStoneInterest(pool);
  } catch (err) {
    console.error('[projects/backfill] sample stone_interest error:', err.message);
  }

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

  // Track E: per-entry work category for the consultant timesheet view.
  // Default is 'development' so legacy entries without a category still
  // render in the dashboard. Allowed values are enforced in the route layer
  // (see ALLOWED_TIME_CATEGORIES) — keeping the column unconstrained leaves
  // room to add new categories without a migration round-trip.
  await pool.query(`ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS category VARCHAR(30) DEFAULT 'development'`);

  // Provenance flag for entries created by the auto time-tracker. Manual
  // POSTs default to 'manual'; the auto-tracker writes 'auto-git'. The
  // partial unique index lets the tracker re-run hourly and idempotently
  // update today's row without stacking duplicates, while never colliding
  // with a manual entry on the same date.
  await pool.query(`ALTER TABLE time_entries ADD COLUMN IF NOT EXISTS source VARCHAR(20) DEFAULT 'manual'`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_time_auto_unique
                    ON time_entries (user_id, date) WHERE source = 'auto-git'`);

  // One-shot backfill for the seeded May 2026 entries + early Track E/F/G
  // work. Each UPDATE is gated on category IS NULL OR category = 'development'
  // (the default) so it's idempotent and never overwrites a manual choice.
  const BACKFILL_RULES = [
    { cat: 'infrastructure', patterns: ['%Railway%', '%infrastructure%planning%'] },
    { cat: 'infrastructure', patterns: ['%Twilio%', '%notification architecture%'] },
    { cat: 'infrastructure', patterns: ['%SendGrid DNS%', '%Cloudflare%DNS%'] },
    { cat: 'infrastructure', patterns: ['%Postgres%', '%form handler%'] },
    { cat: 'communications', patterns: ['%Stakeholder%', '%email comms%'] },
    { cat: 'development',    patterns: ['%notifications build%', '%forms portal%'] },
    { cat: 'development',    patterns: ['%Project tracker%', '%Kanban%'] },
    { cat: 'development',    patterns: ['%Track G%', '%Prompt A%', '%Track F%'] },
    { cat: 'infrastructure', patterns: ['%SendGrid API key rotation%'] },
    { cat: 'project-mgmt',   patterns: ['%Ticket pipeline%', '%Project management%'] },
    { cat: 'planning',       patterns: ['%Architecture%spec writing%', '%Prompt D%', '%Prompt B%'] }
  ];
  for (const rule of BACKFILL_RULES) {
    const ors = rule.patterns.map((_, i) => `description ILIKE $${i + 2}`).join(' OR ');
    await pool.query(
      `UPDATE time_entries
          SET category = $1
        WHERE (category IS NULL OR category = 'development')
          AND (${ors})`,
      [rule.cat, ...rule.patterns]
    );
  }

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

    // Track G follow-up: backfill May 9 + May 11 2026 from git log (no
    // auto-tracker was running yet). Idempotent per-date: only inserts when
    // the (user, date) is empty so re-running this block on redeploy is
    // a no-op. The cap bump below ensures the warning + cap alerts stay
    // quiet for this historical insert.
    await pool.query(
      `UPDATE user_time_settings SET monthly_hours_cap = 30
        WHERE user_id = $1 AND monthly_hours_cap < 30`,
      [seanId]
    );
    const MAY_9_11_BACKFILL = [
      {
        date: '2026-05-09',
        minutes: 465,
        desc: 'FlippingBook brochure integration (CSP/embed/iframe), blocker system + nag notifications, showroom check-in form, knowledge base with seeded docs, time tracker category breakdown, nav UX redesign, warranty photo upload',
      },
      {
        date: '2026-05-11',
        minutes: 480,
        desc: 'Forms → Pipedrive hot leads, weekly sales report scheduler, approval badges on Kanban, target account landing pages (Dream Doors, Impala, Dimension Stone, Hammertime), partner brand assets + alpha-advantage page, blocker nag fixes, Contact Us nav restructure, fab guide prep',
      },
    ];
    for (const e of MAY_9_11_BACKFILL) {
      const existing = await pool.query(
        `SELECT 1 FROM time_entries WHERE user_id = $1 AND date = $2::date LIMIT 1`,
        [seanId, e.date]
      );
      if (!existing.rows.length) {
        await pool.query(
          `INSERT INTO time_entries (ticket_id, user_id, date, minutes, description, category, source)
           VALUES (NULL, $1, $2, $3, $4, 'development', 'backfill-git')`,
          [seanId, e.date, e.minutes, e.desc]
        );
        console.log(`[projects/time] backfilled ${e.date}: ${e.minutes}m for Sean`);
      }
    }
    // Pre-mark May 2026 warning + cap alerts as already sent so the
    // backfill doesn't trigger emails for past hours. Forward-looking
    // alerts (overage rungs above 30h) still fire when crossed.
    await pool.query(
      `INSERT INTO time_alerts (user_id, month, alert_type)
       VALUES ($1, '2026-05', '15hr_warning'), ($1, '2026-05', '20hr_reached'),
              ($1, '2026-05', '30hr_reached')
       ON CONFLICT (user_id, month, alert_type) DO NOTHING`,
      [seanId]
    );
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

  // Seed knowledge-base articles — only when the table is empty so manual
  // edits via the Docs UI aren't blown away on redeploy.
  const kb = await pool.query('SELECT COUNT(*)::int AS c FROM knowledge_articles');
  if (kb.rows[0].c === 0 && KB_SEED.length) {
    for (let i = 0; i < KB_SEED.length; i++) {
      const a = KB_SEED[i];
      await pool.query(
        `INSERT INTO knowledge_articles (slug, title, category, content, sort_order, author, published)
         VALUES ($1, $2, $3, $4, $5, 'Sean Stone', TRUE)
         ON CONFLICT (slug) DO NOTHING`,
        [a.slug, a.title, a.category, a.content, i]
      );
    }
    console.log(`[projects] seeded ${KB_SEED.length} knowledge-base articles`);
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
    reviewers: 'Reviewers', approver: 'Approver',
    blocked_by: 'Blocked by', blocked_reason: 'Blocker reason'
  };
  const label = labelMap[col] || col;
  // Long fields (description) — collapse to "Updated description"
  if (col === 'description' || col === 'title') {
    return { action: 'edited', detail: `Updated ${label.toLowerCase()}` };
  }
  if (col === 'blocked_reason') {
    // Reason text can be long — keep the activity feed compact.
    return { action: 'blocker_updated', detail: 'Updated blocker reason' };
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
  else if (col === 'blocked_by') action = newVal ? 'blocker_set' : 'blocker_cleared';
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

// ─── Track I: typed-form helpers ─────────────────────────────────────────
//
// FORM_TYPES describes every typed form table — the prefix powers reference
// number generation, the route segment is the URL slug, and the legacy
// form_type values are what server.js writes into form_submissions.form_type
// today. Adding a new form means adding one entry here + creating the table
// in initSchema; the CRUD route factory below picks it up automatically.
const FORM_TYPES = {
  sample:   { table: 'sample_requests',      prefix: 'SR', route: 'samples',   legacy: ['Sample Request'],
              statuses: ['new', 'processing', 'shipped', 'completed', 'archived'] },
  enquiry:  { table: 'enquiries',            prefix: 'EN', route: 'enquiries', legacy: ['Enquiry'],
              statuses: ['new', 'read', 'responded', 'closed', 'archived'] },
  warranty: { table: 'warranty_activations', prefix: 'WA', route: 'warranty',  legacy: ['Warranty Activation'],
              statuses: ['new', 'under_review', 'approved', 'rejected', 'archived'] },
  contact:  { table: 'contact_submissions',  prefix: 'CT', route: 'contacts',  legacy: ['Contact'],
              statuses: ['new', 'read', 'responded', 'closed', 'archived'] },
  partner:  { table: 'partner_enquiries',    prefix: 'PA', route: 'partners',  legacy: ['Partner', 'Trade'],
              statuses: ['new', 'read', 'meeting_scheduled', 'approved', 'declined', 'archived'] },
  showroom: { table: 'showroom_checkins',    prefix: 'SC', route: 'showroom',  legacy: ['Showroom Check-In'],
              statuses: ['new', 'followed_up', 'converted', 'no_response', 'archived'] }
};

// Generate the next reference number for a typed form table. Uses a
// transactional row count to keep the sequence dense + 1-based; SR-0001,
// SR-0002, … Concurrency note: in the unlikely case two inserts race on
// the same count we'll get a UNIQUE collision on the reference column —
// the caller catches the 23505 and retries with the next count. That race
// is exceedingly rare for the volumes Alpha Surfaces sees.
async function nextRef(pool, table, prefix) {
  const { rows } = await pool.query(`SELECT COUNT(*)::int AS c FROM ${table}`);
  const n = rows[0].c + 1;
  return `${prefix}-${String(n).padStart(4, '0')}`;
}

async function logTypedFormActivity(pool, formType, recordId, user, action, detail) {
  try {
    await pool.query(
      `INSERT INTO form_activity_log (form_type, record_id, user_id, user_name, action, detail)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [formType, recordId, (user && user.userId) || null, (user && user.name) || 'System', action, detail || null]
    );
  } catch (err) {
    console.error('[projects/forms-typed] activity log error:', err.message);
  }
}

// Insert a public form submission into the matching typed table. Called
// from server.js handleForm right after the legacy form_submissions write,
// so a single submit lands in BOTH places (typed table for the new UI,
// legacy table for archive/search). Returns { reference, id, table } on
// success, or null if the formType isn't one we have a typed table for.
async function insertTypedSubmission(pool, legacyFormType, fields, sampleItems = []) {
  const typeKey = (() => {
    // Contact Enquiry is shared between the public contact form and the
    // partner/trade form — store_location distinguishes them.
    if (legacyFormType === 'Contact Enquiry') {
      const loc = fields && (fields.store_location || fields.company);
      return (loc && String(loc).trim()) ? 'partner' : 'contact';
    }
    for (const k of Object.keys(FORM_TYPES)) {
      if (FORM_TYPES[k].legacy.includes(legacyFormType)) return k;
    }
    return null;
  })();
  if (!typeKey) return null;
  const cfg = FORM_TYPES[typeKey];
  const consent = !!fields.consent;
  const name = fields.name
    || `${fields.first_name || ''} ${fields.last_name || ''}`.trim()
    || null;
  // Stone interest can come either as a free-text field or as a chosen
  // sampleItems list (sample-request page builds the list from picks).
  const stoneInterest = fields.stone_interest
    || (Array.isArray(sampleItems) && sampleItems.length
      ? sampleItems.map(s => s.name || s.slug).filter(Boolean).join(', ')
      : null);
  // Wrap insert in a tiny retry to absorb the rare nextRef race when two
  // submissions land in the same millisecond.
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const ref = await nextRef(pool, cfg.table, cfg.prefix);
      let result;
      if (typeKey === 'sample') {
        result = await pool.query(
          `INSERT INTO sample_requests
             (reference, name, email, phone, company, role, stone_interest, message,
              street, suburb, unit, state, postcode, source, consent)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
           RETURNING id, reference`,
          [ref, name, fields.email, fields.phone, fields.company,
           fields.i_am_a || fields.role || fields.type || null,
           stoneInterest, fields.message || fields.special_instructions || null,
           fields.street, fields.suburb, fields.unit,
           fields.state || null, fields.postcode || null,
           fields.source, consent]
        );
      } else if (typeKey === 'enquiry') {
        const message = fields.message || fields.special_instructions || '';
        if (!message) return null; // enquiry table requires non-null message
        result = await pool.query(
          `INSERT INTO enquiries
             (reference, name, email, phone, company, role, reason, message, consent)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
           RETURNING id, reference`,
          [ref, name, fields.email, fields.phone, fields.company,
           fields.i_am_a || fields.role || null,
           fields.reason || fields.enquiry_reason || null,
           message, consent]
        );
      } else if (typeKey === 'warranty') {
        const isoDate = v => (v && /^\d{4}-\d{2}-\d{2}/.test(String(v))) ? v : null;
        const purchase = isoDate(fields.purchase_date);
        const install  = isoDate(fields.installation_date);
        result = await pool.query(
          `INSERT INTO warranty_activations
             (reference, name, email, phone, street, suburb, state, postcode,
              stone_name, batch_number, lot_number, application, coverage_type,
              purchase_date, installation_date, fabricator, retailer, invoice_number,
              installation_photos, photo_consent, consent)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
           RETURNING id, reference`,
          [ref, name, fields.email, fields.phone || '',
           fields.street || '', fields.suburb || '', fields.state || '', fields.postcode || '',
           fields.stone_name || fields.stone_interest || '',
           fields.batch_number || null, fields.lot_number || null,
           fields.application || null,
           fields.coverage_type || fields.warranty_type || null,
           purchase, install, fields.fabricator || '', fields.retailer || null, fields.invoice_number || null,
           Array.isArray(fields.installation_photos) ? fields.installation_photos : [],
           !!fields.photo_consent,
           consent]
        );
      } else if (typeKey === 'contact') {
        const message = fields.message || '';
        if (!message) return null;
        result = await pool.query(
          `INSERT INTO contact_submissions
             (reference, name, email, phone, message, consent)
           VALUES ($1,$2,$3,$4,$5,$6)
           RETURNING id, reference`,
          [ref, name, fields.email, fields.phone, message, consent]
        );
      } else if (typeKey === 'partner') {
        result = await pool.query(
          `INSERT INTO partner_enquiries
             (reference, name, email, phone, company, role, reason, message, consent)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
           RETURNING id, reference`,
          [ref, name, fields.email, fields.phone,
           fields.company || fields.store_location || '',
           fields.i_am_a || fields.role || null,
           fields.reason || null,
           fields.message || null,
           consent]
        );
      } else if (typeKey === 'showroom') {
        result = await pool.query(
          `INSERT INTO showroom_checkins
             (reference, name, email, phone, interests, visitor_type, state,
              source, notes, consent)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
           RETURNING id, reference`,
          [ref, name, fields.email || null, fields.phone,
           fields.interested_in || null,
           fields.i_am_a || fields.role || null,
           fields.state || null,
           fields.source || null,
           fields.message || fields.notes || null, consent]
        );
      } else {
        return null;
      }
      return { table: cfg.table, id: result.rows[0].id, reference: result.rows[0].reference, type: typeKey };
    } catch (err) {
      if (err.code === '23505') continue; // reference collision — retry
      console.error(`[projects/${typeKey}] typed insert error:`, err.message);
      return null;
    }
  }
  return null;
}

// One-time copy from form_submissions into the typed tables. Routes by
// form_type column; raw_data JSONB picks up fields that never made it into
// dedicated columns (warranty extras, partner reason). Newsletter rows live
// in their own table already (see db.js) so they're not part of this sweep.
async function migrateFormSubmissionsIntoTypedTables(pool) {
  console.log('[projects/migrate] starting form_submissions → typed-tables copy');
  // For sample requests, the picked stones live in sample_request_items not
  // form_submissions.stone_interest. Pre-aggregate so each row gets a real
  // comma-joined list (e.g. "Jewel, Carrara") instead of NULL.
  const { rows: sampleStoneRows } = await pool.query(
    `SELECT submission_id, string_agg(stone_name, ', ' ORDER BY id) AS stones
       FROM sample_request_items
      GROUP BY submission_id`
  );
  const stonesBySubmissionId = new Map();
  for (const r of sampleStoneRows) stonesBySubmissionId.set(r.submission_id, r.stones);
  const { rows } = await pool.query(`SELECT * FROM form_submissions ORDER BY id ASC`);
  let counts = { sample: 0, enquiry: 0, warranty: 0, contact: 0, partner: 0, skipped: 0 };
  for (const s of rows) {
    const ft = String(s.form_type || '');
    const rd = (s.raw_data && typeof s.raw_data === 'object') ? s.raw_data : {};
    const consent = !!s.consent;
    try {
      if (ft === 'Sample Request') {
        const ref = await nextRef(pool, 'sample_requests', 'SR');
        const stoneInterest = stonesBySubmissionId.get(s.id) || s.stone_interest || null;
        // postcode/state were not captured as dedicated columns on the
        // legacy form_submissions table — fall back to raw_data when they
        // do exist there.
        const postcode = s.postcode || rd.postcode || null;
        const stateAU  = s.state    || rd.state    || null;
        await pool.query(
          `INSERT INTO sample_requests
             (reference, name, email, phone, company, role, stone_interest, message,
              street, suburb, unit, state, postcode, source, consent, status, created_at, updated_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$17)`,
          [ref, s.name, s.email, s.phone, s.company, s.role, stoneInterest, s.message,
           s.street, s.suburb, s.unit, stateAU, postcode, s.source, consent, s.status || 'new', s.submitted_at]
        );
        counts.sample++;
      } else if (ft === 'Enquiry') {
        if (!s.message) { counts.skipped++; continue; }
        const ref = await nextRef(pool, 'enquiries', 'EN');
        await pool.query(
          `INSERT INTO enquiries
             (reference, name, email, phone, company, role, reason, message,
              consent, status, created_at, updated_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11)`,
          [ref, s.name, s.email, s.phone, s.company, s.role, s.reason, s.message,
           consent, s.status || 'new', s.submitted_at]
        );
        counts.enquiry++;
      } else if (ft === 'Warranty Activation') {
        const ref = await nextRef(pool, 'warranty_activations', 'WA');
        const purchase = rd.purchase_date || null;
        await pool.query(
          `INSERT INTO warranty_activations
             (reference, name, email, phone, street, suburb, state, postcode,
              stone_name, purchase_date, fabricator, retailer, invoice_number,
              installation_photos, consent, status, created_at, updated_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$17)`,
          [ref, s.name, s.email, s.phone || rd.phone || '',
           s.street || rd.street || '', s.suburb || rd.suburb || '',
           s.state || rd.state || '', s.postcode || rd.postcode || '',
           s.stone_interest || rd.stone_interest || rd.stone_name || '',
           purchase && /^\d{4}-\d{2}-\d{2}/.test(String(purchase)) ? purchase : null,
           rd.fabricator || '', rd.retailer || null, rd.invoice_number || null,
           Array.isArray(rd.installation_photos) ? rd.installation_photos : [],
           consent, s.status || 'new', s.submitted_at]
        );
        counts.warranty++;
      } else if (ft === 'Contact Enquiry') {
        // Track I splits the legacy "Contact Enquiry" by store_location:
        // partner enquiries always carry one (showroom/trade contact form);
        // pure contact form submissions don't.
        const isPartner = !!(s.store_location && String(s.store_location).trim());
        if (!s.message) { counts.skipped++; continue; }
        if (isPartner) {
          const ref = await nextRef(pool, 'partner_enquiries', 'PA');
          await pool.query(
            `INSERT INTO partner_enquiries
               (reference, name, email, phone, company, role, reason, message,
                consent, status, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11)`,
            [ref, s.name, s.email, s.phone, s.company || s.store_location, s.role, s.reason, s.message,
             consent, s.status || 'new', s.submitted_at]
          );
          counts.partner++;
        } else {
          const ref = await nextRef(pool, 'contact_submissions', 'CT');
          await pool.query(
            `INSERT INTO contact_submissions
               (reference, name, email, phone, message, consent, status, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8)`,
            [ref, s.name, s.email, s.phone, s.message, consent, s.status || 'new', s.submitted_at]
          );
          counts.contact++;
        }
      } else {
        counts.skipped++;
      }
    } catch (err) {
      console.error('[projects/migrate] row', s.id, 'error:', err.message);
    }
  }
  console.log('[projects/migrate] done:', JSON.stringify(counts));
}

// Backfill stone_interest on sample_requests rows that came through the
// initial typed-table migration with NULL/empty stones. The data lives in
// sample_request_items (linked to form_submissions, not sample_requests),
// so we re-match on name+email+created_at to find the originating
// form_submissions row, then aggregate its items.
//
// Idempotent by construction: only processes rows where stone_interest is
// blank, so a re-run after success simply finds nothing to do.
async function backfillSampleRequestStoneInterest(pool) {
  const { rows: blanks } = await pool.query(
    `SELECT sr.id, sr.name, sr.email, sr.created_at FROM sample_requests sr
      WHERE sr.stone_interest IS NULL OR sr.stone_interest = '' OR sr.stone_interest = '—'`
  );
  if (!blanks.length) return;
  console.log('[projects/backfill] sample_requests stone_interest:', blanks.length, 'row(s) to backfill');
  let fixed = 0;
  for (const sr of blanks) {
    if (!sr.name || !sr.email) continue;
    const { rows: matches } = await pool.query(
      `SELECT fs.id FROM form_submissions fs
        WHERE LOWER(fs.name) = LOWER($1) AND LOWER(fs.email) = LOWER($2)
          AND fs.form_type = 'Sample Request'
        ORDER BY ABS(EXTRACT(EPOCH FROM (fs.submitted_at - $3::timestamptz))) ASC
        LIMIT 1`,
      [sr.name, sr.email, sr.created_at]
    );
    if (!matches.length) continue;
    const { rows: items } = await pool.query(
      `SELECT string_agg(stone_name, ', ' ORDER BY id) AS stones
         FROM sample_request_items WHERE submission_id = $1`,
      [matches[0].id]
    );
    if (items[0]?.stones) {
      await pool.query(
        'UPDATE sample_requests SET stone_interest = $1 WHERE id = $2',
        [items[0].stones, sr.id]
      );
      fixed++;
    }
  }
  console.log('[projects/backfill] sample_requests stone_interest: fixed', fixed, 'row(s)');
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
          'SELECT id, email, name, role, password_hash, active, must_change_password, default_view FROM project_users WHERE LOWER(email) = LOWER($1)',
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
              must_change_password: !!u.must_change_password,
              default_view: u.default_view || 'kanban'
            });
          }
        }
      } catch (err) {
        console.error('[projects-login] db error:', err.message);
      }
    }

    // Legacy forms password bridge. Old /forms URLs now redirect into
    // /projects?view=forms, but staff may still know only the old forms
    // password. Let that password create an operator session that lands in
    // the Projects forms tab without resurrecting a separate forms page.
    const legacyFormsHash = readLegacyFormsPasswordHash();
    const legacyFormsEnv = process.env.FORMS_PASSWORD;
    if (await passwordMatches(supplied, legacyFormsHash) || await passwordMatches(supplied, legacyFormsEnv)) {
      let linkedUser = null;
      if (email && typeof email === 'string') {
        try {
          const { rows } = await pool.query(
            'SELECT id, email, name, role, active FROM project_users WHERE LOWER(email) = LOWER($1)',
            [email.trim()]
          );
          if (rows.length && rows[0].active && rows[0].role !== 'viewer') linkedUser = rows[0];
        } catch (err) {
          console.error('[projects-login] legacy forms user lookup error:', err.message);
        }
      }
      return issueSession(res, {
        userId: linkedUser && linkedUser.role === 'operator' ? linkedUser.id : null,
        email: linkedUser ? linkedUser.email : (email || 'forms@alphasurfaces.com.au'),
        name: linkedUser ? linkedUser.name : 'Forms',
        role: 'operator',
        source: 'forms_password',
        must_change_password: false,
        default_view: 'forms'
      });
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
          must_change_password: false,
          default_view: 'kanban'
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
      user: {
        userId: payload.userId || null,
        email: payload.email, name: payload.name, role: payload.role,
        default_view: payload.default_view || 'kanban'
      },
      must_change_password: !!payload.must_change_password
    });
  }

  app.post('/api/projects-logout', (req, res) => {
    const token = req.cookies?.projects_session;
    if (token) projectsSessions.delete(token);
    res.clearCookie('projects_session');
    res.json({ ok: true });
  });

  app.get('/api/projects-auth-check', async (req, res) => {
    const user = resolveUser(req);
    if (!user) return res.json({ authenticated: false });
    // Pull the current default_view from the DB so it always reflects the
    // latest preference (the in-memory session may be stale after a PATCH).
    let defaultView = user.default_view || 'kanban';
    if (user.userId) {
      try {
        const { rows } = await pool.query(
          'SELECT default_view FROM project_users WHERE id = $1', [user.userId]
        );
        if (rows.length && rows[0].default_view) defaultView = rows[0].default_view;
      } catch (err) {
        console.error('[projects-auth-check] default_view lookup error:', err.message);
      }
    }
    res.json({
      authenticated: true,
      user: { userId: user.userId || null,
              email: user.email, name: user.name, role: user.role,
              initials: initialsFromName(user.name),
              default_view: defaultView },
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

  router.get('/me', async (req, res) => {
    let defaultView = 'kanban';
    if (req.user.userId) {
      try {
        const { rows } = await pool.query(
          'SELECT default_view FROM project_users WHERE id = $1', [req.user.userId]
        );
        if (rows.length && rows[0].default_view) defaultView = rows[0].default_view;
      } catch (err) {
        console.error('[projects/me] default_view lookup error:', err.message);
      }
    }
    res.json({
      ok: true,
      user: {
        email: req.user.email, name: req.user.name, role: req.user.role,
        initials: initialsFromName(req.user.name), source: req.user.source,
        default_view: defaultView
      }
    });
  });

  // Update the user's landing-view preference. Body: { default_view: 'forms' }.
  // Role-gated: forms is blocked for viewers, time is super_admin-only — the
  // server enforces this so the UI can't quietly persist an inaccessible view.
  router.patch('/me/default-view', async (req, res) => {
    try {
      const v = String(req.body?.default_view || '').trim().toLowerCase();
      if (!ALLOWED_DEFAULT_VIEWS.includes(v)) {
        return res.status(400).json({ ok: false, error: 'Invalid view.' });
      }
      if (v === 'forms' && req.user.role === 'viewer') {
        return res.status(403).json({ ok: false, error: 'Viewers cannot land on the forms view.' });
      }
      if (v === 'time' && req.user.role !== 'super_admin') {
        return res.status(403).json({ ok: false, error: 'Time tracking is restricted to super_admin.' });
      }
      if (!req.user.userId) {
        return res.status(400).json({ ok: false, error: 'Default view cannot be set on the master admin session.' });
      }
      await pool.query(
        'UPDATE project_users SET default_view = $1 WHERE id = $2',
        [v, req.user.userId]
      );
      // Update the in-memory session record so the next /me hit returns the
      // new value immediately, without waiting for re-login.
      const token = req.cookies?.projects_session;
      if (token && projectsSessions.has(token)) {
        const sess = projectsSessions.get(token);
        sess.default_view = v;
        projectsSessions.set(token, sess);
      }
      res.json({ ok: true, default_view: v });
    } catch (err) {
      console.error('[projects] default-view error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
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

  // ── Track I: typed form CRUD (per-form-type endpoints) ─────────────
  //
  // Each form type gets list / stats / detail / patch / export under its own
  // route segment, all gated by requireFormsAccess (super_admin + operator).
  // The factory keeps the per-form code DRY — only column lists and the few
  // type-specific bits diverge.
  function mountTypedFormRoutes(typeKey) {
    const cfg = FORM_TYPES[typeKey];
    const { table, route, statuses } = cfg;
    const path = '/' + route;

    // List with filters: status, search (name/email/reference/message),
    // date range (from/to ISO dates). Returns rows + totals + status counts.
    router.get(path, requireFormsAccess, async (req, res) => {
      try {
        const limit  = Math.min(parseInt(req.query.limit  || '100', 10) || 100, 500);
        const offset = Math.max(parseInt(req.query.offset || '0',   10) || 0,   0);
        const where = [];
        const vals  = [];
        if (req.query.status) {
          vals.push(req.query.status);
          where.push(`status = $${vals.length}`);
        }
        if (req.query.from) {
          vals.push(req.query.from);
          where.push(`created_at >= $${vals.length}::date`);
        }
        if (req.query.to) {
          vals.push(req.query.to);
          where.push(`created_at < ($${vals.length}::date + INTERVAL '1 day')`);
        }
        if (req.query.q) {
          vals.push('%' + req.query.q + '%');
          const i = vals.length;
          // Build a search clause from whichever text-bearing columns this
          // table actually has — name/email/reference are universal; the
          // rest are conditionally added based on FORM_TYPES.
          const cols = ['name', 'email', 'reference'];
          if (typeKey === 'sample' || typeKey === 'enquiry' || typeKey === 'partner') cols.push('company');
          if (typeKey === 'enquiry' || typeKey === 'partner' || typeKey === 'contact') cols.push('message');
          if (typeKey === 'sample') cols.push('stone_interest');
          if (typeKey === 'warranty') cols.push('stone_name', 'fabricator', 'suburb',
            'batch_number', 'lot_number', 'application', 'coverage_type');
          if (typeKey === 'showroom') cols.push('phone', 'interests', 'visitor_type', 'state', 'notes', 'source');
          where.push('(' + cols.map(c => `${c} ILIKE $${i}`).join(' OR ') + ')');
        }
        const whereSql = where.length ? ' WHERE ' + where.join(' AND ') : '';
        const { rows } = await pool.query(
          `SELECT * FROM ${table}${whereSql}
            ORDER BY created_at DESC, id DESC
            LIMIT $${vals.length + 1} OFFSET $${vals.length + 2}`,
          [...vals, limit, offset]
        );
        const totalQ  = await pool.query(`SELECT COUNT(*)::int AS c FROM ${table}${whereSql}`, vals);
        const statusQ = await pool.query(`SELECT status, COUNT(*)::int AS c FROM ${table} GROUP BY status`);
        const counts = { new: 0, total: 0 };
        statusQ.rows.forEach(r => { counts[r.status] = r.c; counts.total += r.c; });
        res.json({ ok: true, rows, total: totalQ.rows[0].c, counts, statuses });
      } catch (err) {
        console.error(`[projects/${typeKey}] list error:`, err.message);
        res.status(500).json({ ok: false, error: err.message });
      }
    });

    // Cheap counts endpoint for the nav-dropdown badges. Kept separate from
    // the list endpoint so the dropdown can refresh without the full payload.
    router.get(path + '/stats', requireFormsAccess, async (req, res) => {
      try {
        const statusQ = await pool.query(`SELECT status, COUNT(*)::int AS c FROM ${table} GROUP BY status`);
        // "Today" is calendar-day in Brisbane time so the dashboard count
        // matches what Jess sees on the showroom iPad.
        const todayQ = await pool.query(
          `SELECT COUNT(*)::int AS c FROM ${table}
            WHERE (created_at AT TIME ZONE 'Australia/Brisbane')::date
                = (NOW()       AT TIME ZONE 'Australia/Brisbane')::date`
        );
        const weekQ = await pool.query(
          `SELECT COUNT(*)::int AS c FROM ${table} WHERE created_at >= NOW() - INTERVAL '7 days'`
        );
        const monthQ = await pool.query(
          `SELECT COUNT(*)::int AS c FROM ${table} WHERE created_at >= NOW() - INTERVAL '30 days'`
        );
        const by_status = {};
        let total = 0;
        statusQ.rows.forEach(r => { by_status[r.status] = r.c; total += r.c; });
        res.json({
          ok: true,
          total,
          by_status,
          new: by_status.new || 0,
          today: todayQ.rows[0].c,
          this_week: weekQ.rows[0].c,
          this_month: monthQ.rows[0].c
        });
      } catch (err) {
        res.status(500).json({ ok: false, error: err.message });
      }
    });

    // Export must come before /:id so Express doesn't match "export" as the id.
    router.get(path + '/export', requireFormsAccess, async (req, res) => {
      try {
        const where = [];
        const vals = [];
        if (req.query.status) { vals.push(req.query.status); where.push(`status = $${vals.length}`); }
        if (req.query.from)   { vals.push(req.query.from);   where.push(`created_at >= $${vals.length}::date`); }
        if (req.query.to)     { vals.push(req.query.to);     where.push(`created_at < ($${vals.length}::date + INTERVAL '1 day')`); }
        const whereSql = where.length ? ' WHERE ' + where.join(' AND ') : '';
        const { rows } = await pool.query(
          `SELECT * FROM ${table}${whereSql} ORDER BY created_at ASC`, vals
        );
        // Use the first row's column list as the header — falls back to a
        // hand-picked subset when the table is empty.
        const cols = rows.length ? Object.keys(rows[0]) : ['reference','name','email','status','created_at'];
        const escapeCSV = v => {
          if (v == null) return '';
          if (Array.isArray(v)) return '"' + v.map(x => String(x).replace(/"/g, '""')).join(' | ') + '"';
          const s = v instanceof Date ? v.toISOString() : (typeof v === 'object' ? JSON.stringify(v) : String(v));
          return (s.includes(',') || s.includes('"') || s.includes('\n'))
            ? `"${s.replace(/"/g, '""')}"` : s;
        };
        const csv = [
          cols.join(','),
          ...rows.map(r => cols.map(c => escapeCSV(r[c])).join(','))
        ].join('\n');
        await logTypedFormActivity(pool, typeKey, 0, req.user, 'export', `Exported ${rows.length} rows`);
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="${route}-${Date.now()}.csv"`);
        res.send(csv);
      } catch (err) {
        console.error(`[projects/${typeKey}] export error:`, err.message);
        res.status(500).json({ ok: false, error: err.message });
      }
    });

    // Activity feed — separate endpoint so the detail drawer can fetch it lazily.
    router.get(path + '/:id/activity', requireFormsAccess, async (req, res) => {
      try {
        const id = parseInt(req.params.id, 10);
        if (!id) return res.status(400).json({ ok: false, error: 'Invalid id' });
        const { rows } = await pool.query(
          `SELECT id, user_id, user_name, action, detail, created_at
             FROM form_activity_log
            WHERE form_type = $1 AND record_id = $2
            ORDER BY created_at DESC, id DESC`,
          [typeKey, id]
        );
        res.json({ ok: true, activity: rows });
      } catch (err) {
        res.status(500).json({ ok: false, error: err.message });
      }
    });

    router.get(path + '/:id', requireFormsAccess, async (req, res) => {
      try {
        const id = parseInt(req.params.id, 10);
        if (!id) return res.status(400).json({ ok: false, error: 'Invalid id' });
        const { rows } = await pool.query(`SELECT * FROM ${table} WHERE id = $1`, [id]);
        if (!rows.length) return res.status(404).json({ ok: false, error: 'Not found' });
        res.json({ ok: true, record: rows[0] });
      } catch (err) {
        res.status(500).json({ ok: false, error: err.message });
      }
    });

    // Patch handles status + notes. Warranty has the additional side-effect
    // of stamping warranty_number / approved_at / approved_by when status
    // moves to 'approved'. The check is gated to first-time approval so a
    // demote-then-reapprove keeps the original warranty number.
    router.patch(path + '/:id', requireFormsAccess, async (req, res) => {
      try {
        const id = parseInt(req.params.id, 10);
        if (!id) return res.status(400).json({ ok: false, error: 'Invalid id' });
        const b = req.body || {};
        const sets = [];
        const vals = [];
        const before = await pool.query(`SELECT * FROM ${table} WHERE id = $1`, [id]);
        if (!before.rows.length) return res.status(404).json({ ok: false, error: 'Not found' });
        const oldRow = before.rows[0];
        const changes = [];

        if (Object.prototype.hasOwnProperty.call(b, 'status')) {
          if (!statuses.includes(b.status)) {
            return res.status(400).json({ ok: false, error: `status must be one of ${statuses.join(', ')}` });
          }
          if (b.status !== oldRow.status) {
            vals.push(b.status); sets.push(`status = $${vals.length}`);
            changes.push({ field: 'status', from: oldRow.status, to: b.status });
            // Warranty: auto-assign warranty number on first approval.
            if (typeKey === 'warranty' && b.status === 'approved' && !oldRow.warranty_number) {
              const yr = new Date().getFullYear();
              const seqQ = await pool.query(
                `SELECT COUNT(*)::int AS c FROM warranty_activations
                  WHERE warranty_number LIKE $1`,
                [`AW-${yr}-%`]
              );
              const num = `AW-${yr}-${String(seqQ.rows[0].c + 1).padStart(4, '0')}`;
              vals.push(num); sets.push(`warranty_number = $${vals.length}`);
              sets.push(`approved_at = NOW()`);
              vals.push(req.user.name || 'Unknown');
              sets.push(`approved_by = $${vals.length}`);
              changes.push({ field: 'warranty_number', from: null, to: num });
            }
          }
        }
        if (Object.prototype.hasOwnProperty.call(b, 'notes')) {
          const notes = b.notes == null ? null : String(b.notes);
          if (notes !== oldRow.notes) {
            vals.push(notes); sets.push(`notes = $${vals.length}`);
            changes.push({ field: 'notes', from: oldRow.notes, to: notes });
          }
        }
        if (typeKey === 'showroom' && Object.prototype.hasOwnProperty.call(b, 'follow_up_date')) {
          const fud = b.follow_up_date && /^\d{4}-\d{2}-\d{2}$/.test(String(b.follow_up_date))
            ? b.follow_up_date : null;
          const old = oldRow.follow_up_date
            ? new Date(oldRow.follow_up_date).toISOString().slice(0, 10) : null;
          if (fud !== old) {
            vals.push(fud); sets.push(`follow_up_date = $${vals.length}`);
            changes.push({ field: 'follow_up_date', from: old, to: fud });
          }
        }
        if (!sets.length) return res.json({ ok: true, record: oldRow, unchanged: true });
        sets.push(`updated_at = NOW()`);
        vals.push(id);
        const { rows } = await pool.query(
          `UPDATE ${table} SET ${sets.join(', ')} WHERE id = $${vals.length} RETURNING *`,
          vals
        );
        for (const c of changes) {
          if (c.field === 'status') {
            await logTypedFormActivity(pool, typeKey, id, req.user, 'status_changed',
              `Status: ${c.from || '—'} → ${c.to}`);
          } else if (c.field === 'notes') {
            await logTypedFormActivity(pool, typeKey, id, req.user, 'notes_updated', 'Updated notes');
          } else if (c.field === 'warranty_number') {
            await logTypedFormActivity(pool, typeKey, id, req.user, 'warranty_assigned',
              `Assigned warranty number ${c.to}`);
          } else if (c.field === 'follow_up_date') {
            await logTypedFormActivity(pool, typeKey, id, req.user, 'follow_up_set',
              `Follow-up: ${c.from || '—'} → ${c.to || '—'}`);
          }
        }
        res.json({ ok: true, record: rows[0] });
      } catch (err) {
        console.error(`[projects/${typeKey}] patch error:`, err.message);
        res.status(500).json({ ok: false, error: err.message });
      }
    });
  }

  // Mount routes for every typed form. Newsletter sits separately because
  // its table predates Track I (see db.js) and the schema diverges.
  Object.keys(FORM_TYPES).forEach(mountTypedFormRoutes);

  // Aggregated counts across all typed-form tables — powers the nav dropdown
  // badges on the Forms ▾ menu. One query per table, run in parallel.
  router.get('/forms-counts', requireFormsAccess, async (req, res) => {
    try {
      const entries = await Promise.all(Object.keys(FORM_TYPES).map(async (key) => {
        const { table } = FORM_TYPES[key];
        const r = await pool.query(`SELECT
            COUNT(*) FILTER (WHERE status = 'new')::int AS new_count,
            COUNT(*)::int AS total
          FROM ${table}`);
        return [key, { new: r.rows[0].new_count, total: r.rows[0].total }];
      }));
      // Newsletter — uses the legacy newsletter_subscribers schema.
      const nl = await pool.query(
        `SELECT COUNT(*) FILTER (WHERE status = 'active')::int AS active,
                COUNT(*)::int AS total FROM newsletter_subscribers`
      );
      const counts = Object.fromEntries(entries);
      counts.newsletter = { new: 0, total: nl.rows[0].total, active: nl.rows[0].active };
      res.json({ ok: true, counts });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── Newsletter (super_admin only — separate from Track I form tables) ──
  router.get('/newsletter', requireRole('super_admin'), async (req, res) => {
    try {
      const limit  = Math.min(parseInt(req.query.limit  || '500', 10) || 500, 5000);
      const offset = Math.max(parseInt(req.query.offset || '0',   10) || 0,   0);
      const where  = [];
      const vals   = [];
      if (req.query.status) { vals.push(req.query.status); where.push(`status = $${vals.length}`); }
      if (req.query.q) {
        vals.push('%' + req.query.q + '%'); const i = vals.length;
        where.push(`(email ILIKE $${i})`);
      }
      const whereSql = where.length ? ' WHERE ' + where.join(' AND ') : '';
      const { rows } = await pool.query(
        `SELECT id, email, consent_timestamp_utc AS subscribed_at,
                unsubscribed_timestamp_utc AS unsubscribed_at,
                unsubscribe_method, source_url, status
           FROM newsletter_subscribers${whereSql}
          ORDER BY consent_timestamp_utc DESC
          LIMIT $${vals.length + 1} OFFSET $${vals.length + 2}`,
        [...vals, limit, offset]
      );
      const totalQ = await pool.query(`SELECT COUNT(*)::int AS c FROM newsletter_subscribers${whereSql}`, vals);
      res.json({ ok: true, rows, total: totalQ.rows[0].c });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  router.get('/newsletter/export', requireRole('super_admin'), async (req, res) => {
    try {
      const { rows } = await pool.query(
        `SELECT email, consent_timestamp_utc AS subscribed_at, status, source_url
           FROM newsletter_subscribers WHERE status = 'active'
          ORDER BY consent_timestamp_utc ASC`
      );
      const escapeCSV = v => v == null ? '' : (String(v).includes(',') ? `"${String(v).replace(/"/g, '""')}"` : String(v));
      const csv = ['email,subscribed_at,status,source',
        ...rows.map(r => [r.email, r.subscribed_at, r.status, r.source_url].map(escapeCSV).join(','))
      ].join('\n');
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="newsletter-${Date.now()}.csv"`);
      res.send(csv);
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── Track G: knowledge base ────────────────────────────────────────
  router.get('/kb', async (req, res) => {
    try {
      const { rows } = await pool.query(
        `SELECT slug, title, category, sort_order, updated_at, published
           FROM knowledge_articles
          WHERE published = TRUE
          ORDER BY category ASC, sort_order ASC, title ASC`
      );
      res.json({ ok: true, articles: rows });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  router.get('/kb/search', async (req, res) => {
    try {
      const q = String(req.query.q || '').trim();
      if (!q) return res.json({ ok: true, results: [] });
      const { rows } = await pool.query(
        `SELECT slug, title, category,
                LEFT(content, 200) AS preview
           FROM knowledge_articles
          WHERE published = TRUE
            AND (title ILIKE $1 OR content ILIKE $1)
          ORDER BY category, title
          LIMIT 50`,
        ['%' + q + '%']
      );
      res.json({ ok: true, results: rows });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  router.get('/kb/:slug', async (req, res) => {
    try {
      const { rows } = await pool.query(
        `SELECT * FROM knowledge_articles WHERE slug = $1`,
        [String(req.params.slug)]
      );
      if (!rows.length) return res.status(404).json({ ok: false, error: 'Not found' });
      res.json({ ok: true, article: rows[0] });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  router.post('/kb', requireRole('super_admin'), async (req, res) => {
    try {
      const b = req.body || {};
      const slug     = String(b.slug || '').trim().toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/^-+|-+$/g, '');
      const title    = String(b.title || '').trim();
      const category = String(b.category || '').trim();
      const content  = String(b.content || '').trim();
      const sort     = parseInt(b.sort_order, 10) || 0;
      const published = b.published == null ? true : !!b.published;
      if (!slug || !title || !category || !content) {
        return res.status(400).json({ ok: false, error: 'slug, title, category and content are required.' });
      }
      const { rows } = await pool.query(
        `INSERT INTO knowledge_articles (slug, title, category, content, sort_order, author, published)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
        [slug, title, category, content, sort, req.user.name || 'Unknown', published]
      );
      res.json({ ok: true, article: rows[0] });
    } catch (err) {
      if (err.code === '23505') return res.status(409).json({ ok: false, error: 'Slug already exists.' });
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  router.patch('/kb/:slug', requireRole('super_admin'), async (req, res) => {
    try {
      const slug = String(req.params.slug);
      const b = req.body || {};
      const sets = [];
      const vals = [];
      ['title', 'category', 'content'].forEach(f => {
        if (Object.prototype.hasOwnProperty.call(b, f)) {
          vals.push(String(b[f] || '')); sets.push(`${f} = $${vals.length}`);
        }
      });
      if (Object.prototype.hasOwnProperty.call(b, 'sort_order')) {
        vals.push(parseInt(b.sort_order, 10) || 0); sets.push(`sort_order = $${vals.length}`);
      }
      if (Object.prototype.hasOwnProperty.call(b, 'published')) {
        vals.push(!!b.published); sets.push(`published = $${vals.length}`);
      }
      if (!sets.length) return res.status(400).json({ ok: false, error: 'No updatable fields supplied.' });
      vals.push(req.user.name || 'Unknown'); sets.push(`updated_by = $${vals.length}`);
      sets.push(`updated_at = NOW()`);
      vals.push(slug);
      const { rows } = await pool.query(
        `UPDATE knowledge_articles SET ${sets.join(', ')} WHERE slug = $${vals.length} RETURNING *`,
        vals
      );
      if (!rows.length) return res.status(404).json({ ok: false, error: 'Not found' });
      res.json({ ok: true, article: rows[0] });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  router.delete('/kb/:slug', requireRole('super_admin'), async (req, res) => {
    try {
      const { rowCount } = await pool.query(
        `DELETE FROM knowledge_articles WHERE slug = $1`,
        [String(req.params.slug)]
      );
      if (!rowCount) return res.status(404).json({ ok: false, error: 'Not found' });
      res.json({ ok: true });
    } catch (err) {
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

  // GET: time-entry category taxonomy. super_admin only (matches the rest of
  // the time API). Surfaces the labels + colours so the front-end doesn't
  // duplicate the list.
  router.get('/time/categories', requireRole('super_admin'), (req, res) => {
    res.json({ ok: true, categories: TIME_CATEGORIES });
  });

  // POST: log a time entry. super_admin only — time tracking is scoped to
  // Sean's consulting hours against a monthly cap. Operators / viewers don't
  // have access. The ticket_id visibility check below is harmless under this
  // tighter policy (a super_admin sees every ticket), kept for defensive
  // symmetry should the policy ever broaden again.
  router.post('/time/entries', requireRole('super_admin'), async (req, res) => {
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
      const category = b.category && ALLOWED_TIME_CATEGORIES.includes(b.category)
        ? b.category : 'development';
      const { rows } = await pool.query(
        `INSERT INTO time_entries (ticket_id, user_id, date, minutes, description, category)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING *`,
        [ticketId, req.user.userId, date, minutes, desc, category]
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

  // GET: list time entries (paginated). super_admin only.
  router.get('/time/entries', requireRole('super_admin'), async (req, res) => {
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
                COALESCE(te.category, 'development') AS category,
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

  // GET: monthly summary across active users. super_admin only.
  router.get('/time/summary', requireRole('super_admin'), async (req, res) => {
    try {
      const month = req.query.month || currentMonth();
      const range = monthRange(month);
      if (!range) return res.status(400).json({ ok: false, error: 'month must be YYYY-MM' });
      const vals = [range.start, range.end];
      const { rows } = await pool.query(
        `SELECT u.id AS user_id, u.name, u.email, u.role,
                COALESCE(s.monthly_hours_cap, 20) AS monthly_hours_cap,
                COALESCE(s.warning_hours, 15)     AS warning_hours,
                COALESCE(SUM(te.minutes), 0)::int AS total_minutes
           FROM project_users u
           LEFT JOIN user_time_settings s ON s.user_id = u.id
           LEFT JOIN time_entries te
             ON te.user_id = u.id AND te.date >= $1::date AND te.date < $2::date
          WHERE u.active = TRUE
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
  // super_admin only.
  router.get('/time/summary/:userId', requireRole('super_admin'), async (req, res) => {
    try {
      const userId = parseInt(req.params.userId, 10);
      if (!Number.isFinite(userId)) return res.status(400).json({ ok: false, error: 'Invalid user id' });
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
      // Per-category breakdown for the timesheet stacked-bar chart. COALESCE
      // collapses NULL category rows into 'development' (the default).
      const byCategoryQ = await pool.query(
        `SELECT COALESCE(category, 'development') AS category,
                COALESCE(SUM(minutes), 0)::int AS minutes
           FROM time_entries
          WHERE user_id = $1 AND date >= $2::date AND date < $3::date
          GROUP BY COALESCE(category, 'development')
          ORDER BY minutes DESC`,
        [userId, range.start, range.end]
      );
      const entriesQ = await pool.query(
        `SELECT te.id, te.ticket_id, te.date, te.minutes, te.description, te.created_at,
                COALESCE(te.category, 'development') AS category,
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
        by_category: byCategoryQ.rows.map(r => ({
          category: r.category,
          label: TIME_CATEGORY_LABEL[r.category] || r.category,
          color: TIME_CATEGORY_COLOR[r.category] || '#6B7280',
          minutes: r.minutes,
          hours: Math.round((r.minutes / 60) * 100) / 100,
          percent: totalMinutes > 0 ? Math.round((r.minutes / totalMinutes) * 100) : 0
        })),
        categories: TIME_CATEGORIES,
        entries: entriesQ.rows
      });
    } catch (err) {
      console.error('[projects/time] user summary error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // GET: CSV export of time entries. super_admin only.
  router.get('/time/export', requireRole('super_admin'), async (req, res) => {
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
                t.title AS ticket_title, te.minutes, te.description,
                COALESCE(te.category, 'development') AS category
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
      const header = ['Date','Category','Ticket ID','Ticket Title','Hours','Minutes','Description'];
      const lines = rows.map(r => [
        escapeCSV(r.date),
        escapeCSV(TIME_CATEGORY_LABEL[r.category] || r.category),
        escapeCSV(r.ticket_id),
        escapeCSV(r.ticket_title),
        escapeCSV((r.minutes / 60).toFixed(2)),
        escapeCSV(r.minutes),
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

  // GET: branded printable timesheet report. Renders an HTML page with the
  // letterhead, monthly summary, category breakdown, and full daily activity
  // log. Opens in a new tab and is print-friendly (`@media print` strips the
  // page background but keeps the olive header bar so it still reads as
  // Alpha Surfaces stationery).
  router.get('/time/report', requireRole('super_admin'), async (req, res) => {
    try {
      const month = req.query.month || currentMonth();
      const range = monthRange(month);
      if (!range) return res.status(400).json({ ok: false, error: 'month must be YYYY-MM' });
      const userId = parseInt(req.query.user_id, 10);
      if (!Number.isFinite(userId)) {
        return res.status(400).json({ ok: false, error: 'user_id required' });
      }
      const userQ = await pool.query(
        `SELECT u.id, u.name, u.email,
                COALESCE(s.monthly_hours_cap, 20) AS monthly_hours_cap
           FROM project_users u
           LEFT JOIN user_time_settings s ON s.user_id = u.id
          WHERE u.id = $1`,
        [userId]
      );
      if (!userQ.rows.length) return res.status(404).send('User not found');
      const user = userQ.rows[0];

      const entriesQ = await pool.query(
        `SELECT te.date, te.minutes, te.description,
                COALESCE(te.category, 'development') AS category,
                te.ticket_id, t.title AS ticket_title
           FROM time_entries te
           LEFT JOIN tickets t ON t.ticket_id = te.ticket_id
          WHERE te.user_id = $1 AND te.date >= $2::date AND te.date < $3::date
          ORDER BY te.date DESC, te.id DESC`,
        [userId, range.start, range.end]
      );

      const totalMinutes = entriesQ.rows.reduce((s, r) => s + r.minutes, 0);
      const totalHours = totalMinutes / 60;
      const cap = user.monthly_hours_cap;
      const percent = cap > 0 ? Math.round((totalHours / cap) * 100) : 0;

      // Category aggregation
      const catTotals = {};
      entriesQ.rows.forEach(r => {
        catTotals[r.category] = (catTotals[r.category] || 0) + r.minutes;
      });
      const categoryRows = Object.keys(catTotals).map(k => ({
        key: k,
        label: TIME_CATEGORY_LABEL[k] || k,
        color: TIME_CATEGORY_COLOR[k] || '#6B7280',
        minutes: catTotals[k],
        hours: catTotals[k] / 60,
        percent: totalMinutes > 0 ? Math.round((catTotals[k] / totalMinutes) * 100) : 0
      })).sort((a, b) => b.minutes - a.minutes);

      // Group entries by date for the activity log section.
      const byDate = {};
      entriesQ.rows.forEach(r => {
        const d = r.date instanceof Date ? r.date.toISOString().slice(0, 10) : String(r.date).slice(0, 10);
        (byDate[d] = byDate[d] || []).push(r);
      });
      const dateKeys = Object.keys(byDate).sort().reverse();

      const monthLabel = new Date(`${range.start}T00:00:00Z`).toLocaleString('en-AU', {
        month: 'long', year: 'numeric', timeZone: 'UTC'
      });
      const fmtHM = (mins) => {
        const h = Math.floor(mins / 60);
        const m = mins % 60;
        return `${h}h ${String(m).padStart(2, '0')}m`;
      };
      const fmtDate = (iso) => {
        const d = new Date(`${iso}T00:00:00Z`);
        return d.toLocaleString('en-AU', { weekday: 'short', day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' });
      };
      const generatedAt = new Date().toLocaleString('en-AU', {
        timeZone: 'Australia/Brisbane', day: 'numeric', month: 'long', year: 'numeric',
        hour: '2-digit', minute: '2-digit', hour12: false
      });

      // Stacked bar — one segment per category, in descending size order.
      const stackedBar = categoryRows.map(c =>
        `<span style="display:inline-block;width:${c.percent}%;height:18px;background:${c.color}" title="${esc(c.label)} ${c.percent}%"></span>`
      ).join('');

      const categoryBreakdown = categoryRows.map(c => `
        <tr>
          <td style="padding:8px 12px"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${c.color};margin-right:8px;vertical-align:middle"></span>${esc(c.label)}</td>
          <td style="padding:8px 12px;text-align:right;font-variant-numeric:tabular-nums">${fmtHM(c.minutes)}</td>
          <td style="padding:8px 12px;text-align:right;font-variant-numeric:tabular-nums;color:#666">${c.percent}%</td>
        </tr>
      `).join('');

      const dailyLog = dateKeys.map(d => {
        const rows = byDate[d];
        const dayMin = rows.reduce((s, r) => s + r.minutes, 0);
        const items = rows.map(r => `
          <tr class="entry-row">
            <td style="padding:8px 12px;border-bottom:1px solid #eee;white-space:nowrap">
              <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${TIME_CATEGORY_COLOR[r.category] || '#6B7280'};margin-right:6px;vertical-align:middle"></span>
              ${esc(TIME_CATEGORY_LABEL[r.category] || r.category)}
            </td>
            <td style="padding:8px 12px;border-bottom:1px solid #eee;font-variant-numeric:tabular-nums;white-space:nowrap">${fmtHM(r.minutes)}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #eee">
              ${r.ticket_id ? `<strong style="color:#564D22;margin-right:6px">${esc(r.ticket_id)}</strong>` : ''}
              ${esc(r.description || (r.ticket_title ? r.ticket_title : '—'))}
            </td>
          </tr>
        `).join('');
        return `
          <table style="width:100%;border-collapse:collapse;margin:0 0 18px;background:#fff">
            <thead>
              <tr style="background:#f7f4e8">
                <th colspan="2" style="text-align:left;padding:10px 12px;font-size:13px;letter-spacing:0.06em;text-transform:uppercase;color:#564D22;border-bottom:1px solid #ddd">${esc(fmtDate(d))}</th>
                <th style="text-align:right;padding:10px 12px;font-size:13px;color:#564D22;font-variant-numeric:tabular-nums;border-bottom:1px solid #ddd">${fmtHM(dayMin)}</th>
              </tr>
            </thead>
            <tbody>${items}</tbody>
          </table>
        `;
      }).join('');

      const html = `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Consulting Timesheet — ${esc(user.name)} — ${esc(monthLabel)}</title>
<style>
  body { margin: 0; padding: 0; background: #f3f1e6; font-family: 'Helvetica Neue', Arial, sans-serif; color: #222; }
  .sheet { max-width: 880px; margin: 0 auto; padding: 32px 28px 60px; }
  .letterhead { background: #564D22; color: #fff; padding: 24px 28px; border-radius: 6px 6px 0 0; }
  .letterhead .brand { font-size: 11px; letter-spacing: 0.18em; text-transform: uppercase; color: #f3f1e6; opacity: 0.9; }
  .letterhead h1 { margin: 4px 0 2px; font-size: 22px; font-weight: 700; }
  .letterhead .meta { font-size: 13px; color: #f3f1e6; opacity: 0.85; }
  .body { background: #fff; padding: 28px; border-radius: 0 0 6px 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.06); }
  .summary { margin-bottom: 24px; padding-bottom: 20px; border-bottom: 1px solid #e8e5d3; }
  .summary h2 { font-size: 13px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: #888; margin-bottom: 10px; }
  .total-line { font-size: 18px; font-weight: 700; color: #222; margin-bottom: 10px; }
  .total-line .pct { color: #888; font-weight: 400; font-size: 14px; margin-left: 8px; }
  .stacked-bar { width: 100%; height: 18px; background: #f3f1e6; border-radius: 3px; overflow: hidden; display: flex; }
  .legend { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
  .section { margin: 28px 0 16px; font-size: 13px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: #888; }
  .footer { margin-top: 36px; padding-top: 18px; border-top: 1px solid #e8e5d3; font-size: 12px; color: #999; text-align: center; }
  .toolbar { max-width: 880px; margin: 16px auto 0; padding: 0 28px; text-align: right; }
  .toolbar button { background: #564D22; color: #fff; border: none; padding: 9px 18px; border-radius: 4px; font-size: 13px; font-weight: 600; letter-spacing: 0.04em; cursor: pointer; font-family: inherit; }
  .toolbar button:hover { background: #3f3819; }
  @media print {
    body { background: #fff; }
    .toolbar { display: none; }
    .sheet { padding: 0; }
    .body { box-shadow: none; padding: 18px 0; }
    .letterhead { -webkit-print-color-adjust: exact; print-color-adjust: exact; border-radius: 0; }
    .stacked-bar span, .legend td span { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  }
</style>
</head><body>
<div class="toolbar"><button type="button" onclick="window.print()">Print / Save as PDF</button></div>
<div class="sheet">
  <div class="letterhead">
    <div class="brand">Alpha Surfaces</div>
    <h1>Consulting Timesheet — ${esc(user.name)}</h1>
    <div class="meta">${esc(monthLabel)} · ${esc(user.email || '')}</div>
  </div>
  <div class="body">
    <div class="summary">
      <h2>Monthly Summary</h2>
      <div class="total-line">${totalHours.toFixed(1)} / ${cap} hrs <span class="pct">(${percent}%)</span></div>
      <div class="stacked-bar">${stackedBar}</div>
      <table class="legend">
        <thead>
          <tr style="border-bottom:1px solid #e8e5d3">
            <th style="text-align:left;padding:10px 12px;font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:#888;font-weight:700">Category</th>
            <th style="text-align:right;padding:10px 12px;font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:#888;font-weight:700">Hours</th>
            <th style="text-align:right;padding:10px 12px;font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:#888;font-weight:700">%</th>
          </tr>
        </thead>
        <tbody>${categoryBreakdown || '<tr><td colspan="3" style="padding:14px;color:#999;text-align:center">No time logged this month.</td></tr>'}</tbody>
      </table>
    </div>
    <div class="section">Daily Activity Log</div>
    ${dailyLog || '<div style="padding:14px;color:#999;text-align:center">No entries.</div>'}
    <div class="footer">Generated from Alpha Surfaces Project Tracker on ${esc(generatedAt)} AEST</div>
  </div>
</div>
</body></html>`;
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(html);
    } catch (err) {
      console.error('[projects/time] report error:', err.message);
      res.status(500).send('Report generation failed: ' + err.message);
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

  // ── Approval helpers ─────────────────────────────────────────────────
  // Match a user against a ticket's named approver. Full name OR first name,
  // case-insensitive — same rules the rest of the codebase uses.
  function isTicketApprover(user, ticket) {
    if (!user || !ticket || !ticket.approver) return false;
    if (user.role === 'super_admin') return true;
    const name = String(user.name || '').trim().toLowerCase();
    if (!name) return false;
    const first = name.split(/\s+/)[0];
    const target = String(ticket.approver).trim().toLowerCase();
    const targetFirst = target.split(/\s+/)[0];
    return target === name || target === first || targetFirst === name || targetFirst === first;
  }

  // When the approver clicks Approve, peek at the ticket's description + notes
  // for words that suggest the work has already shipped. If so, jump straight
  // to 'done'; otherwise the ticket sits in review with a green APPROVED badge
  // so the assignee knows to deploy.
  const DEPLOYED_RE = /\b(deployed|deploy(?:ed)? to (?:prod|production|main)|in production|live on (?:prod|production|main)|shipped|released|rolled out|implemented|pushed to (?:prod|production|main))\b/i;
  function looksDeployed(ticket) {
    const blob = [ticket.description || '', ticket.notes || ''].join('\n');
    return DEPLOYED_RE.test(blob);
  }

  // Shared approve / request_changes pipeline. Returns the updated ticket row.
  // Both POST /review and PATCH approval_status funnel through here so the
  // audit trail, emails, and status transitions stay consistent.
  async function applyApprovalDecision(pool, ticket, user, decision, feedback) {
    const fb = feedback ? String(feedback).trim() : '';
    if (decision === 'changes_requested' && !fb) {
      const err = new Error('Feedback is required when requesting changes.');
      err.status = 400;
      throw err;
    }

    // Audit row first — never lose history if the UPDATE fails.
    await pool.query(
      `INSERT INTO ticket_reviews (ticket_id, reviewer_id, reviewer_name, action, feedback, role)
       VALUES ($1, $2, $3, $4, $5, 'approver')`,
      [ticket.ticket_id, user.userId || null, user.name || 'Unknown', decision, fb || null]
    );

    let updated = ticket;
    if (decision === 'approved') {
      const targetStatus = looksDeployed(ticket) ? 'done' : 'review';
      const upd = await pool.query(
        `UPDATE tickets SET status = $2, approval_status = 'approved',
                            review_started_at = NULL, updated_at = NOW()
          WHERE id = $1 RETURNING *`,
        [ticket.id, targetStatus]
      );
      updated = upd.rows[0];
      // Auto-log to ticket notes for visibility outside the review tab.
      const noteLine = fb ? `Approved by ${user.name}: ${fb}` : `Approved by ${user.name}`;
      updated = await appendNote(pool, ticket.ticket_id, user, noteLine) || updated;
      logActivity(pool, ticket.ticket_id, user, 'approved',
        targetStatus === 'done'
          ? (fb ? `Approved: ${fb} — moved to done` : 'Approved — moved to done')
          : (fb ? `Approved: ${fb} — awaiting deployment` : 'Approved — awaiting deployment'));
      if (notifyApproved) {
        notifyApproved(pool, updated, user.name, fb)
          .catch(e => console.error('[projects/review] approved email dispatch:', e.message));
      }
    } else if (decision === 'changes_requested') {
      const upd = await pool.query(
        `UPDATE tickets SET status = 'in_progress', approval_status = 'changes_requested',
                            review_started_at = NULL, updated_at = NOW()
          WHERE id = $1 RETURNING *`,
        [ticket.id]
      );
      updated = upd.rows[0];
      updated = await appendNote(pool, ticket.ticket_id, user, `Changes requested by ${user.name}: ${fb}`) || updated;
      logActivity(pool, ticket.ticket_id, user, 'changes_requested', fb);
      if (notifyChangesRequested) {
        notifyChangesRequested(pool, updated, user.name, fb)
          .catch(e => console.error('[projects/review] changes_requested email dispatch:', e.message));
      }
    } else {
      const err = new Error('Invalid approval decision.');
      err.status = 400;
      throw err;
    }
    return updated;
  }

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
      // approval_status is approver-only — short-circuit straight to the
      // shared decision pipeline so PATCH and POST /review share one code
      // path. Reject anything but 'approved' / 'changes_requested' here so
      // the column-loop below can keep treating approval_status as derived.
      if (Object.prototype.hasOwnProperty.call(req.body || {}, 'approval_status')) {
        const incoming = String(req.body.approval_status || '').trim();
        if (incoming !== 'approved' && incoming !== 'changes_requested') {
          return res.status(400).json({
            ok: false,
            error: 'approval_status can only be set to "approved" or "changes_requested" via PATCH.'
          });
        }
        if (!isTicketApprover(req.user, oldRow)) {
          return res.status(403).json({
            ok: false,
            error: `Only the named approver (${oldRow.approver || '—'}) can change approval_status.`
          });
        }
        try {
          const ticket = await applyApprovalDecision(
            pool, oldRow, req.user, incoming,
            req.body.feedback || req.body.note || ''
          );
          return res.json({ ok: true, ticket });
        } catch (e) {
          return res.status(e.status || 500).json({ ok: false, error: e.message });
        }
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

      // Blocker permission gate: super_admins can always set/clear; everyone
      // else can only clear a blocker they set themselves. Setting a new
      // blocker is open to anyone with ticket write access.
      if (req.user.role !== 'super_admin'
          && Object.prototype.hasOwnProperty.call(req.body || {}, 'blocked_by')
          && oldRow.blocked_by) {
        const incoming = req.body.blocked_by;
        const isCleared = incoming == null || incoming === '';
        const isReplaced = !isCleared && String(incoming).trim() !== oldRow.blocked_by;
        if (isCleared || isReplaced) {
          if (!req.user.userId || oldRow.blocked_set_by_user_id !== req.user.userId) {
            return res.status(403).json({
              ok: false,
              error: 'Only a super_admin or the person who set this blocker can clear or replace it.'
            });
          }
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
          if (col === 'blocked_by' && newVal != null) newVal = String(newVal).trim() || null;
          if (col === 'blocked_reason' && newVal != null) newVal = String(newVal).trim() || null;
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

      // Blocker transition side-effects. The "cleared" trigger reads the
      // request payload (not the diff) so a stale row carrying derived
      // fields without a blocked_by name still gets fully wiped — the red
      // badge only disappears once blocked_at + blocker_last_nagged +
      // blocked_set_by_user_id are all NULL alongside blocked_by.
      const blockerChange = changed.find(c => c.col === 'blocked_by');
      const reasonChange  = changed.find(c => c.col === 'blocked_reason');
      const blockerInPatch = Object.prototype.hasOwnProperty.call(req.body || {}, 'blocked_by');
      const incomingBlocker = blockerInPatch ? req.body.blocked_by : undefined;
      const blockerExplicitlyCleared = blockerInPatch && (
        incomingBlocker == null ||
        (typeof incomingBlocker === 'string' && incomingBlocker.trim() === '')
      );
      const blockerJustSet = blockerChange && !blockerChange.oldVal && blockerChange.newVal;
      if (blockerJustSet) {
        sets.push(`blocked_at = NOW()`);
        sets.push(`blocker_last_nagged = NULL`);
        if (req.user.userId) {
          vals.push(req.user.userId);
          sets.push(`blocked_set_by_user_id = $${vals.length}`);
        } else {
          sets.push(`blocked_set_by_user_id = NULL`);
        }
      } else if (blockerExplicitlyCleared) {
        // Defensive: always wipe every derived field so a partial-state row
        // (e.g. blocked_at set but blocked_by null) can't keep the badge red.
        // blocked_by itself was already pushed by the loop above.
        sets.push(`blocked_at = NULL`);
        sets.push(`blocker_last_nagged = NULL`);
        sets.push(`blocked_set_by_user_id = NULL`);
        // Force-clear reason too — UI hides reason anyway when no blocker is set.
        if (!Object.prototype.hasOwnProperty.call(req.body || {}, 'blocked_reason')) {
          vals.push(null);
          sets.push(`blocked_reason = $${vals.length}`);
        }
      } else if (reasonChange && oldRow.blocked_by) {
        // Reason was edited mid-block. Reset the nag clock so the next email
        // includes the updated wording instead of going out 2 days later
        // with stale text.
        sets.push(`blocker_last_nagged = NULL`);
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

      // Status email — only when status actually moved. Goes to the assignee
      // + every active super_admin (deduped, no self-notify).
      const statusChange = changed.find(c => c.col === 'status');
      if (statusChange && sendTicketStatusEmail) {
        sendTicketStatusEmail(pool, newRow, statusChange.oldVal, statusChange.newVal, req.user)
          .catch(err => console.error('[projects] status email dispatch:', err.message));
      }

      // Blocker email — fire the moment a blocker goes on. The cron handles
      // follow-ups. Reason-only edits don't re-fire (the next cron tick will
      // pick it up because we cleared blocker_last_nagged above).
      if (blockerJustSet && sendBlockerNotice) {
        sendBlockerNotice(pool, newRow, req.user.name)
          .catch(err => console.error('[projects/blocker] notice email dispatch:', err.message));
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

      let updated = ticket;
      if (action === 'approve' || action === 'request_changes') {
        const decision = action === 'approve' ? 'approved' : 'changes_requested';
        try {
          updated = await applyApprovalDecision(pool, ticket, req.user, decision, feedback);
        } catch (e) {
          return res.status(e.status || 500).json({ ok: false, error: e.message });
        }
      } else {
        // reviewer_feedback: advisory only, doesn't change status. But it
        // does advance pending_review → pending_approval per the spec
        // ("after 24h OR when any reviewer leaves feedback, whichever first").
        await pool.query(
          `INSERT INTO ticket_reviews (ticket_id, reviewer_id, reviewer_name, action, feedback, role)
           VALUES ($1, $2, $3, 'feedback', $4, 'reviewer')`,
          [ticket.ticket_id, req.user.userId || null, req.user.name || 'Unknown', feedback || null]
        );
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
  // codebase. multer may not be available in test contexts — the upload
  // routes degrade to a 503 when so. Files land on the persistent volume
  // (ATTACHMENTS_DIR) and are served back via /api/projects/attachments/:f.
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

        // Sanitise the original extension. Strip anything non-alphanumeric so
        // a hostile filename like "x.<script>" can't smuggle markup into the
        // stored path or the Content-Disposition header.
        const origName = req.file.originalname || 'file';
        const rawExt = path.extname(origName).toLowerCase().replace(/[^a-z0-9.]/g, '');
        const ext = rawExt && rawExt.length <= 10 ? rawExt : '';
        const storedName = crypto.randomUUID() + ext;
        await fs.promises.mkdir(ATTACHMENTS_DIR, { recursive: true });
        await fs.promises.writeFile(path.join(ATTACHMENTS_DIR, storedName), req.file.buffer);

        // Store the URL the frontend uses verbatim — same shape Cloudinary
        // gave us, so render code (`a.url`) keeps working.
        const url = `/api/projects/attachments/${storedName}`;

        const ins = await pool.query(
          `INSERT INTO ticket_attachments
             (ticket_id, user_id, user_name, filename, url, mime_type, size_bytes, context)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
          [ticketId, req.user.userId || null, req.user.name || 'Unknown',
           origName, url,
           req.file.mimetype || null, req.file.size || null, context]
        );
        logActivity(pool, ticketId, req.user, 'attachment_added',
          `Attached ${origName} (${context})`);
        res.json({ ok: true, attachment: ins.rows[0] });
      } catch (err) {
        console.error('[projects] attachment upload error:', err.message);
        res.status(500).json({ ok: false, error: err.message });
      }
    }
  );

  // Serve a stored attachment. Filename is the random UUID + extension we
  // saved at upload time — the basename guard rejects anything containing a
  // separator so a crafted "../../etc/passwd" can't escape ATTACHMENTS_DIR.
  // Access is gated to users who can see the owning ticket.
  router.get('/attachments/:filename', async (req, res) => {
    try {
      const filename = req.params.filename || '';
      if (!/^[A-Za-z0-9._-]+$/.test(filename) || filename !== path.basename(filename)) {
        return res.status(400).json({ ok: false, error: 'Invalid filename.' });
      }
      const url = `/api/projects/attachments/${filename}`;
      const att = await pool.query(
        `SELECT a.*, t.assigned_to, t.id AS t_id
           FROM ticket_attachments a
           JOIN tickets t ON t.ticket_id = a.ticket_id
          WHERE a.url = $1 LIMIT 1`,
        [url]
      );
      if (!att.rows.length) return res.status(404).json({ ok: false, error: 'Not found' });
      const row = att.rows[0];
      if (!canAccessTicket(req.user, { assigned_to: row.assigned_to, id: row.t_id })) {
        return res.status(404).json({ ok: false, error: 'Not found' });
      }
      const filePath = path.join(ATTACHMENTS_DIR, filename);
      if (!fs.existsSync(filePath)) return res.status(404).json({ ok: false, error: 'File missing on disk.' });
      if (row.mime_type) res.setHeader('Content-Type', row.mime_type);
      // inline so browsers preview images/PDFs; ASCII-only quoted name plus
      // RFC 5987 filename* for the original UTF-8 name.
      const safeOrig = String(row.filename || 'file').replace(/[\r\n"]/g, '');
      const asciiName = safeOrig.replace(/[^\x20-\x7E]/g, '_');
      res.setHeader('Content-Disposition',
        `inline; filename="${asciiName}"; filename*=UTF-8''${encodeURIComponent(safeOrig)}`);
      res.setHeader('Cache-Control', 'private, max-age=300');
      fs.createReadStream(filePath).pipe(res);
    } catch (err) {
      console.error('[projects] attachment serve error:', err.message);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

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
          `DELETE FROM ticket_attachments WHERE id = $1 RETURNING ticket_id, filename, url`,
          [att]
        );
        if (!rows.length) return res.status(404).json({ ok: false, error: 'Attachment not found.' });
        // Unlink the on-disk file for local-storage attachments. Legacy
        // Cloudinary URLs (https://…) are skipped — best-effort cleanup,
        // never block the response on a stat/unlink failure.
        const url = rows[0].url || '';
        const m = url.match(/^\/api\/projects\/attachments\/([A-Za-z0-9._-]+)$/);
        if (m) {
          fs.promises.unlink(path.join(ATTACHMENTS_DIR, m[1]))
            .catch(err => console.error('[projects] attachment unlink:', err.message));
        }
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

  // ── Blocker nag scheduler ───────────────────────────────────────────
  //
  // Fires once per day around 09:00 Australia/Brisbane. Reuses the same
  // setInterval + Brisbane-hour pattern as the daily digest in server.js so
  // we don't introduce a new dependency. Each ticket dedupes via
  // blocker_last_nagged: emails go out the first time a blocker has been
  // open for ≥0 days, then every 2 days after that, until the blocker is
  // cleared.
  function brisbaneTodayString() {
    return new Date().toLocaleDateString('en-CA', { timeZone: 'Australia/Brisbane' });
  }
  function brisbaneHour() {
    const parts = new Intl.DateTimeFormat('en-AU', {
      timeZone: 'Australia/Brisbane', hour: 'numeric', hour12: false
    }).formatToParts(new Date());
    const h = parts.find(p => p.type === 'hour');
    return h ? parseInt(h.value, 10) : 0;
  }
  let lastBlockerSweepDay = null;
  async function runBlockerNagSweep() {
    try {
      // Atomic claim: UPDATE with the cooldown predicate, RETURNING the row.
      // Because the UPDATE itself bumps blocker_last_nagged, a second
      // overlapping sweep on the same minute can't re-claim the ticket — it
      // sees the just-updated timestamp and the predicate filters it out.
      // Sending after the claim means the worst case on dispatch failure is a
      // missed nag (recoverable next sweep) rather than a duplicate email.
      const { rows } = await pool.query(
        `UPDATE tickets
            SET blocker_last_nagged = NOW()
          WHERE blocked_by IS NOT NULL
            AND blocked_by <> ''
            AND status NOT IN ('done', 'archived')
            AND (blocker_last_nagged IS NULL
                 OR blocker_last_nagged < NOW() - INTERVAL '2 days')
          RETURNING *`
      );
      for (const ticket of rows) {
        if (sendBlockerNagEmail) {
          try {
            await sendBlockerNagEmail(pool, ticket);
          } catch (err) {
            console.error('[blocker-nag] dispatch error for', ticket.ticket_id, ':', err.message);
            continue;
          }
        }
        console.log('[blocker-nag]', ticket.ticket_id, '→', ticket.blocked_by);
      }
      if (rows.length) console.log('[blocker-nag] sweep nagged', rows.length, 'ticket(s)');
    } catch (err) {
      console.error('[blocker-nag] sweep error:', err.message);
    }
  }
  async function checkBlockerNag() {
    const today = brisbaneTodayString();
    if (lastBlockerSweepDay === today) return;
    if (brisbaneHour() < 9) return;
    lastBlockerSweepDay = today;
    console.log('[blocker-nag] firing daily sweep for', today);
    await runBlockerNagSweep();
  }
  // Same cadence as the daily-digest scheduler in server.js. The day-string
  // gate above prevents re-firing once we've swept for the day.
  setTimeout(checkBlockerNag, 35 * 1000);
  // DISABLED 1 Sep 2026 — project tracker blocker nags retired at client request.
  // setInterval(checkBlockerNag, 60 * 1000);

  // Manual sweep endpoint — super_admin only. Useful for QA-ing the nag
  // template without waiting for 9am, and for forcing a re-send if a
  // recipient lost their initial mail.
  router.post('/blockers/run-nag', requireRole('super_admin'), async (req, res) => {
    try {
      await runBlockerNagSweep();
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

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
// Expose Track I helpers for server.js to call from /api/form-submit so a
// single submission lands in BOTH form_submissions (legacy archive) and the
// matching typed table (sample_requests/enquiries/warranty/contact/partner).
module.exports.insertTypedSubmission = insertTypedSubmission;
module.exports.FORM_TYPES = FORM_TYPES;
