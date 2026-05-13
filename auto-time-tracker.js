// Auto time tracking from GitHub commits.
//
// Pulls commits via the GitHub API for today's Brisbane day, groups by
// (matched user, Brisbane date), and UPSERTs a single time_entries row per
// user per day with source='auto-git'. Manual entries (source='manual')
// are untouched.
//
// Wiring: scheduleAutoTracker({ pool }) is called from server.js after
// initDB(). On the first tick (30s after boot) and every 60s after, it
// checks the Brisbane wall-clock; runs only on the top of an hour between
// 06:00 and 22:00. Within-hour duplicate runs are guarded by lastTickHour.

const fetch = require('node-fetch');

const GITHUB_REPO = process.env.GITHUB_REPO || 'Cangaroo007/alpha-surfaces-site';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const TZ = 'Australia/Brisbane';

// Map commit-prefix → time category. Anything unmatched falls back to
// 'development'. Keep keys aligned with TIME_CATEGORIES in projects-routes.js.
const CATEGORY_FROM_PREFIX = {
  feat:    'development',
  fix:     'development',
  refactor:'development',
  perf:    'development',
  test:    'development',
  build:   'infrastructure',
  ci:      'infrastructure',
  chore:   'infrastructure',
  docs:    'communications',
  style:   'design',
  revert:  'development',
};

function brisbaneDateString(d = new Date()) {
  return d.toLocaleDateString('en-CA', { timeZone: TZ });
}

function brisbaneHour(d = new Date()) {
  const parts = new Intl.DateTimeFormat('en-AU', {
    timeZone: TZ, hour: 'numeric', hour12: false
  }).formatToParts(d);
  const h = parts.find(p => p.type === 'hour');
  return h ? parseInt(h.value, 10) : 0;
}

// Brisbane-local start/end of a given YYYY-MM-DD, returned as UTC ISO strings
// for the GitHub API `since` / `until` params.
function brisbaneDayRangeUTC(brisDate) {
  // Brisbane is UTC+10 with no DST. Start = 00:00 AEST = previous 14:00 UTC.
  const [y, m, d] = brisDate.split('-').map(Number);
  const startUTC = new Date(Date.UTC(y, m - 1, d, -10, 0, 0));
  const endUTC = new Date(Date.UTC(y, m - 1, d + 1, -10, 0, 0));
  return { since: startUTC.toISOString(), until: endUTC.toISOString() };
}

function parseCategoryFromCommit(message) {
  const m = String(message || '').match(/^([a-z]+)(?:\([^)]+\))?\s*:/i);
  if (!m) return 'development';
  return CATEGORY_FROM_PREFIX[m[1].toLowerCase()] || 'development';
}

// Pick the category that covers the largest share of commits. Ties favour
// 'development' since that's the default in the schema.
function pickDominantCategory(commits) {
  const counts = {};
  for (const c of commits) {
    const cat = parseCategoryFromCommit(c.commit.message);
    counts[cat] = (counts[cat] || 0) + 1;
  }
  let best = 'development', bestN = -1;
  for (const [cat, n] of Object.entries(counts)) {
    if (n > bestN || (n === bestN && cat === 'development')) {
      best = cat; bestN = n;
    }
  }
  return best;
}

// Span between first and last commit + 30min buffer each side, minimum
// 30min if only one commit, round to 15min, cap at 8h.
function computeMinutes(commits) {
  if (!commits.length) return 0;
  const sortedTimes = commits
    .map(c => new Date(c.commit.author.date).getTime())
    .sort((a, b) => a - b);
  const spanMin = commits.length === 1
    ? 30
    : Math.round((sortedTimes[sortedTimes.length - 1] - sortedTimes[0]) / 60000);
  const withBuffer = spanMin + 60; // 30min each side
  const rounded = Math.round(withBuffer / 15) * 15;
  return Math.min(rounded, 480);
}

// One-line description: comma-separated first 5 subjects, truncated.
function summarizeCommits(commits) {
  const subjects = commits
    .map(c => String(c.commit.message || '').split('\n')[0].trim())
    .filter(Boolean)
    .slice(0, 6);
  let text = subjects.join('; ');
  if (text.length > 500) text = text.slice(0, 497) + '…';
  return text;
}

async function fetchCommitsForDay(brisDate) {
  if (!GITHUB_TOKEN) {
    return { ok: false, error: 'GITHUB_TOKEN not set', commits: [] };
  }
  const { since, until } = brisbaneDayRangeUTC(brisDate);
  const url = `https://api.github.com/repos/${GITHUB_REPO}/commits`
    + `?since=${encodeURIComponent(since)}&until=${encodeURIComponent(until)}&per_page=100`;
  try {
    const res = await fetch(url, {
      headers: {
        'Authorization': `token ${GITHUB_TOKEN}`,
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'alpha-surfaces-auto-tracker'
      }
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      return { ok: false, error: `GitHub ${res.status}: ${body.slice(0, 200)}`, commits: [] };
    }
    const commits = await res.json();
    return { ok: true, commits: Array.isArray(commits) ? commits : [] };
  } catch (err) {
    return { ok: false, error: err.message, commits: [] };
  }
}

// Match a commit to a project_users row by lowercased email. Returns the
// row's user_id or null if no mapping exists. Uses the user-supplied
// github_emails array on project_users so we can route Claude-authored
// commits (noreply@anthropic.com) to whichever person triggered them.
function matchCommitToUser(commit, userIndex) {
  const email = String(commit.commit?.author?.email || '').toLowerCase();
  if (!email) return null;
  return userIndex.get(email) || null;
}

async function buildUserIndex(pool) {
  const { rows } = await pool.query(
    `SELECT id, LOWER(email) AS email, github_emails FROM project_users WHERE active = TRUE`
  );
  const index = new Map();
  for (const r of rows) {
    if (r.email) index.set(r.email, r.id);
    if (Array.isArray(r.github_emails)) {
      for (const e of r.github_emails) {
        if (e) index.set(String(e).toLowerCase(), r.id);
      }
    }
  }
  return index;
}

// UPSERT one auto-tracked entry. Respects monthly_hours_cap: if the
// computed entry would push the user over cap for this month, the entry is
// trimmed to fit. Returns { action: 'inserted'|'updated'|'skipped'|'capped', ... }.
async function upsertAutoEntry(pool, userId, date, minutes, description, category) {
  // Look up current month total *excluding* any existing auto-git entry for
  // this same date — that one will be overwritten, not stacked.
  const month = date.slice(0, 7);
  const { rows: capRows } = await pool.query(
    `SELECT COALESCE(s.monthly_hours_cap, 20) AS cap
       FROM project_users u
       LEFT JOIN user_time_settings s ON s.user_id = u.id
      WHERE u.id = $1`,
    [userId]
  );
  const capMin = (capRows[0]?.cap || 20) * 60;
  const { rows: sumRows } = await pool.query(
    `SELECT COALESCE(SUM(minutes), 0)::int AS used FROM time_entries
      WHERE user_id = $1
        AND date >= ($2 || '-01')::date
        AND date <  (CASE WHEN substring($2, 6, 2)::int = 12
                          THEN (substring($2, 1, 4)::int + 1) || '-01-01'
                          ELSE substring($2, 1, 4) || '-' || lpad((substring($2, 6, 2)::int + 1)::text, 2, '0') || '-01' END)::date
        AND NOT (source = 'auto-git' AND date = $3::date)`,
    [userId, month, date]
  );
  const used = sumRows[0].used;
  const headroom = capMin - used;
  if (headroom <= 0) {
    return { action: 'skipped', reason: 'monthly cap reached', minutes: 0, used, capMin };
  }
  const finalMin = Math.min(minutes, headroom);
  const capped = finalMin < minutes;

  // INSERT … ON CONFLICT requires a unique constraint — we create a partial
  // unique index in initDB on (user_id, date) WHERE source = 'auto-git'.
  // Use a manual SELECT-then-INSERT/UPDATE so this works regardless of which
  // PG version supports partial index ON CONFLICT (PG15+ only).
  const existing = await pool.query(
    `SELECT id, minutes FROM time_entries
      WHERE user_id = $1 AND date = $2::date AND source = 'auto-git'
      LIMIT 1`,
    [userId, date]
  );
  if (existing.rows.length) {
    const prev = existing.rows[0];
    if (prev.minutes === finalMin) {
      return { action: 'unchanged', minutes: finalMin, capped };
    }
    await pool.query(
      `UPDATE time_entries
          SET minutes = $1, description = $2, category = $3
        WHERE id = $4`,
      [finalMin, description, category, prev.id]
    );
    return { action: 'updated', minutes: finalMin, capped, prevMinutes: prev.minutes };
  }
  await pool.query(
    `INSERT INTO time_entries (ticket_id, user_id, date, minutes, description, category, source)
     VALUES (NULL, $1, $2, $3, $4, $5, 'auto-git')`,
    [userId, date, finalMin, description, category]
  );
  return { action: 'inserted', minutes: finalMin, capped };
}

// Main entry point. Pulls today's Brisbane commits, groups by user, and
// UPSERTs one entry per user. Returns a summary you can log/inspect.
async function runAutoTracker({ pool, checkAndSendTimeAlert, brisDate } = {}) {
  if (!pool) throw new Error('runAutoTracker: pool required');
  const date = brisDate || brisbaneDateString();
  const { ok, commits, error } = await fetchCommitsForDay(date);
  if (!ok) {
    return { ok: false, date, error };
  }
  const userIndex = await buildUserIndex(pool);
  // Group commits by user_id.
  const byUser = new Map();
  for (const c of commits) {
    const userId = matchCommitToUser(c, userIndex);
    if (!userId) continue;
    if (!byUser.has(userId)) byUser.set(userId, []);
    byUser.get(userId).push(c);
  }
  const results = [];
  for (const [userId, userCommits] of byUser) {
    const minutes  = computeMinutes(userCommits);
    if (minutes <= 0) continue;
    const desc     = summarizeCommits(userCommits);
    const category = pickDominantCategory(userCommits);
    try {
      const r = await upsertAutoEntry(pool, userId, date, minutes, desc, category);
      results.push({ userId, commits: userCommits.length, ...r });
      // Trigger threshold alerts in the background. Only meaningful when the
      // entry actually went in (or grew), since alerts are gated on hours.
      if ((r.action === 'inserted' || r.action === 'updated') && typeof checkAndSendTimeAlert === 'function') {
        const month = date.slice(0, 7);
        checkAndSendTimeAlert(pool, userId, month).catch(e =>
          console.error('[auto-tracker] alert dispatch error:', e.message));
      }
    } catch (err) {
      console.error(`[auto-tracker] upsert failed for user ${userId}:`, err.message);
      results.push({ userId, commits: userCommits.length, action: 'error', error: err.message });
    }
  }
  return { ok: true, date, total_commits: commits.length, results };
}

// Scheduler. Fires runAutoTracker at the top of every hour between 06:00
// and 22:00 Brisbane. Uses the same setInterval+wall-clock pattern as the
// daily-digest scheduler so we don't pull a new dep.
function scheduleAutoTracker({ pool, checkAndSendTimeAlert }) {
  if (!GITHUB_TOKEN) {
    console.warn('[auto-tracker] GITHUB_TOKEN not set — auto-tracking disabled');
    return;
  }
  let lastTickHour = null;
  async function tick() {
    try {
      const h = brisbaneHour();
      if (h < 6 || h > 22) return;
      const tickKey = `${brisbaneDateString()}-${h}`;
      if (lastTickHour === tickKey) return;
      lastTickHour = tickKey;
      const result = await runAutoTracker({ pool, checkAndSendTimeAlert });
      const summary = result.ok
        ? `${result.results.length} user(s), ${result.total_commits} commits`
        : `error: ${result.error}`;
      console.log(`[auto-tracker] ${result.date} hr ${h}: ${summary}`);
    } catch (err) {
      console.error('[auto-tracker] tick error:', err.message);
    }
  }
  setTimeout(tick, 30 * 1000);
  setInterval(tick, 60 * 1000);
}

module.exports = {
  scheduleAutoTracker,
  runAutoTracker,
  // exported for tests / manual invocation
  parseCategoryFromCommit,
  pickDominantCategory,
  computeMinutes,
  summarizeCommits,
  brisbaneDateString,
  brisbaneDayRangeUTC,
};
