const { Pool } = require('pg');
const crypto = require('crypto');

const CONSENT_TEXT = 'Yes, I\'d like to receive emails from Alpha Surfaces about new collections, products and events. I can unsubscribe anytime.';

function normalizeClientSubmissionId(fields = {}) {
  const value = fields._client_submission_id || fields.client_submission_id || fields.submission_uuid;
  if (!value) return null;
  return String(value).trim().slice(0, 100) || null;
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: (function () {
    // Managed Postgres (Railway) requires SSL. A local Postgres usually does
    // not offer it and refuses the connection outright. Enable SSL only for an
    // explicitly remote host, so `node server.js` works locally with no setup.
    var url = process.env.DATABASE_URL || '';
    if (!url) return false;                       // unset -> local socket
    if (/localhost|127\.0\.0\.1|::1/.test(url)) return false;
    return { rejectUnauthorized: false };
  })(),
  connectionTimeoutMillis: Number(process.env.PG_CONNECTION_TIMEOUT_MS || 5000),
  query_timeout: Number(process.env.PG_QUERY_TIMEOUT_MS || 15000),
  statement_timeout: Number(process.env.PG_STATEMENT_TIMEOUT_MS || 15000)
});

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS form_submissions (
        id              SERIAL PRIMARY KEY,
        form_type       VARCHAR(50)  NOT NULL,
        submitted_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        name            VARCHAR(255),
        email           VARCHAR(255),
        phone           VARCHAR(50),
        company         VARCHAR(255),
        message         TEXT,
        postcode        VARCHAR(20),
        state           VARCHAR(50),
        store_location  VARCHAR(255),
        source          VARCHAR(100),
        consent         BOOLEAN DEFAULT FALSE,
        client_submission_id VARCHAR(100),
        status          VARCHAR(20)  NOT NULL DEFAULT 'new'
      );

      CREATE TABLE IF NOT EXISTS sample_request_items (
        id              SERIAL PRIMARY KEY,
        submission_id   INTEGER NOT NULL REFERENCES form_submissions(id) ON DELETE CASCADE,
        stone_slug      VARCHAR(100) NOT NULL,
        stone_name      VARCHAR(255) NOT NULL,
        collection      VARCHAR(50)
      );

      CREATE INDEX IF NOT EXISTS idx_submissions_form_type
        ON form_submissions(form_type);

      CREATE INDEX IF NOT EXISTS idx_submissions_submitted_at
        ON form_submissions(submitted_at DESC);

      CREATE INDEX IF NOT EXISTS idx_sample_items_submission
        ON sample_request_items(submission_id);
    `);

    // Idempotent column additions — safe to run on every startup. Older
    // databases may be missing some of these; new ones already have them.
    await client.query(`ALTER TABLE form_submissions ADD COLUMN IF NOT EXISTS role VARCHAR(100)`);
    await client.query(`ALTER TABLE form_submissions ADD COLUMN IF NOT EXISTS reason TEXT`);
    await client.query(`ALTER TABLE form_submissions ADD COLUMN IF NOT EXISTS raw_data JSONB`);
    await client.query(`ALTER TABLE form_submissions ADD COLUMN IF NOT EXISTS company VARCHAR(255)`);
    await client.query(`ALTER TABLE form_submissions ADD COLUMN IF NOT EXISTS stone_interest VARCHAR(255)`);
    await client.query(`ALTER TABLE form_submissions ADD COLUMN IF NOT EXISTS source VARCHAR(100)`);
    await client.query(`ALTER TABLE form_submissions ADD COLUMN IF NOT EXISTS consent BOOLEAN DEFAULT FALSE`);
    await client.query(`ALTER TABLE form_submissions ADD COLUMN IF NOT EXISTS postcode VARCHAR(20)`);
    await client.query(`ALTER TABLE form_submissions ADD COLUMN IF NOT EXISTS state VARCHAR(50)`);
    await client.query(`ALTER TABLE form_submissions ADD COLUMN IF NOT EXISTS store_location VARCHAR(255)`);
    await client.query(`ALTER TABLE form_submissions ADD COLUMN IF NOT EXISTS street VARCHAR(255)`);
    await client.query(`ALTER TABLE form_submissions ADD COLUMN IF NOT EXISTS suburb VARCHAR(255)`);
    await client.query(`ALTER TABLE form_submissions ADD COLUMN IF NOT EXISTS unit VARCHAR(100)`);
    await client.query(`ALTER TABLE form_submissions ADD COLUMN IF NOT EXISTS client_submission_id VARCHAR(100)`);
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_submissions_client_submission_id
        ON form_submissions(client_submission_id)
        WHERE client_submission_id IS NOT NULL
    `);
    console.log('[db] form_submissions migration complete');

    // One-time backfill: populate dedicated cols on rows submitted before
    // those cols existed, by reading from the raw_data JSONB safety net.
    await client.query(`
      UPDATE form_submissions
      SET
        role   = COALESCE(role,   raw_data->>'i_am_a', raw_data->>'role', raw_data->>'i_am', raw_data->>'type'),
        reason = COALESCE(reason, raw_data->>'reason', raw_data->>'enquiry_reason'),
        street = COALESCE(street, raw_data->>'street'),
        suburb = COALESCE(suburb, raw_data->>'suburb'),
        unit   = COALESCE(unit,   raw_data->>'unit')
      WHERE raw_data IS NOT NULL
        AND (role IS NULL OR reason IS NULL OR street IS NULL OR suburb IS NULL OR unit IS NULL)
    `);
    console.log('[db] Backfill from raw_data complete');

    // ─── Outreach tracking (landing-page → form attribution) ───
    // outreach_sends: one row per tracked URL handed to a prospect
    // landing_page_views: engagement pings from landing-page-tracker.js
    // outreach_conversions: form submissions linked back to the send
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS outreach_sends (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          prospect_id VARCHAR(100) NOT NULL,
          prospect_email VARCHAR(255) NOT NULL,
          prospect_name VARCHAR(255),
          prospect_company VARCHAR(255),
          am_email VARCHAR(255) NOT NULL,
          landing_page_slug VARCHAR(100) NOT NULL,
          landing_page_url TEXT NOT NULL,
          sg_message_id VARCHAR(255),
          pipedrive_contact_id VARCHAR(255),
          pipedrive_org_id VARCHAR(255),
          sent_at TIMESTAMPTZ DEFAULT NOW(),
          status VARCHAR(50) DEFAULT 'sent'
        );

        CREATE TABLE IF NOT EXISTS landing_page_views (
          id SERIAL PRIMARY KEY,
          prospect_id VARCHAR(100),
          campaign VARCHAR(100),
          am_email VARCHAR(255),
          page_path VARCHAR(255),
          viewed_date DATE DEFAULT CURRENT_DATE,
          duration_seconds INT,
          max_scroll_pct INT,
          cta_clicks JSONB DEFAULT '[]',
          referrer TEXT,
          user_agent TEXT,
          viewed_at TIMESTAMPTZ DEFAULT NOW()
        );

        ALTER TABLE landing_page_views
          ADD COLUMN IF NOT EXISTS viewed_date DATE;

        UPDATE landing_page_views
           SET viewed_date = COALESCE(viewed_date, (viewed_at AT TIME ZONE 'Australia/Brisbane')::date, CURRENT_DATE)
         WHERE viewed_date IS NULL;

        ALTER TABLE landing_page_views
          ALTER COLUMN viewed_date SET DEFAULT CURRENT_DATE;

        DROP INDEX IF EXISTS idx_lp_views_unique;

        CREATE UNIQUE INDEX IF NOT EXISTS idx_lp_views_unique
          ON landing_page_views (prospect_id, page_path, viewed_date);

        CREATE TABLE IF NOT EXISTS outreach_conversions (
          id SERIAL PRIMARY KEY,
          prospect_id VARCHAR(100),
          outreach_send_id UUID REFERENCES outreach_sends(id),
          form_submission_id INT REFERENCES form_submissions(id),
          pipedrive_lead_id VARCHAR(255),
          conversion_type VARCHAR(50),
          converted_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_outreach_sends_am ON outreach_sends(am_email);
        CREATE INDEX IF NOT EXISTS idx_outreach_sends_status ON outreach_sends(status);
        CREATE INDEX IF NOT EXISTS idx_outreach_sends_prospect ON outreach_sends(prospect_email);
        CREATE INDEX IF NOT EXISTS idx_outreach_sends_pid ON outreach_sends(prospect_id);
        CREATE INDEX IF NOT EXISTS idx_lp_views_prospect ON landing_page_views(prospect_id);
        CREATE INDEX IF NOT EXISTS idx_lp_views_campaign ON landing_page_views(campaign);
        CREATE INDEX IF NOT EXISTS idx_conversions_prospect ON outreach_conversions(prospect_id);
      `);
      console.log('[db] Outreach tracking tables ready');
    } catch (err) {
      console.error('[db] Outreach tracking migration failed; continuing without tracking tables:', err.message);
    }

    await client.query(`
      CREATE TABLE IF NOT EXISTS newsletter_subscribers (
        id                         SERIAL PRIMARY KEY,
        email                      VARCHAR(255) NOT NULL,
        consent_timestamp_utc      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        confirmed_timestamp_utc    TIMESTAMPTZ,
        ip_address                 VARCHAR(45),
        user_agent                 TEXT,
        source_url                 VARCHAR(500),
        consent_text_hash          VARCHAR(64),
        checkbox_state             BOOLEAN      NOT NULL DEFAULT TRUE,
        unsubscribed_timestamp_utc TIMESTAMPTZ,
        unsubscribe_method         VARCHAR(50),
        status                     VARCHAR(20)  NOT NULL DEFAULT 'pending'
      );
      CREATE TABLE IF NOT EXISTS email_suppression (
        id       SERIAL PRIMARY KEY,
        email    VARCHAR(255) NOT NULL UNIQUE,
        added_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        reason   VARCHAR(100) DEFAULT 'unsubscribe'
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_newsletter_email
        ON newsletter_subscribers(email);
      CREATE INDEX IF NOT EXISTS idx_newsletter_status
        ON newsletter_subscribers(status);
    `);

    console.log('[db] Schema ready');
  } finally {
    client.release();
  }
}

async function saveSubmission(formType, fields, sampleItems = []) {
  if (formType === 'Sample Request' && sampleItems.length > 3) {
    throw new Error('A maximum of 3 samples may be requested at one time.');
  }

  const clientSubmissionId = normalizeClientSubmissionId(fields);
  const client = await pool.connect();
  try {
    if (clientSubmissionId) {
      const existing = await client.query(
        'SELECT id, submitted_at FROM form_submissions WHERE client_submission_id = $1 LIMIT 1',
        [clientSubmissionId]
      );
      if (existing.rows.length) return { ...existing.rows[0], duplicate: true };
    }

    await client.query('BEGIN');

    const name = fields.name
      || `${fields.first_name || ''} ${fields.last_name || ''}`.trim()
      || null;
    const { rows } = await client.query(
      `INSERT INTO form_submissions
         (form_type, name, email, phone, company, stone_interest, message,
          postcode, state, store_location, source, consent, role, reason,
          street, suburb, unit, raw_data, client_submission_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
       RETURNING id, submitted_at`,
      [
        formType,
        name,
        fields.email          || null,
        fields.phone          || null,
        fields.company        || null,
        fields.stone_interest || null,
        fields.message        || fields.special_instructions || null,
        fields.postcode       || null,
        fields.state          || null,
        fields.store_location || null,
        fields.source         || null,
        fields.consent ? true : false,
        fields.i_am_a || fields.role || fields.type || null,
        fields.reason || fields.enquiry_reason || null,
        fields.street         || null,
        fields.suburb         || null,
        fields.unit           || null,
        // ALWAYS store the full payload as a safety net, so any new form
        // field surfaces immediately even before a dedicated column exists.
        JSON.stringify(fields),
        clientSubmissionId
      ]
    );

    const { id, submitted_at } = rows[0];

    if (formType === 'Sample Request' && sampleItems.length > 0) {
      for (const item of sampleItems) {
        await client.query(
          `INSERT INTO sample_request_items
            (submission_id, stone_slug, stone_name, collection)
           VALUES ($1,$2,$3,$4)`,
          [id, item.slug, item.name, item.collection || null]
        );
      }
    }

    await client.query('COMMIT');
    return { id, submitted_at, duplicate: false };
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch {}
    if (err.code === '23505' && clientSubmissionId) {
      const existing = await client.query(
        'SELECT id, submitted_at FROM form_submissions WHERE client_submission_id = $1 LIMIT 1',
        [clientSubmissionId]
      );
      if (existing.rows.length) return { ...existing.rows[0], duplicate: true };
    }
    throw err;
  }
}

async function saveSubscriber(email, meta = {}) {
  const client = await pool.connect();
  try {
    const suppressed = await client.query(
      'SELECT id FROM email_suppression WHERE LOWER(email) = LOWER($1)', [email]
    );
    if (suppressed.rows.length > 0) throw new Error('SUPPRESSED');
    const consentHash = crypto.createHash('sha256').update(CONSENT_TEXT).digest('hex');
    const { rows } = await client.query(
      `INSERT INTO newsletter_subscribers
        (email, ip_address, user_agent, source_url, consent_text_hash, checkbox_state, status)
       VALUES ($1,$2,$3,$4,$5,$6,'active')
       ON CONFLICT (email) DO UPDATE
         SET consent_timestamp_utc = NOW(),
             ip_address = EXCLUDED.ip_address,
             source_url = EXCLUDED.source_url,
             status = 'active',
             unsubscribed_timestamp_utc = NULL
       RETURNING id, consent_timestamp_utc`,
      [email.toLowerCase().trim(), meta.ip || null, meta.userAgent || null,
       meta.sourceUrl || null, consentHash, true]
    );
    return rows[0];
  } finally {
    client.release();
  }
}

async function unsubscribeEmail(email, method = 'email-link') {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `UPDATE newsletter_subscribers
       SET status = 'unsubscribed', unsubscribed_timestamp_utc = NOW(), unsubscribe_method = $2
       WHERE LOWER(email) = LOWER($1)`, [email, method]
    );
    await client.query(
      `INSERT INTO email_suppression (email, reason)
       VALUES (LOWER($1), $2) ON CONFLICT (email) DO NOTHING`, [email, method]
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { pool, initDB, saveSubmission, saveSubscriber, unsubscribeEmail };
