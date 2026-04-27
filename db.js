const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
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
    console.log('[db] Schema ready');
  } finally {
    client.release();
  }
}

async function saveSubmission(formType, fields, sampleItems = []) {
  if (formType === 'Sample Request' && sampleItems.length > 3) {
    throw new Error('A maximum of 3 samples may be requested at one time.');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows } = await client.query(
      `INSERT INTO form_submissions
    (form_type, name, email, phone, company, message, postcode,
     state, store_location, source, consent)
   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
   RETURNING id, submitted_at`,
  [
    formType,
    fields.name || `${fields.first_name || ''} ${fields.last_name || ''}`.trim() || null,
    fields.email   || null,
    fields.phone   || null,
    fields.company || null,
    fields.message || null,
    fields.postcode|| null,
    fields.state   || null,
    fields.store_location || null,
    fields.source  || null,
    fields.consent ? true : false
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
    return { id, submitted_at };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  }
}

module.exports = { pool, initDB, saveSubmission };
