#!/usr/bin/env node
/* eslint-disable no-console */
// Measures the fabricator → Pipedrive organisation match rate against real
// data. Read-only: it queries, it never writes to Pipedrive or Postgres.
//
// Runs the exact matcher the live sync uses (imported from pipedrive.js, not
// reimplemented) over every distinct fabricator in warranty_activations, and
// prints matched / ambiguous / unmatched with the hit rate.
//
// Usage:
//   DATABASE_URL=… PIPEDRIVE_API_TOKEN=… node scripts/pipedrive-fabricator-report.js
//
// On Railway:
//   railway ssh -- node scripts/pipedrive-fabricator-report.js
//
// Unmatched names are the useful output: they're either fabricators genuinely
// not in the CRM, or spelling variants worth adding as an org alias.

const { Pool } = require('pg');
const { matchFabricatorOrganisation, normaliseOrgName } = require('../pipedrive');

const LIMIT = Number(process.env.REPORT_LIMIT || 0); // 0 = all

async function main() {
  if (!process.env.PIPEDRIVE_API_TOKEN) {
    console.error('PIPEDRIVE_API_TOKEN is not set — the matcher needs it to search organisations.');
    process.exit(1);
  }
  if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL is not set.');
    process.exit(1);
  }

  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL) ? false : { rejectUnauthorized: false },
  });

  const { rows } = await pool.query(
    `SELECT fabricator, COUNT(*)::int AS activations
       FROM warranty_activations
      WHERE fabricator IS NOT NULL AND btrim(fabricator) <> ''
      GROUP BY fabricator
      ORDER BY activations DESC, fabricator ASC
      ${LIMIT ? `LIMIT ${LIMIT}` : ''}`
  );

  if (!rows.length) {
    console.log('No fabricators recorded in warranty_activations yet — nothing to measure.');
    await pool.end();
    return;
  }

  console.log(`Fabricator → organisation match report`);
  console.log(`${rows.length} distinct fabricator name(s), ` +
    `${rows.reduce((n, r) => n + r.activations, 0)} activation(s)\n`);
  console.log('─'.repeat(78));

  const buckets = { matched: [], ambiguous: [], unmatched: [], error: [] };
  for (const row of rows) {
    let res;
    try {
      res = await matchFabricatorOrganisation(row.fabricator);
    } catch (err) {
      console.error(`  ! ${row.fabricator}: lookup failed — ${err.message}`);
      continue;
    }
    buckets[res.status].push({ ...row, res });
    const tag = { matched: '✓ matched  ', ambiguous: '? ambiguous',
                  unmatched: '· unmatched', error: '! error    ' }[res.status];
    const detail = res.status === 'matched'
      ? `→ ${res.org.name} (#${res.org.id})`
      : res.status === 'ambiguous'
        ? `→ ${(res.candidates || []).map(c => c.name).join(' | ')}`
        : `(normalised: "${res.target}")`;
    console.log(`  ${tag} ${String(row.fabricator).padEnd(34)} ×${String(row.activations).padEnd(4)} ${detail}`);
    // Be polite to the search endpoint.
    await new Promise(r => setTimeout(r, 250));
  }

  const total = rows.length;
  const weighted = rows.reduce((n, r) => n + r.activations, 0);
  const wMatched = buckets.matched.reduce((n, r) => n + r.activations, 0);
  const pct = (a, b) => b ? ((a / b) * 100).toFixed(1) + '%' : 'n/a';

  console.log('─'.repeat(78));
  console.log(`\nBy distinct name:  ${buckets.matched.length}/${total} matched (${pct(buckets.matched.length, total)})`);
  console.log(`                   ${buckets.ambiguous.length} ambiguous, ${buckets.unmatched.length} unmatched` +
    (buckets.error.length ? `, ${buckets.error.length} LOOKUP FAILED` : ''));
  console.log(`By activation:     ${wMatched}/${weighted} matched (${pct(wMatched, weighted)})`);
  if (buckets.error.length) {
    console.log(`\n⚠ ${buckets.error.length} lookup(s) failed — the rate above understates the truth.`);
    console.log('  Re-run when Pipedrive is reachable before treating it as a real hit rate.');
  }

  if (buckets.unmatched.length) {
    console.log(`\nUnmatched — add these as organisations in Pipedrive if they're real trade accounts:`);
    for (const u of buckets.unmatched) {
      console.log(`  ${u.fabricator}  (normalised "${normaliseOrgName(u.fabricator)}", ${u.activations} activation(s))`);
    }
  }
  if (buckets.ambiguous.length) {
    console.log(`\nAmbiguous — duplicate organisations in Pipedrive, worth merging:`);
    for (const a of buckets.ambiguous) {
      console.log(`  ${a.fabricator} → ${(a.res.candidates || []).map(c => `${c.name} (#${c.id})`).join(', ')}`);
    }
  }

  await pool.end();
}

main().catch(err => {
  console.error('\nFailed:', err.message);
  process.exit(1);
});
