#!/usr/bin/env node
/* eslint-disable no-console */
// Brings the CMS's Alpha Zero (discontinued) list in line with
// config/discontinued-stock.json (Pam's stock on hand).
//
// The live list comes from the CMS tables (cms_stones), not from
// public/data/stones.json, so a code deploy alone does not remove a colour
// that is already in the database. This script:
//   - lists every in-stock colour in Alpha Zero (adds missing ones from
//     public/data/stones.json, makes hidden ones visible, sets the order);
//   - hides zero-stock colours, but ONLY rows in the alpha-zero collection.
//     A current-range colour with the same name (Taj Mahal, Viola Ligera,
//     Whitehaven) is never touched;
//   - reports, without changing, any other visible Alpha Zero colour that is
//     not on the stock list.
//
// Dry run by default (prints what it would do). Add --apply to write, in one
// transaction. Reads DATABASE_URL (the website database).
//
//   DATABASE_URL=... node scripts/sync-discontinued-stock.js
//   DATABASE_URL=... node scripts/sync-discontinued-stock.js --apply

const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

const APPLY = process.argv.includes('--apply');
const COLLECTION = 'alpha-zero';
const STOCK = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'config', 'discontinued-stock.json'), 'utf8'));
const STATIC = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'public', 'data', 'stones.json'), 'utf8'));

function slabs(n) {
  return n === 1 ? '1 slab' : n + ' slabs';
}

function staticStone(slug) {
  const col = (STATIC.collections || []).find(c => c.id === COLLECTION);
  return col ? (col.stones || []).find(s => s.slug === slug) : null;
}

async function main() {
  const url = process.env.DATABASE_URL;
  if (!url) {
    console.error('Set DATABASE_URL to the website database.');
    process.exit(1);
  }
  const local = /localhost|127\.0\.0\.1|::1/.test(url);
  const pool = new Pool({ connectionString: url, ssl: local ? false : { rejectUnauthorized: false } });
  const client = await pool.connect();
  const actions = [];
  try {
    await client.query('BEGIN');
    const col = await client.query('SELECT 1 FROM cms_collections WHERE collection_id = $1', [COLLECTION]);
    if (!col.rows.length) throw new Error('No alpha-zero collection in cms_collections');

    const { rows } = await client.query('SELECT slug, name, collection_id, visible, discontinued, sort_order FROM cms_stones');
    const bySlug = new Map(rows.map(r => [r.slug, r]));
    const wanted = new Set();

    for (let i = 0; i < STOCK.in_stock.length; i++) {
      const item = STOCK.in_stock[i];
      wanted.add(item.slug);
      const row = bySlug.get(item.slug);
      if (row && row.collection_id && row.collection_id !== COLLECTION) {
        actions.push(`LEAVE  ${item.name}: its row is in ${row.collection_id}, not Alpha Zero (check by hand)`);
        continue;
      }
      if (row) {
        if (row.visible && row.discontinued && row.collection_id === COLLECTION && row.sort_order === i) continue;
        actions.push(row.visible && row.discontinued && row.collection_id === COLLECTION
          ? `ORDER  ${item.name}: moved to position ${i + 1}`
          : `SHOW   ${item.name} (${slabs(item.slabs)})` + (row.visible ? '' : ' - was hidden'));
        await client.query(
          `UPDATE cms_stones SET collection_id = $2, discontinued = TRUE, visible = TRUE, sort_order = $3, updated_at = NOW()
           WHERE slug = $1`,
          [item.slug, COLLECTION, i]
        );
        continue;
      }
      const s = staticStone(item.slug);
      if (!s) {
        actions.push(`MISSING ${item.name}: not in public/data/stones.json, cannot add`);
        continue;
      }
      actions.push(`ADD    ${item.name} (${slabs(item.slabs)})`);
      await client.query(
        `INSERT INTO cms_stones
          (slug, name, collection_id, finish, image_url, thumbnail_url, swatch_url, slab_url,
           gallery, specs, uv_stable, indoor_outdoor, discontinued, images_pending, visible, sort_order)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'[]'::jsonb,$9::jsonb,FALSE,FALSE,TRUE,$10,TRUE,$11)`,
        [
          s.slug, s.name, COLLECTION, s.finish || '', s.image || '', s.thumbnail || '', s.swatch || '', s.slab || '',
          JSON.stringify({ slab_width: 3200, slab_height: 1600, thickness: 20, weight: 236, warranty: '15-Year Limited Warranty' }),
          !!s.images_pending, i
        ]
      );
    }

    for (const item of STOCK.zero_stock) {
      const row = bySlug.get(item.slug);
      if (!row) continue;
      if (row.collection_id !== COLLECTION) {
        actions.push(`KEEP   ${row.name}: current range (${row.collection_id}), only the discontinued stock is at zero`);
        continue;
      }
      if (!row.visible) continue;
      actions.push(`HIDE   ${row.name} (zero stock)`);
      await client.query('UPDATE cms_stones SET visible = FALSE, updated_at = NOW() WHERE slug = $1', [item.slug]);
    }

    const zero = new Set(STOCK.zero_stock.map(z => z.slug));
    for (const r of rows) {
      if (r.collection_id === COLLECTION && r.visible && !wanted.has(r.slug) && !zero.has(r.slug)) {
        actions.push(`REVIEW ${r.name}: shown in Alpha Zero but not on the ${STOCK.as_at} stock list (left as is)`);
      }
    }

    await client.query(APPLY ? 'COMMIT' : 'ROLLBACK');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
    await pool.end();
  }

  console.log(`Alpha Zero stock list as at ${STOCK.as_at}:`);
  console.log(actions.length ? actions.map(a => '  ' + a).join('\n') : '  nothing to change');
  console.log(APPLY ? '\nApplied.' : '\nDry run: nothing written. Add --apply to write.');
}

main().catch(err => {
  console.error(err.message);
  process.exit(1);
});
