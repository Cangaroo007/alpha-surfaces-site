#!/usr/bin/env node
/* eslint-disable no-console */
// One-off setup: create the Pipedrive person custom fields the warranty
// activation sync writes to, and print the env assignments for Railway.
//
// Idempotent. Fields are matched by name (case- and whitespace-insensitive),
// so re-running never creates a duplicate — it just re-prints the keys of
// what's already there. Safe to run against a workspace that's been set up
// by hand: name an existing field the same and it will be adopted.
//
// Field keys are 40-char hashes that differ per Pipedrive workspace, which is
// why they live in env rather than in pipedrive.js next to the older
// hard-coded ones.
//
// Usage:
//   PIPEDRIVE_API_TOKEN=… node scripts/pipedrive-warranty-fields.js --dry-run
//   PIPEDRIVE_API_TOKEN=… node scripts/pipedrive-warranty-fields.js
//
// --dry-run reports what exists and what would be created, and writes nothing.

const { WARRANTY_PERSON_FIELDS } = require('../pipedrive');

const PD_BASE = process.env.PIPEDRIVE_API_BASE || 'https://api.pipedrive.com/v1';
const TOKEN = process.env.PIPEDRIVE_API_TOKEN;
const DRY_RUN = process.argv.includes('--dry-run');

function normaliseFieldName(name) {
  return String(name || '').toLowerCase().replace(/\s+/g, ' ').trim();
}

async function pdRequest(method, endpoint, body) {
  const url = `${PD_BASE}/${endpoint}${endpoint.includes('?') ? '&' : '?'}api_token=${TOKEN}`;
  const res = await fetch(url, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => null);
  if (!res.ok || json?.success === false) {
    throw new Error(`${method} ${endpoint} → HTTP ${res.status} ${json?.error || ''}`.trim());
  }
  return json;
}

// personFields is paginated; walk it so a workspace with many custom fields
// doesn't silently look like it has none and get duplicates created.
async function fetchAllPersonFields() {
  const all = [];
  let start = 0;
  for (;;) {
    const page = await pdRequest('GET', `personFields?start=${start}&limit=100`);
    all.push(...(page?.data || []));
    const more = page?.additional_data?.pagination;
    if (!more?.more_items_in_collection) break;
    start = more.next_start;
  }
  return all;
}

async function main() {
  if (!TOKEN) {
    console.error('PIPEDRIVE_API_TOKEN is not set. Export it and re-run:');
    console.error('  PIPEDRIVE_API_TOKEN=… node scripts/pipedrive-warranty-fields.js --dry-run');
    process.exit(1);
  }

  console.log(`Pipedrive warranty person fields${DRY_RUN ? ' (DRY RUN — nothing will be written)' : ''}`);
  console.log('─'.repeat(72));

  const existing = await fetchAllPersonFields();
  const byName = new Map();
  for (const f of existing) byName.set(normaliseFieldName(f.name), f);
  console.log(`Workspace has ${existing.length} person fields.\n`);

  const results = [];
  for (const def of WARRANTY_PERSON_FIELDS) {
    const found = byName.get(normaliseFieldName(def.name));
    if (found) {
      const typeOk = found.field_type === def.type;
      results.push({ def, key: found.key, action: 'exists', typeOk, actualType: found.field_type });
      console.log(`  ✓ exists   ${def.name.padEnd(24)} ${found.key}` +
        (typeOk ? '' : `   ⚠ type is "${found.field_type}", expected "${def.type}"`));
      continue;
    }
    if (DRY_RUN) {
      results.push({ def, key: null, action: 'would-create', typeOk: true });
      console.log(`  + would create ${def.name.padEnd(20)} (${def.type})`);
      continue;
    }
    const created = await pdRequest('POST', 'personFields', { name: def.name, field_type: def.type });
    const key = created?.data?.key;
    results.push({ def, key, action: 'created', typeOk: true });
    console.log(`  + created  ${def.name.padEnd(24)} ${key}`);
  }

  const mistyped = results.filter(r => !r.typeOk);
  const missing = results.filter(r => !r.key);

  console.log('\n' + '─'.repeat(72));
  if (missing.length && DRY_RUN) {
    console.log(`\n${missing.length} field(s) would be created. Re-run without --dry-run, then`);
    console.log('paste the printed block into Railway.\n');
  } else {
    console.log('\nSet these in Railway (Variables tab) for every environment that syncs:\n');
    for (const r of results) {
      if (r.key) console.log(`${r.def.env}=${r.key}`);
    }
    console.log('\nOr from the CLI:\n');
    console.log('  railway variables --set ' +
      results.filter(r => r.key).map(r => `"${r.def.env}=${r.key}"`).join(' \\\n    '));
    console.log('');
  }

  if (mistyped.length) {
    console.log('⚠ Type mismatches — these fields exist but not as the expected type:');
    for (const r of mistyped) {
      console.log(`    ${r.def.name}: is "${r.actualType}", expected "${r.def.type}"`);
    }
    console.log('  Pipedrive cannot change a field\'s type after creation. Either rename the');
    console.log('  existing field and re-run, or accept the type — the sync writes strings');
    console.log('  and Pipedrive will coerce where it can.\n');
  }

  console.log('Nothing here creates deals, pipelines or organisations.');
}

main().catch(err => {
  console.error('\nFailed:', err.message);
  process.exit(1);
});
