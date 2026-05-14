#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const TOKEN = process.env.PIPEDRIVE_API_TOKEN;
if (!TOKEN) { console.error('PIPEDRIVE_API_TOKEN not set'); process.exit(1); }

const API = 'https://api.pipedrive.com/v1';
const CONTACTS_PATH = path.join(process.env.HOME, 'Downloads/business-cards-contacts.json');
const RATE_DELAY_MS = 150;
const BELINDA_EMAIL = 'belinda@alphasurfaces.com.au';

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function pd(method, endpoint, body) {
  const url = `${API}${endpoint}${endpoint.includes('?') ? '&' : '?'}api_token=${TOKEN}`;
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  const json = await res.json().catch(() => ({}));
  if (!res.ok || json.success === false) {
    throw new Error(`${method} ${endpoint} → ${res.status} ${JSON.stringify(json).slice(0, 300)}`);
  }
  await sleep(RATE_DELAY_MS);
  return json;
}

async function findUserId(email) {
  const r = await pd('GET', '/users');
  const u = r.data.find(x => x.email && x.email.toLowerCase() === email.toLowerCase());
  if (!u) throw new Error(`User ${email} not found`);
  return u.id;
}

async function findOrg(name) {
  const r = await pd('GET', `/organizations/search?term=${encodeURIComponent(name)}&fields=name&exact_match=true`);
  const items = r.data && r.data.items;
  if (items && items.length) return items[0].item.id;
  // try fuzzy
  const r2 = await pd('GET', `/organizations/search?term=${encodeURIComponent(name)}&fields=name`);
  const items2 = r2.data && r2.data.items;
  if (items2 && items2.length) {
    const match = items2.find(i => i.item.name && i.item.name.toLowerCase() === name.toLowerCase());
    if (match) return match.item.id;
  }
  return null;
}

async function findPerson(name, email) {
  if (email) {
    const r = await pd('GET', `/persons/search?term=${encodeURIComponent(email)}&fields=email&exact_match=true`);
    const items = r.data && r.data.items;
    if (items && items.length) return items[0].item.id;
  }
  const r2 = await pd('GET', `/persons/search?term=${encodeURIComponent(name)}&fields=name&exact_match=true`);
  const items2 = r2.data && r2.data.items;
  if (items2 && items2.length) return items2[0].item.id;
  return null;
}

async function createOrg({ name, address, ownerId, type }) {
  const body = { name, owner_id: ownerId };
  if (address) body.address = address;
  const r = await pd('POST', '/organizations', body);
  const orgId = r.data.id;
  if (type) {
    await pd('POST', '/notes', { content: `Type: ${type}`, org_id: orgId });
  }
  return orgId;
}

async function createPerson({ name, orgId, ownerId, email, phone, jobTitle, note }) {
  const body = { name, owner_id: ownerId };
  if (orgId) body.org_id = orgId;
  if (email) body.email = [email];
  if (phone) body.phone = [phone];
  if (jobTitle) body.job_title = jobTitle;
  const r = await pd('POST', '/persons', body);
  const personId = r.data.id;
  if (note) {
    await pd('POST', '/notes', { content: note, person_id: personId });
  }
  return personId;
}

(async () => {
  const contacts = JSON.parse(fs.readFileSync(CONTACTS_PATH, 'utf8'));
  console.log(`Loaded ${contacts.length} contacts from ${CONTACTS_PATH}`);

  const ownerId = await findUserId(BELINDA_EMAIL);
  console.log(`Belinda owner_id: ${ownerId}`);

  const orgCache = new Map(); // company name → org_id
  const stats = { orgsCreated: 0, orgsExisting: 0, personsCreated: 0, personsSkipped: 0, errors: [] };

  for (let i = 0; i < contacts.length; i++) {
    const c = contacts[i];
    const tag = `[${i + 1}/${contacts.length}] ${c.name} @ ${c.company}`;
    try {
      let orgId = null;
      if (c.company) {
        if (orgCache.has(c.company)) {
          orgId = orgCache.get(c.company);
        } else {
          const existing = await findOrg(c.company);
          if (existing) {
            orgId = existing;
            stats.orgsExisting++;
            console.log(`  ${tag} → org exists (${orgId})`);
          } else {
            orgId = await createOrg({ name: c.company, address: c.address, ownerId, type: c.type });
            stats.orgsCreated++;
            console.log(`  ${tag} → org created (${orgId})`);
          }
          orgCache.set(c.company, orgId);
        }
      }

      const existingPerson = await findPerson(c.name, c.email);
      if (existingPerson) {
        stats.personsSkipped++;
        console.log(`  ${tag} → person exists (${existingPerson}), skipped`);
        continue;
      }

      const personId = await createPerson({
        name: c.name,
        orgId,
        ownerId,
        email: c.email,
        phone: c.phone,
        jobTitle: c.title,
        note: c.note,
      });
      stats.personsCreated++;
      console.log(`  ${tag} → person created (${personId})`);
    } catch (e) {
      stats.errors.push({ contact: `${c.name} @ ${c.company}`, error: e.message });
      console.error(`  ${tag} → ERROR: ${e.message}`);
    }
  }

  console.log('\n=== SUMMARY ===');
  console.log(`Organizations created: ${stats.orgsCreated}`);
  console.log(`Organizations already existed: ${stats.orgsExisting}`);
  console.log(`Persons created: ${stats.personsCreated}`);
  console.log(`Persons skipped (duplicates): ${stats.personsSkipped}`);
  console.log(`Errors: ${stats.errors.length}`);
  if (stats.errors.length) {
    console.log('\nErrors:');
    stats.errors.forEach(e => console.log(`  - ${e.contact}: ${e.error}`));
  }
})().catch(e => { console.error('FATAL:', e); process.exit(1); });
