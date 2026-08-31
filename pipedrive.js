// Pipedrive integration. Website forms create LEADS (not Deals) tagged HOT
// in the Leads Inbox; sales qualifies and converts manually. Walk-ins log
// as 'meeting' activities; warranty activations attach as a note on the
// person. Best-effort throughout — every call is wrapped so a Pipedrive
// outage can't fail a public form submit.

// Overridable so the integration can be pointed at a sandbox workspace or a
// local stub in tests. Unset in production — defaults to the real API.
// warnIfPipedriveMisrouted() below makes an override impossible to miss at boot.
const DEFAULT_PD_BASE = 'https://api.pipedrive.com/v1';
const PD_BASE = process.env.PIPEDRIVE_API_BASE || DEFAULT_PD_BASE;

// Boot-time guard. An override means every lead, person and note this process
// writes goes somewhere other than the real CRM — silent data loss that looks
// exactly like a working integration. Never blocks startup; just refuses to be
// missed in the logs.
//
// NOTE ON THE SIGNAL: Railway sets NODE_ENV=production on BOTH staging and
// production (see the comment at server.js:1013), so NODE_ENV alone cannot
// tell them apart — keyed on it, this would scream "PRODUCTION" on a perfectly
// deliberate staging sandbox override and quickly become noise people ignore.
// RAILWAY_ENVIRONMENT_NAME decides how loud to be; NODE_ENV still contributes,
// so a non-Railway deployment with NODE_ENV=production is still treated as
// deployed rather than local. Returns the severity, for tests.
function warnIfPipedriveMisrouted() {
  const override = process.env.PIPEDRIVE_API_BASE;
  if (!override) return 'default';
  const norm = v => String(v || '').trim().replace(/\/+$/, '');
  if (norm(override) === norm(DEFAULT_PD_BASE)) return 'default';

  const envName = (process.env.RAILWAY_ENVIRONMENT_NAME || '').toLowerCase();
  const bar = '='.repeat(72);

  if (envName === 'production') {
    console.error(bar);
    console.error('!!  PIPEDRIVE MISROUTE — PRODUCTION IS NOT TALKING TO PIPEDRIVE  !!');
    console.error(`!!  PIPEDRIVE_API_BASE = ${override}`);
    console.error(`!!  expected            = ${DEFAULT_PD_BASE}`);
    console.error('!!  Every lead, person and note is going to that host instead.');
    console.error('!!  Unset PIPEDRIVE_API_BASE in Railway and redeploy.');
    console.error(bar);
    return 'production-misroute';
  }

  if (envName || process.env.NODE_ENV === 'production') {
    console.warn(bar);
    console.warn(`[pipedrive] API base overridden on "${envName || 'deployed'}" environment`);
    console.warn(`[pipedrive]   PIPEDRIVE_API_BASE = ${override}`);
    console.warn(`[pipedrive]   default            = ${DEFAULT_PD_BASE}`);
    console.warn('[pipedrive] Intentional for a sandbox; a mistake anywhere else.');
    console.warn(bar);
    return 'deployed-override';
  }

  console.warn(`[pipedrive] API base overridden for local dev: ${override}`);
  return 'local-override';
}

// Pipedrive person custom-field keys (provided by the workspace). Both are
// multi-select ('set') fields, so values are merged with whatever the person
// already carries rather than overwritten — see mergeSetField().
const FIELD_BUSINESS_CATEGORY = 'da25035c39ec621856e3252165feaf9141423b88';
const FIELD_PRODUCT_CATEGORY  = '6c3a7edb24cde1d21864dcb96693e76fc7bcd116';
// Single-select. Added so submissions can be broken down by state — Pipedrive
// has no native address field on a person, so the state given on the form was
// previously dropped on the floor.
const FIELD_STATE = 'b53442866baff353ea710225b82f3519ece695cd';
const STATE_OPTION = {
  QLD: 233, NSW: 234, VIC: 235, SA: 236,
  WA: 237, TAS: 238, NT: 239, ACT: 240,
};
function stateOptionId(state) {
  return STATE_OPTION[String(state || '').trim().toUpperCase()] || null;
}

// Product Category option ids, as configured in the workspace.
const PRODUCT_CATEGORY = { engineered_stone: 187, porcelain_tiles: 188 };

// ---------------------------------------------------------------------------
// Lead custom fields. Created on DEAL (leads have no field editor of their own
// and inherit deal fields). Verified 25 Aug 2026: the v1 API writes these on
// lead creation and they render in the UI — but NO API can read them back.
// v2 has no /leads endpoint at all. Reporting on these lives in Pipedrive
// Insights, in-app. Do not build a RoadRunner report that expects to read them.
// ---------------------------------------------------------------------------
const DEAL_FIELD_LEAD_TYPE          = '09908c69b05242596fb067beb464faea1d592e2a';
const DEAL_FIELD_ENQUIRY_REASON     = 'dc25b1d68eb4a267b14e9203ee367de6523cb9b1';
const DEAL_FIELD_STONEMASON_COMPANY = 'd01847a937b603ad3cb0bd176c3b7eff9e69b305';
const DEAL_FIELD_STONES_OF_INTEREST = '462063d3a735bd8fbd4b544441f8705843608c0d';
const DEAL_FIELD_SAMPLES_SENT       = '616cf43baf8535455eda9cf21e184d9130843787';
const DEAL_FIELD_LEAD_STAGE         = '4335c1fe2d07a89272099dda48907c9baa497b4c';
const DEAL_FIELD_CAMPAIGN_UTM       = 'f65dc11532e2b5f67f5bac83a7003999a121fbb3';

const LEAD_STAGE_NEW = 308;

// Free-text role → Lead type option id. Keys are lowercased on lookup.
// Legacy website values (Fabricator, Builder, Architect/Designer,
// Retailer/Stockist) are mapped so leads created before the form was fixed
// still land correctly. 'architect/designer' is genuinely ambiguous and is
// deliberately absent — better blank than wrong.
const LEAD_TYPE_OPTION = {
  'homeowner': 292,
  'stonemason': 293, 'fabricator': 293,
  'cabinet maker': 294, 'cabinetmaker': 294, 'joiner': 294,
  'cabinet maker / kitchen company': 294,
  'project home builder': 295,
  'builder/developer': 296, 'builder / developer': 296,
  'builder': 296, 'developer': 296,
  'architect': 297,
  'interior designer': 298, 'designer': 298,
  'tile outlet': 299, 'tile outlet / retailer': 299,
  'retailer/stockist': 299, 'retailer / stockist': 299,
  'other': 300,
};
function leadTypeIdFor(role) {
  return LEAD_TYPE_OPTION[String(role || '').trim().toLowerCase()] || null;
}

const ENQUIRY_REASON_OPTION = {
  'sample request': 301, 'sample': 301, 'order a sample': 301,
  'warranty': 302,
  'general enquiry': 303, 'general': 303, 'product information': 303,
  'technical question': 303,
  'partner enquiry': 304, 'partner': 304, 'trade enquiry': 304,
  'partnership': 304,
  'where to buy': 305, 'stockist': 305, 'stockist enquiry': 305,
  'find a stockist': 305,
  'pricing': 306, 'price': 306, 'quote': 306, 'request a quote': 306,
  'other': 307,
};
function enquiryReasonIdFor(reason) {
  return ENQUIRY_REASON_OPTION[String(reason || '').trim().toLowerCase()] || null;
}

// Builds the custom-field payload for a lead. Only non-empty values are
// included, so an unmapped role leaves the field blank rather than guessing.
function buildLeadFields({ role, reason, stones, campaign, stonemasonOrgId } = {}) {
  const out = { [DEAL_FIELD_LEAD_STAGE]: LEAD_STAGE_NEW };
  const t = leadTypeIdFor(role);
  if (t) out[DEAL_FIELD_LEAD_TYPE] = t;
  const r = enquiryReasonIdFor(reason);
  if (r) out[DEAL_FIELD_ENQUIRY_REASON] = r;
  if (stones) out[DEAL_FIELD_STONES_OF_INTEREST] = String(stones).slice(0, 255);
  if (campaign) out[DEAL_FIELD_CAMPAIGN_UTM] = String(campaign).slice(0, 255);
  if (stonemasonOrgId) out[DEAL_FIELD_STONEMASON_COMPANY] = stonemasonOrgId;
  return out;
}

// utm_source / utm_medium / utm_campaign, collapsed to one readable string.
// Human-readable stonemason line for the lead note. An unmatched name is
// kept here on purpose — Stonemason (company) is an org field and cannot
// hold text, and Jess links the right record when she processes the lead.
function stonemasonNote(f) {
  const status = String(f.stonemason_status || '').trim();
  if (!status) return '';
  const typed = String(f.stonemason_name || '').trim();
  if (status === 'yes') {
    if (f.stonemason_org_id) return `Stonemason: ${escape(typed)} (linked)<br>`;
    if (typed) return `Stonemason: ${escape(typed)} — NOT MATCHED, please identify and link<br>`;
    return 'Stonemason: says they have one, none named<br>';
  }
  if (status === 'no')      return 'Stonemason: NONE — asked to be connected with one<br>';
  if (status === 'unsure')  return 'Stonemason: not sure yet — ask again at follow-up<br>';
  if (status === 'decline') return 'Stonemason: preferred not to say — do not chase<br>';
  return '';
}

function buildCampaignString(f) {
  const parts = [f.utm_source, f.utm_medium, f.utm_campaign]
    .map(v => String(v || '').trim()).filter(Boolean);
  if (!parts.length) return '';
  const content = String(f.utm_content || '').trim();
  return parts.join(' / ') + (content ? ` (${content})` : '');
}

// Free-text role/interest → Product Category option id.
function productCategoryIdsFor(text) {
  const t = String(text || '').toLowerCase();
  const ids = [];
  if (/engineered|alpha|stone|benchtop/.test(t)) ids.push(PRODUCT_CATEGORY.engineered_stone);
  if (/tile|porcelain/.test(t))                  ids.push(PRODUCT_CATEGORY.porcelain_tiles);
  return ids;
}

// Business Category option ids (workspace): 189 Stonemason, 190 Architect,
// 191 Cabinet Maker, 192 Designer, 193 Pool Builder, 194 Builder/Developer,
// 195 Tile Outlet.
//
// ORDER MATTERS — first match wins, so more specific patterns come first.
// 'cabinet' precedes 'builder' so "Cabinetmaker / Builder" lands on Cabinet
// Maker. 'architect' precedes 'designer', which keeps "Designer / Architect"
// resolving to Architect exactly as it always has; flip those two lines if
// Belinda would rather that combined option read as Designer.
const ROLE_TO_BUSINESS_CATEGORY = [
  ['homeowner',  null],
  ['stonemason', 189],
  ['fabricator', 189],
  ['cabinet',    191],
  ['kitchen',    191],
  ['tiler',      195],
  ['tile',       195],
  ['retailer',   195],
  ['stockist',   195],
  ['architect',  190],
  ['designer',   192],
  ['pool',       193],
  ['builder',    194],
  ['developer',  194],
];

function businessCategoryIdFor(role) {
  const r = String(role || '').toLowerCase();
  for (const [key, val] of ROLE_TO_BUSINESS_CATEGORY) {
    if (val && r.includes(key)) return val;
  }
  return null;
}

// Both custom fields are multi-select. Pipedrive returns them as a
// comma-separated string of option ids; assigning a bare id would wipe any
// other value the person already carries. Merge instead, and return null
// when there is nothing new to add so the caller can skip the write.
function mergeSetField(existing, addIds) {
  const have = String(existing || '')
    .split(',').map(s => s.trim()).filter(Boolean);
  const merged = have.slice();
  for (const id of addIds || []) {
    if (id && !merged.includes(String(id))) merged.push(String(id));
  }
  if (merged.length === have.length) return null;
  return merged.join(',');
}

// Warranty person custom-field keys. Unlike the fields above these are NOT
// hard-coded: the keys are 40-char hashes that differ per workspace, so they
// come from env. Run `node scripts/pipedrive-warranty-fields.js` once to
// create the fields and print the exact assignments to paste into Railway.
// Every one is optional — an unset key means that field is simply skipped,
// so a partially-configured workspace still syncs whatever it can.
const WARRANTY_PERSON_FIELDS = [
  { env: 'PIPEDRIVE_FIELD_FABRICATOR',        name: 'Fabricator / installer', type: 'varchar', from: f => f.fabricator },
  { env: 'PIPEDRIVE_FIELD_RETAILER',          name: 'Retailer / stockist',    type: 'varchar', from: f => f.retailer },
  { env: 'PIPEDRIVE_FIELD_STONE_COLOUR',      name: 'Stone colour',           type: 'varchar', from: f => f.stone_name || f.stone_interest },
  { env: 'PIPEDRIVE_FIELD_INSTALLATION_DATE', name: 'Installation date',      type: 'date',    from: f => f.installation_date },
  { env: 'PIPEDRIVE_FIELD_WARRANTY_REFERENCE', name: 'Warranty reference',    type: 'varchar', from: (f, ref) => ref },
];

// Custom activity type created in the workspace for iPad walk-ins. Counting
// them relies on this key — generic 'meeting' is indistinguishable from every
// other rep meeting in the account.
const SHOWROOM_ACTIVITY_TYPE = process.env.PIPEDRIVE_SHOWROOM_ACTIVITY_TYPE || 'showroom_visit';

// Forms whose product line is implied by the form itself.
const PRODUCT_INTEREST_BY_FORM = {
  'Sample Request':      'engineered stone',
  'Warranty Activation': 'engineered stone',
};

let PD_HOT_LABEL_ID = null;

function getToken() { return process.env.PIPEDRIVE_API_TOKEN; }

async function pdGet(endpoint, params = {}) {
  const token = getToken();
  if (!token) return null;
  const url = new URL(`${PD_BASE}/${endpoint}`);
  url.searchParams.set('api_token', token);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null) url.searchParams.set(k, v);
  }
  try {
    const res = await fetch(url);
    return await res.json();
  } catch (err) {
    console.error('[pipedrive] GET', endpoint, 'failed:', err.message);
    return null;
  }
}

async function pdPost(endpoint, body) {
  const token = getToken();
  if (!token) return null;
  try {
    const res = await fetch(`${PD_BASE}/${endpoint}?api_token=${token}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    return await res.json();
  } catch (err) {
    console.error('[pipedrive] POST', endpoint, 'failed:', err.message);
    return null;
  }
}

async function pdPatch(endpoint, body) {
  const token = getToken();
  if (!token) return null;
  try {
    const res = await fetch(`${PD_BASE}/${endpoint}?api_token=${token}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    return await res.json();
  } catch (err) {
    console.error('[pipedrive] PATCH', endpoint, 'failed:', err.message);
    return null;
  }
}

// Email-first dedup: same email → same person. Falls back to creating a
// new person, optionally attaching to a matching/created organization.
async function findOrCreatePerson({ name, email, phone, company, role, interestedIn, state, consent }) {
  const bcId = businessCategoryIdFor(role);
  const pcIds = productCategoryIdsFor(interestedIn);
  const stateId = stateOptionId(state);
  if (email) {
    const search = await pdGet('persons/search', { term: email, fields: 'email', limit: 1 });
    const item = search?.data?.items?.[0]?.item;
    if (item?.id) {
      console.log(`[pipedrive] found existing person: ${item.name} (ID: ${item.id})`);
      // Existing people used to be returned untouched, so a repeat visitor
      // never picked up a category. Enrich in place, merging rather than
      // overwriting. Best-effort — a failure here must not block the form.
      await enrichPerson(item.id, bcId, pcIds, stateId, !!consent).catch(err =>
        console.error('[pipedrive] person enrich failed:', err.message));
      return item;
    }
  }

  const personData = { name: name || 'Unknown' };
  if (email) personData.email = [{ value: email, primary: true }];
  if (phone) personData.phone = [{ value: phone, primary: true }];

  if (company && String(company).trim()) {
    let orgId = null;
    const orgSearch = await pdGet('organizations/search', { term: company, limit: 1 });
    const orgItem = orgSearch?.data?.items?.[0]?.item;
    if (orgItem?.id) {
      orgId = orgItem.id;
    } else {
      // Match an existing organisation, but NEVER create one. Between May and
      // Aug 2026 this branch created 152 orgs with no category and no real
      // contact — homeowners typing a builder's name, a school, a suburb.
      // An unmatched company name is a job for Jess, not for a fuzzy search.
      console.log(`[pipedrive] no org match for "${company}" — leaving unlinked for manual review`);
    }
    if (orgId) personData.org_id = orgId;
  }

  if (bcId) personData[FIELD_BUSINESS_CATEGORY] = String(bcId);
  if (pcIds.length) personData[FIELD_PRODUCT_CATEGORY] = pcIds.join(',');
  if (stateId) personData[FIELD_STATE] = stateId;
  // Marketing consent. Pipedrive's built-in marketing_status is what its own
  // Campaigns feature reads, so it goes there rather than a custom field.
  // Only ever set to subscribed on an explicit tick — never inferred.
  personData.marketing_status = consent ? 'subscribed' : 'no_consent';

  const result = await pdPost('persons', personData);
  if (result?.data?.id) {
    console.log(`[pipedrive] created person: ${name} (ID: ${result.data.id})`);
  } else {
    console.warn('[pipedrive] person create returned no id for', email || name);
  }
  return result?.data || null;
}

// Merge Business/Product Category onto a person that already exists. Reads
// the current values first so multi-select entries aren't flattened — one
// contact in the workspace already carries "191,195" (Cabinet Maker + Tile
// Outlet) and a bare assignment would drop one of them.
async function enrichPerson(personId, bcId, pcIds, stateId, consentGiven) {
  if (!personId || (!bcId && !(pcIds && pcIds.length) && !stateId)) return;
  const current = await pdGet(`persons/${personId}`);
  const p = current?.data;
  if (!p) return;
  const patch = {};
  if (bcId) {
    const merged = mergeSetField(p[FIELD_BUSINESS_CATEGORY], [bcId]);
    if (merged) patch[FIELD_BUSINESS_CATEGORY] = merged;
  }
  if (pcIds && pcIds.length) {
    const merged = mergeSetField(p[FIELD_PRODUCT_CATEGORY], pcIds);
    if (merged) patch[FIELD_PRODUCT_CATEGORY] = merged;
  }
  // State is single-select: fill it when blank, never overwrite an answer
  // someone has already given.
  if (stateId && !p[FIELD_STATE]) patch[FIELD_STATE] = stateId;
  // Consent only ever moves upward. A repeat visitor who ticks the box is
  // subscribed; one who doesn't tick it is left exactly as they were. Never
  // downgrade someone who has already opted in, and never touch unsubscribed.
  if (consentGiven && p.marketing_status !== 'subscribed'
      && p.marketing_status !== 'unsubscribed') {
    patch.marketing_status = 'subscribed';
  }
  if (!Object.keys(patch).length) return;
  await pdPatch(`persons/${personId}`, patch);
  console.log(`[pipedrive] enriched person ${personId}:`, Object.keys(patch).join(', '));
}

// Creates a LEAD (Leads Inbox), not a Deal. Always tags HOT — every web
// form is an active outreach. Optional follow-up note attached to the lead.
async function createLead({ title, personId, orgId, notes, labelIds, leadFields }) {
  if (!personId) return null;
  const leadData = {
    title,
    person_id: personId,
  };
  if (orgId) leadData.organization_id = orgId;
  const labels = labelIds && labelIds.length
    ? labelIds
    : (PD_HOT_LABEL_ID ? [PD_HOT_LABEL_ID] : null);
  if (labels) leadData.label_ids = labels;
  // Custom fields go in the same POST body, keyed by field hash. Pipedrive
  // returns 200 regardless of whether it recognised them, so a change here
  // must be verified in the UI, not from the response.
  if (leadFields) {
    for (const [k, v] of Object.entries(leadFields)) {
      if (v !== null && v !== undefined && v !== '') leadData[k] = v;
    }
  }

  const result = await pdPost('leads', leadData);
  const leadId = result?.data?.id;
  if (leadId && notes) {
    await pdPost('notes', { lead_id: leadId, content: notes });
  }
  if (leadId) console.log(`[pipedrive] created HOT lead: ${title} (ID: ${leadId})`);
  return result?.data || null;
}

// Cache the workspace's "hot" label UUID so we don't look it up on every
// lead create. Safe to call on every boot — silent no-op without a token.
async function initPipedriveLabels() {
  if (!getToken()) return;
  try {
    const labels = await pdGet('leadLabels');
    if (Array.isArray(labels?.data)) {
      const hot = labels.data.find(l => String(l.name || '').toLowerCase() === 'hot');
      if (hot) PD_HOT_LABEL_ID = hot.id;
      console.log(`[pipedrive] labels loaded, hot=${PD_HOT_LABEL_ID || 'NOT FOUND'}`);
    }
  } catch (err) {
    console.error('[pipedrive] label lookup failed:', err.message);
  }
}

function escape(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// ─── Warranty: structured person fields + fabricator → organisation ───

// Normalise a business name for comparison. Deliberately conservative: it
// folds case, punctuation and trailing legal-entity suffixes, and nothing
// else. Stripping words like "Australia" or "Group" would fold genuinely
// different businesses together, and a wrong org link is worse than none —
// it silently reassigns a customer to another company's record.
const ORG_SUFFIXES = /\s+(pty\s+ltd|pty\s+limited|pty|ltd|limited|inc|incorporated|p\s+l)$/;

function normaliseOrgName(name) {
  let n = String(name || '')
    .toLowerCase()
    .replace(/&/g, ' and ')
    .replace(/[^a-z0-9]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  // Suffixes can stack ("Coast Stone Pty Ltd" → strip "pty ltd"); loop until
  // stable so "… Pty Ltd Ltd" and similar data-entry noise still land.
  let prev;
  do { prev = n; n = n.replace(ORG_SUFFIXES, '').trim(); } while (n !== prev);
  return n;
}

// Look for an existing organisation whose normalised name is exactly the
// fabricator's. Returns { status, org } where status is one of:
//   'matched'    — exactly one organisation matched, safe to link
//   'ambiguous'  — several distinct organisations matched, so we link none
//   'unmatched'  — nothing matched
//   'error'      — the search itself failed; NOT the same as unmatched, and
//                  deliberately separate so a Pipedrive outage can't quietly
//                  depress the match rate we report on.
// NEVER creates an organisation: an auto-created org per fabricator typo
// would fill the workspace with near-duplicates that someone has to merge
// by hand. Unmatched fabricators stay in the note and in the custom field.
async function matchFabricatorOrganisation(fabricator) {
  const target = normaliseOrgName(fabricator);
  if (target.length < 3) return { status: 'unmatched', org: null, target };
  const search = await pdGet('organizations/search', { term: fabricator, limit: 10 });
  // pdGet returns null when the request threw — a network failure, not a miss.
  if (search == null) return { status: 'error', org: null, target };
  const items = search?.data?.items || [];
  const hits = [];
  for (const entry of items) {
    const org = entry?.item;
    if (!org?.id) continue;
    if (normaliseOrgName(org.name) === target && !hits.some(h => h.id === org.id)) {
      hits.push({ id: org.id, name: org.name });
    }
  }
  if (hits.length === 1) return { status: 'matched', org: hits[0], target };
  if (hits.length > 1)   return { status: 'ambiguous', org: null, target, candidates: hits };
  return { status: 'unmatched', org: null, target };
}

// Pipedrive date fields accept YYYY-MM-DD and nothing else — that's the whole
// reason 'Installation date' is created as a `date` field rather than a
// varchar: only a real date field is filterable and sortable in the CRM.
// The form already sends YYYY-MM-DD (<input type="date">, checked server-side
// by isRealIsoDate), but a payload replayed from the fallback queue or built
// from a Postgres DATE can arrive as a full ISO timestamp, and hand-entered
// data as DD/MM/YYYY. Coerce what's recognisable; return null for anything
// else so the caller skips the field rather than posting a string Pipedrive
// will reject — a rejected value takes the whole patch, and the other four
// fields with it.
function toPipedriveDate(value) {
  const raw = String(value == null ? '' : value).trim();
  if (!raw) return null;
  let y, m, d;
  const iso = /^(\d{4})-(\d{2})-(\d{2})(?:[T\s].*)?$/.exec(raw);
  const au  = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/.exec(raw);
  if (iso)      { [, y, m, d] = iso; }
  else if (au)  { [, d, m, y] = au; }   // DD/MM/YYYY — Australian convention
  else return null;
  const out = `${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
  // Reject impossible calendar dates (2026-02-31 and friends) rather than
  // letting Pipedrive silently roll them forward.
  const parsed = new Date(`${out}T00:00:00Z`);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== out) return null;
  return out;
}

// Write the five structured warranty fields onto the person. Latest
// activation wins: someone activating a second benchtop has newer, more
// relevant detail, and the append-only notes keep the full history. Skips
// any field whose env key isn't configured and any empty value, so a
// half-configured workspace still writes what it can.
async function setWarrantyPersonFields(personId, fields, ref) {
  if (!personId) return [];
  const patch = {};
  const written = [];
  for (const def of WARRANTY_PERSON_FIELDS) {
    const key = process.env[def.env];
    if (!key) continue;
    const raw = def.from(fields, ref);
    if (raw == null || String(raw).trim() === '') continue;
    let value;
    if (def.type === 'date') {
      value = toPipedriveDate(raw);
      if (!value) {
        console.warn(`[pipedrive] skipping ${def.name}: "${raw}" is not a date Pipedrive accepts`);
        continue;
      }
    } else {
      value = String(raw).trim();
    }
    patch[key] = value;
    written.push(def.name);
  }
  if (!written.length) return [];
  // pdPatch swallows transport errors and returns null; don't claim success
  // on the back of that, or an outage reads as a clean write in the logs.
  const result = await pdPatch(`persons/${personId}`, patch);
  if (!result || result.success === false) {
    throw new Error(`person field write rejected (${written.length} field(s))`);
  }
  return written;
}

// Form-type → Pipedrive object mapping. Sample/Enquiry/Contact/Partner
// produce HOT leads; Showroom check-ins log a completed meeting activity;
// warranty activations attach as a person note (not a sales lead).
async function syncFormToPipedrive(formType, fields, sampleItems, typed) {
  if (!getToken()) return;
  const name = fields.name
    || `${fields.first_name || ''} ${fields.last_name || ''}`.trim()
    || 'Unknown';
  const role = fields.i_am_a || fields.role || fields.type || '';
  // Product interest → Pipedrive Product Category. The showroom iPad sends an
  // explicit `interested_in` (Engineered Stone / Tiles). Sample requests and
  // warranty activations are Alpha stone by definition, so they're mapped by
  // form type rather than by parsing stone names — "Opal Mist" contains no
  // word that would match. Anything else falls back to free text, which
  // simply yields no category when it matches nothing.
  const interestedIn = fields.interested_in
    || PRODUCT_INTEREST_BY_FORM[formType]
    || fields.stone_interest
    || role;
  const person = await findOrCreatePerson({
    name,
    email: fields.email,
    phone: fields.phone,
    company: fields.company || fields.store_location,
    role,
    interestedIn,
    state: fields.state,
    consent: !!fields.consent,
  });
  if (!person?.id) return;

  const stoneInterest = (Array.isArray(sampleItems) && sampleItems.length)
    ? sampleItems.map(s => s.name || s.slug).filter(Boolean).join(', ')
    : (fields.stone_interest || '');
  const ref = typed?.reference || '';
  const orgId = person.org_id?.value || person.org_id || null;

  // Landing-page attribution — when the form was originated by a tracked
  // outreach URL, prepend an attribution block to the lead note so sales
  // can see the campaign + AM at a glance. Empty string when the form
  // arrived without UTM params (organic / direct).
  const campaign = buildCampaignString(fields);
  const utmSource = fields.utm_source || '';
  const utmCampaign = fields.utm_campaign || '';
  const utmContent = fields.utm_content || '';
  const pid = fields.pid || '';
  const attribution = (utmSource === 'landing_page' && pid)
    ? `<b>Landing-page outreach</b><br>` +
      `Campaign: ${escape(utmCampaign || '—')}<br>` +
      `Sent by: ${escape(utmContent || '—')}<br>` +
      `Prospect ID: ${escape(pid)}<br><br>`
    : '';

  switch (formType) {
    case 'Sample Request':
      await createLead({
        title: `Sample Request — ${name}${stoneInterest ? ' (' + stoneInterest + ')' : ''}`,
        personId: person.id,
        orgId,
        leadFields: buildLeadFields({
          // Sprint B. A matched org id becomes a real link on the lead and
          // fires the referral automation. "Connect me with one" is handled
          // by Jess, who refers the nearest stonemason and logs it.
          stonemasonOrgId: fields.stonemason_org_id
            ? Number(fields.stonemason_org_id)
            : null,
          role,
          // /order-sample has its own reason select. 'Find a stockist' is a
          // Where-to-buy lead, not a sample request — keep it.
          reason: (fields.reason && String(fields.reason).trim().toLowerCase() !== 'sample')
            ? fields.reason
            : 'Sample request',
          stones: stoneInterest,
          campaign,
        }),
        notes:
          attribution +
          `<b>Sample Request ${escape(ref)}</b><br>` +
          `Stones: ${escape(stoneInterest || 'Not specified')}<br>` +
          `Source: alphasurfaces.com.au/order-sample<br>` +
          `Role: ${escape(role || '—')}<br>` +
          `State: ${escape(fields.state || '—')}<br>` +
          // Spam Act: record that consent was given, when, and via which form.
          `Marketing consent: ${fields.consent ? 'YES — ' + new Date().toISOString().slice(0, 10) + ' via /order-sample' : 'no'}<br>` +
          stonemasonNote(fields) +
          `Message: ${escape(fields.message || fields.special_instructions || '—')}`,
      });
      break;

    case 'Enquiry':
      await createLead({
        title: `Enquiry — ${name}: ${fields.reason || 'General'}`,
        personId: person.id,
        orgId,
        leadFields: buildLeadFields({
          role,
          reason: fields.reason || 'General enquiry',
          stones: stoneInterest,
          campaign,
        }),
        notes:
          attribution +
          `<b>Enquiry ${escape(ref)}</b><br>` +
          `Reason: ${escape(fields.reason || '—')}<br>` +
          `Message: ${escape(fields.message || '—')}<br>` +
          `Source: alphasurfaces.com.au/enquiry`,
      });
      break;

    case 'Contact Enquiry': {
      // store_location → trade contact form (always partner). Otherwise a
      // populated company also signals partner; bare-email contact form
      // without a company is a general consumer contact.
      const isPartner = !!(fields.store_location || (fields.company && String(fields.company).trim()));
      await createLead({
        title: `${isPartner ? 'Partner' : 'Contact'} — ${name}${isPartner && fields.company ? ' (' + fields.company + ')' : ''}`,
        personId: person.id,
        orgId,
        leadFields: buildLeadFields({
          role,
          reason: isPartner ? 'Partner enquiry' : 'General enquiry',
          campaign,
        }),
        notes:
          attribution +
          `<b>${isPartner ? 'Partner Enquiry' : 'Contact Form'} ${escape(ref)}</b><br>` +
          `Company: ${escape(fields.company || '—')}<br>` +
          `Message: ${escape(fields.message || '—')}<br>` +
          `Source: alphasurfaces.com.au/contact`,
      });
      break;
    }

    case 'Showroom Check-In':
      // Walk-ins aren't sales leads, so they stay out of the Leads Inbox and
      // log as a completed activity instead. The type is the workspace's
      // custom 'showroom_visit' (not generic 'meeting') so the saved filter
      // "Showroom Visits (iPad check-ins)" can count them. Pipedrive has no
      // custom fields on activities, so the visit detail stays in the note —
      // the reportable attributes live on the person record instead.
      await pdPost('activities', {
        person_id: person.id,
        org_id: orgId || undefined,
        type: SHOWROOM_ACTIVITY_TYPE,
        subject: `Showroom visit — ${name}`,
        note:
          `Walk-in at Kunda Park showroom.\n` +
          `Visitor type: ${fields.i_am_a || role || '—'}\n` +
          `Interested in: ${fields.interested_in || '—'}\n` +
          `State: ${fields.state || '—'}\n` +
          `Source: ${fields.source || '—'}\n` +
          `Marketing consent: ${fields.consent ? 'Yes' : 'No'}\n` +
          `Notes: ${fields.message || '—'}\n` +
          `Reference: ${ref || '—'}`,
        done: 1,
        due_date: new Date().toISOString().split('T')[0],
      });
      console.log(`[pipedrive] logged showroom visit for ${name}`);
      break;

    case 'Warranty Activation': {
      // Warranty activations are not sales leads and never become deals —
      // warranty_activations in Postgres stays the system of record. Pipedrive
      // gets the sales-relevant subset: five structured person fields (so the
      // data is filterable/reportable), an optional organisation link, and the
      // note as the human-readable summary.
      //
      // Each step is independently guarded. A failure in one must not stop the
      // others, and none of them may fail the submission — the caller in
      // server.js is already fire-and-forget, and this keeps a partial outage
      // from costing us the note as well as the fields.
      const photoCount = Array.isArray(fields.installation_photos) ? fields.installation_photos.length : 0;
      const coverage = fields.coverage_type || fields.warranty_type || '';

      // 1. Structured fields on the person.
      try {
        const written = await setWarrantyPersonFields(person.id, fields, ref);
        if (written.length) {
          console.log(`[pipedrive] warranty fields set on person ${person.id}: ${written.join(', ')}`);
        } else {
          console.warn('[pipedrive] no warranty person fields configured — ' +
            'run scripts/pipedrive-warranty-fields.js and set the PIPEDRIVE_FIELD_* env vars');
        }
      } catch (err) {
        console.error('[pipedrive] warranty field write failed:', err.message);
      }

      // 2. Fabricator → organisation, match-only. Logged either way so the
      // hit rate is visible in the Railway logs over time; grep
      // '[pipedrive] fabricator' to measure it.
      let orgNote = '';
      if (fields.fabricator && String(fields.fabricator).trim()) {
        try {
          const m = await matchFabricatorOrganisation(fields.fabricator);
          if (m.status === 'matched') {
            console.log(`[pipedrive] fabricator matched: "${fields.fabricator}" → org ${m.org.id} (${m.org.name})`);
            // Only fill an empty org — never move a person who is already
            // attached to an organisation someone chose deliberately.
            if (!orgId) {
              await pdPatch(`persons/${person.id}`, { org_id: m.org.id });
              console.log(`[pipedrive] linked person ${person.id} → org ${m.org.id}`);
            } else if (String(orgId) !== String(m.org.id)) {
              orgNote = `<br><i>Fabricator "${escape(fields.fabricator)}" matches organisation ` +
                `${escape(m.org.name)} (#${m.org.id}), but this person is already linked to ` +
                `organisation #${escape(orgId)} — left as is.</i>`;
              console.log(`[pipedrive] fabricator matched but person ${person.id} already on org ${orgId}`);
            }
          } else if (m.status === 'ambiguous') {
            const names = (m.candidates || []).map(c => `${c.name} (#${c.id})`).join(', ');
            console.log(`[pipedrive] fabricator ambiguous: "${fields.fabricator}" → ${names}`);
            orgNote = `<br><i>Fabricator "${escape(fields.fabricator)}" matches more than one ` +
              `organisation (${escape(names)}) — not linked, please pick one.</i>`;
          } else if (m.status === 'error') {
            // Not a miss — say so, so the hit rate stays honest.
            console.error(`[pipedrive] fabricator lookup errored: "${fields.fabricator}" — org match skipped`);
          } else {
            console.log(`[pipedrive] fabricator unmatched: "${fields.fabricator}" (normalised "${m.target}")`);
            orgNote = `<br><i>Fabricator "${escape(fields.fabricator)}" has no matching organisation ` +
              `in Pipedrive — not linked, and nothing was created automatically.</i>`;
          }
        } catch (err) {
          console.error('[pipedrive] fabricator org match failed:', err.message);
        }
      }

      // 3. The note stays the human-readable summary, leading with batch/lot —
      // those are what make a future claim traceable back to the slab.
      try {
        await pdPost('notes', {
          person_id: person.id,
          content:
            `<b>Warranty Activation ${escape(ref)}</b><br>` +
            `Batch: ${escape(fields.batch_number || '—')} · Shade: ${escape(fields.lot_number || '—')}<br>` +
            `Stone: ${escape(fields.stone_interest || fields.stone_name || '—')}<br>` +
            `Application: ${escape(fields.application || '—')}<br>` +
            `Warranty type: ${escape(coverage || '—')}<br>` +
            `Fabricator: ${escape(fields.fabricator || '—')}<br>` +
            `Retailer: ${escape(fields.retailer || '—')}<br>` +
            `Purchase date: ${escape(fields.purchase_date || '—')}<br>` +
            `Installation date: ${escape(fields.installation_date || '—')}<br>` +
            `Installation photos: ${photoCount ? photoCount + ' attached' : 'none'}` +
            `${fields.photo_consent ? ' (approved for social media)' : ''}<br>` +
            `Source: alphasurfaces.com.au/warranty` +
            orgNote,
        });
      } catch (err) {
        console.error('[pipedrive] warranty note failed:', err.message);
      }
      break;
    }

    default:
      // Unknown form types — silently skip.
      break;
  }
}

module.exports = {
  pdGet,
  pdPost,
  pdPatch,
  findOrCreatePerson,
  createLead,
  buildLeadFields,
  leadTypeIdFor,
  enquiryReasonIdFor,
  buildCampaignString,
  syncFormToPipedrive,
  initPipedriveLabels,
  matchFabricatorOrganisation,
  setWarrantyPersonFields,
  warnIfPipedriveMisrouted,
  WARRANTY_PERSON_FIELDS,
  DEFAULT_PD_BASE,
  toPipedriveDate,
  // Exported for tests — pure helpers, no network.
  businessCategoryIdFor,
  productCategoryIdsFor,
  mergeSetField,
  normaliseOrgName,
};
