// Pipedrive integration. Public forms create LEADS (not Deals) tagged HOT plus
// a form-specific label in the Leads Inbox; sales qualifies and converts
// manually. Showroom check-ins also log a completed meeting activity. Best-
// effort throughout — a Pipedrive outage can't fail a public form submit.

const PD_BASE = 'https://api.pipedrive.com/v1';

// Pipedrive person custom-field keys (provided by the workspace).
// Business Category is mapped from form `i_am_a` / `role` strings.
const FIELD_BUSINESS_CATEGORY = 'da25035c39ec621856e3252165feaf9141423b88';
// Product Category is left for future enrichment (Alpha Surfaces=187,
// Porcelain Tiles=188); we don't set it from forms today.
// const FIELD_PRODUCT_CATEGORY  = '6c3a7edb24cde1d21864dcb96693e76fc7bcd116';

const ROLE_TO_BUSINESS_CATEGORY = {
  homeowner: null,
  builder: 194,
  developer: 194,
  architect: 190,
  designer: 192,
  fabricator: 189,
  stonemason: 189,
  retailer: 195,
  stockist: 195,
  pool: 193,
  cabinet: 191,
};

let PD_HOT_LABEL_ID = null;
let PD_LEAD_LABELS_BY_NAME = new Map();
let PD_LABELS_LOADED = false;

const FORM_LEAD_LABELS = {
  'Sample Request': { name: 'Sample Request', color: 'green' },
  'Enquiry': { name: 'Website Enquiry', color: 'blue' },
  'Contact Form': { name: 'Contact Form', color: 'purple' },
  'Partner Enquiry': { name: 'Partner Enquiry', color: 'yellow' },
  'Showroom Check-In': { name: 'Showroom Check-In', color: 'orange' },
  'Warranty Activation': { name: 'Warranty Activation', color: 'red' },
  'Newsletter': { name: 'Newsletter Signup', color: 'gray' },
};

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
    const data = await res.json().catch(() => null);
    if (!res.ok || data?.success === false) {
      console.error('[pipedrive] GET', endpoint, 'failed:', res.status, JSON.stringify(data));
      return null;
    }
    return data;
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
    const data = await res.json().catch(() => null);
    if (!res.ok || data?.success === false) {
      console.error('[pipedrive] POST', endpoint, 'failed:', res.status, JSON.stringify(data), 'body:', JSON.stringify(body));
      return null;
    }
    return data;
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
    const data = await res.json().catch(() => null);
    if (!res.ok || data?.success === false) {
      console.error('[pipedrive] PATCH', endpoint, 'failed:', res.status, JSON.stringify(data), 'body:', JSON.stringify(body));
      return null;
    }
    return data;
  } catch (err) {
    console.error('[pipedrive] PATCH', endpoint, 'failed:', err.message);
    return null;
  }
}

// Email-first dedup: same email → same person. Falls back to creating a
// new person, optionally attaching to a matching/created organization.
async function findOrCreatePerson({ name, email, phone, company, role }) {
  if (email) {
    const search = await pdGet('persons/search', { term: email, fields: 'email', limit: 1 });
    const item = search?.data?.items?.[0]?.item;
    if (item?.id) {
      console.log(`[pipedrive] found existing person: ${item.name} (ID: ${item.id})`);
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
      const orgResult = await pdPost('organizations', { name: company });
      orgId = orgResult?.data?.id || null;
    }
    if (orgId) personData.org_id = orgId;
  }

  const r = String(role || '').toLowerCase();
  for (const [key, val] of Object.entries(ROLE_TO_BUSINESS_CATEGORY)) {
    if (val && r.includes(key)) {
      personData[FIELD_BUSINESS_CATEGORY] = val;
      break;
    }
  }

  const result = await pdPost('persons', personData);
  if (result?.data?.id) {
    console.log(`[pipedrive] created person: ${name} (ID: ${result.data.id})`);
  } else {
    console.warn('[pipedrive] person create returned no id for', email || name);
  }
  return result?.data || null;
}

// Creates a LEAD (Leads Inbox), not a Deal. Always tags HOT — every web
// form is an active outreach. Optional follow-up note attached to the lead.
async function createLead({ title, personId, orgId, notes, labelIds }) {
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

  const result = await pdPost('leads', leadData);
  const leadId = result?.data?.id;
  if (leadId && notes) {
    await pdPost('notes', { lead_id: leadId, content: notes });
  }
  if (leadId) console.log(`[pipedrive] created HOT lead: ${title} (ID: ${leadId})`);
  return result?.data || null;
}

function cacheLeadLabels(labels) {
  PD_LEAD_LABELS_BY_NAME = new Map();
  if (!Array.isArray(labels)) return;
  labels.forEach(label => {
    const name = String(label.name || '').toLowerCase();
    if (name) PD_LEAD_LABELS_BY_NAME.set(name, label);
  });
  const hot = labels.find(l => String(l.name || '').toLowerCase() === 'hot');
  if (hot) PD_HOT_LABEL_ID = hot.id;
  PD_LABELS_LOADED = true;
}

async function loadLeadLabelsIfNeeded() {
  if (PD_LABELS_LOADED) return;
  const labels = await pdGet('leadLabels');
  if (Array.isArray(labels?.data)) cacheLeadLabels(labels.data);
}

async function ensureLeadLabel(labelSpec) {
  if (!labelSpec || !labelSpec.name) return null;
  await loadLeadLabelsIfNeeded();
  if (!PD_LABELS_LOADED) return null;
  const key = String(labelSpec.name).toLowerCase();
  const existing = PD_LEAD_LABELS_BY_NAME.get(key);
  if (existing?.id) return existing.id;

  const created = await pdPost('leadLabels', {
    name: labelSpec.name,
    color: labelSpec.color || 'gray'
  });
  const label = created?.data;
  if (label?.id) {
    PD_LEAD_LABELS_BY_NAME.set(key, label);
    console.log(`[pipedrive] created lead label: ${labelSpec.name} (${label.id})`);
    return label.id;
  }
  return null;
}

async function labelIdsForForm(formType, labelKey) {
  await loadLeadLabelsIfNeeded();
  const labels = [];
  if (PD_HOT_LABEL_ID) labels.push(PD_HOT_LABEL_ID);
  const formLabelId = await ensureLeadLabel(FORM_LEAD_LABELS[labelKey || formType]);
  if (formLabelId && !labels.includes(formLabelId)) labels.push(formLabelId);
  return labels.length ? labels : null;
}

// Cache the workspace's "hot" label UUID so we don't look it up on every
// lead create. Safe to call on every boot — silent no-op without a token.
async function initPipedriveLabels() {
  if (!getToken()) return;
  try {
    const labels = await pdGet('leadLabels');
    if (Array.isArray(labels?.data)) {
      cacheLeadLabels(labels.data);
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

// Form-type → Pipedrive object mapping. Every public form creates a lead with
// HOT + form-specific labels. Showroom check-ins also log a completed meeting.
async function syncFormToPipedrive(formType, fields, sampleItems, typed) {
  if (!getToken()) return;
  const name = fields.name
    || `${fields.first_name || ''} ${fields.last_name || ''}`.trim()
    || 'Unknown';
  const role = fields.i_am_a || fields.role || fields.type || '';
  const person = await findOrCreatePerson({
    name,
    email: fields.email,
    phone: fields.phone,
    company: fields.company || fields.store_location,
    role,
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
      return await createLead({
        title: `Sample Request — ${name}${stoneInterest ? ' (' + stoneInterest + ')' : ''}`,
        personId: person.id,
        orgId,
        labelIds: await labelIdsForForm(formType),
        notes:
          attribution +
          `<b>Sample Request ${escape(ref)}</b><br>` +
          `Stones: ${escape(stoneInterest || 'Not specified')}<br>` +
          `Source: alphasurfaces.com.au/order-sample<br>` +
          `Role: ${escape(role || '—')}<br>` +
          `Message: ${escape(fields.message || fields.special_instructions || '—')}`,
      });

    case 'Enquiry':
      return await createLead({
        title: `Enquiry — ${name}: ${fields.reason || 'General'}`,
        personId: person.id,
        orgId,
        labelIds: await labelIdsForForm(formType),
        notes:
          attribution +
          `<b>Enquiry ${escape(ref)}</b><br>` +
          `Reason: ${escape(fields.reason || '—')}<br>` +
          `Message: ${escape(fields.message || '—')}<br>` +
          `Source: alphasurfaces.com.au/enquiry`,
      });

    case 'Contact Enquiry': {
      // store_location → trade contact form (always partner). Otherwise a
      // populated company also signals partner; bare-email contact form
      // without a company is a general consumer contact.
      const isPartner = !!(fields.store_location || (fields.company && String(fields.company).trim()));
      return await createLead({
        title: `${isPartner ? 'Partner' : 'Contact'} — ${name}${isPartner && fields.company ? ' (' + fields.company + ')' : ''}`,
        personId: person.id,
        orgId,
        labelIds: await labelIdsForForm(formType, isPartner ? 'Partner Enquiry' : 'Contact Form'),
        notes:
          attribution +
          `<b>${isPartner ? 'Partner Enquiry' : 'Contact Form'} ${escape(ref)}</b><br>` +
          `Company: ${escape(fields.company || '—')}<br>` +
          `Message: ${escape(fields.message || '—')}<br>` +
          `Source: alphasurfaces.com.au/contact`,
      });
    }

    case 'Showroom Check-In':
      // Walk-ins create a form-specific lead and a completed meeting so the
      // visit appears in the Leads Inbox and on the person timeline.
      const showroomLead = await createLead({
        title: `Showroom Check-In — ${name}${stoneInterest ? ' (' + stoneInterest + ')' : ''}`,
        personId: person.id,
        orgId,
        labelIds: await labelIdsForForm(formType),
        notes:
          `<b>Showroom Check-In ${escape(ref)}</b><br>` +
          `Visitor type: ${escape(role || '—')}<br>` +
          `Interests: ${escape(stoneInterest || fields.stone_interest || '—')}<br>` +
          `Source: ${escape(fields.source || '—')}<br>` +
          `Marketing consent: ${fields.consent ? 'Yes' : 'No'}<br>` +
          `Notes: ${escape(fields.message || '—')}`,
      });
      await pdPost('activities', {
        person_id: person.id,
        org_id: orgId || undefined,
        type: 'meeting',
        subject: `Showroom visit — ${name}`,
        note:
          `Walk-in at Kunda Park showroom. ` +
          `Visitor type: ${role || '—'}. ` +
          `Interests: ${stoneInterest || fields.stone_interest || '—'}. ` +
          `Source: ${fields.source || '—'}. ` +
          `Marketing consent: ${fields.consent ? 'Yes' : 'No'}. ` +
          `Notes: ${fields.message || '—'}`,
        done: 1,
        due_date: new Date().toISOString().split('T')[0],
      });
      console.log(`[pipedrive] logged showroom activity for ${name}`);
      return showroomLead;

    case 'Warranty Activation':
      return await createLead({
        title: `Warranty Activation — ${name}${fields.stone_interest || fields.stone_name ? ' (' + (fields.stone_interest || fields.stone_name) + ')' : ''}`,
        personId: person.id,
        orgId,
        labelIds: await labelIdsForForm(formType),
        notes:
          `<b>Warranty Activation ${escape(ref)}</b><br>` +
          `Stone: ${escape(fields.stone_interest || fields.stone_name || '—')}<br>` +
          `Fabricator: ${escape(fields.fabricator || '—')}<br>` +
          `Purchase date: ${escape(fields.purchase_date || '—')}<br>` +
          `Source: alphasurfaces.com.au/warranty`,
      });

    case 'Newsletter':
      return await createLead({
        title: `Newsletter Signup — ${name || fields.email}`,
        personId: person.id,
        orgId,
        labelIds: await labelIdsForForm(formType),
        notes:
          `<b>Newsletter Signup ${escape(ref)}</b><br>` +
          `Email: ${escape(fields.email || '—')}<br>` +
          `Source: ${escape(fields.source || fields.sourceUrl || 'alphasurfaces.com.au')}`,
      });

    default:
      return null;
  }
}

module.exports = {
  pdGet,
  pdPost,
  pdPatch,
  findOrCreatePerson,
  createLead,
  syncFormToPipedrive,
  initPipedriveLabels,
};
