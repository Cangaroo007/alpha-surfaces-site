// Pipedrive integration. Website forms create LEADS (not Deals) tagged HOT
// in the Leads Inbox; sales qualifies and converts manually. Walk-ins log
// as 'meeting' activities; warranty activations attach as a note on the
// person. Best-effort throughout — every call is wrapped so a Pipedrive
// outage can't fail a public form submit.

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

// Form-type → Pipedrive object mapping. Sample/Enquiry/Contact/Partner
// produce HOT leads; Showroom check-ins log a completed meeting activity;
// warranty activations attach as a person note (not a sales lead).
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

  switch (formType) {
    case 'Sample Request':
      await createLead({
        title: `Sample Request — ${name}${stoneInterest ? ' (' + stoneInterest + ')' : ''}`,
        personId: person.id,
        orgId,
        notes:
          `<b>Sample Request ${escape(ref)}</b><br>` +
          `Stones: ${escape(stoneInterest || 'Not specified')}<br>` +
          `Source: alphasurfaces.com.au/order-sample<br>` +
          `Role: ${escape(role || '—')}<br>` +
          `Message: ${escape(fields.message || fields.special_instructions || '—')}`,
      });
      break;

    case 'Enquiry':
      await createLead({
        title: `Enquiry — ${name}: ${fields.reason || 'General'}`,
        personId: person.id,
        orgId,
        notes:
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
        notes:
          `<b>${isPartner ? 'Partner Enquiry' : 'Contact Form'} ${escape(ref)}</b><br>` +
          `Company: ${escape(fields.company || '—')}<br>` +
          `Message: ${escape(fields.message || '—')}<br>` +
          `Source: alphasurfaces.com.au/contact`,
      });
      break;
    }

    case 'Showroom Check-In':
      // Walk-ins aren't sales leads — log a completed meeting so the
      // person record reflects the visit but we don't pollute the inbox.
      await pdPost('activities', {
        person_id: person.id,
        org_id: orgId || undefined,
        type: 'meeting',
        subject: `Showroom visit — ${name}`,
        note:
          `Walk-in at Kunda Park showroom. ` +
          `Interests: ${stoneInterest || fields.stone_interest || '—'}. ` +
          `Source: ${fields.source || '—'}. Notes: ${fields.message || '—'}`,
        done: 1,
        due_date: new Date().toISOString().split('T')[0],
      });
      console.log(`[pipedrive] logged showroom activity for ${name}`);
      break;

    case 'Warranty Activation':
      await pdPost('notes', {
        person_id: person.id,
        content:
          `<b>Warranty Activation ${escape(ref)}</b><br>` +
          `Stone: ${escape(fields.stone_interest || fields.stone_name || '—')}<br>` +
          `Fabricator: ${escape(fields.fabricator || '—')}<br>` +
          `Purchase date: ${escape(fields.purchase_date || '—')}<br>` +
          `Source: alphasurfaces.com.au/warranty`,
      });
      break;

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
  syncFormToPipedrive,
  initPipedriveLabels,
};
