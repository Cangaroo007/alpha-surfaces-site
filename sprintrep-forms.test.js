'use strict';
// node --test sprintrep-forms.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const sf = require('./sprintrep-forms');

const KEY = 'a'.repeat(32);
// Test value only. It opens nothing.
const SECRET = 'test-only-secret-0123456789abcdef0123456789';
const ENV = {
  FORMS_VIA_SPRINTREP: 'newsletter,contact,warranty,sample-modal',
  SPRINTREP_FORMS_URL: 'http://sprintrep.test',
  SPRINTREP_SITE_KEY: KEY,
  SPRINTREP_FORMS_SECRET: SECRET
};

/** An in-memory stand-in for the website's sprintrep_form_copies table. */
function fakePool() {
  const rows = new Map();
  let id = 0;
  return {
    rows,
    async query(sql, params) {
      if (/^CREATE TABLE/.test(sql)) return { rows: [] };
      if (/^INSERT INTO sprintrep_form_copies/.test(sql)) {
        const [cid, formId, fields, sampleItems, meta] = params;
        if (!rows.has(cid)) {
          rows.set(cid, { id: ++id, client_submission_id: cid, form_id: formId, fields: JSON.parse(fields),
            sample_items: JSON.parse(sampleItems), meta: JSON.parse(meta), status: 'pending', done: [],
            reference: null, fallback_reference: null, sprintrep_id: null, attempts: 0,
            created_at: new Date(Date.now() - 5 * 60000) });
        }
        return { rows: [rows.get(cid)] };
      }
      if (/^UPDATE sprintrep_form_copies/.test(sql)) {
        const [cid, status, reference, fbRef, sprintrepId, done, error, attempt] = params;
        const r = rows.get(cid);
        if (r) {
          if (status) r.status = status;
          if (reference) r.reference = reference;
          if (fbRef) r.fallback_reference = fbRef;
          if (sprintrepId) r.sprintrep_id = sprintrepId;
          if (done) r.done = done;
          r.last_error = error;
          if (attempt) r.attempts += 1;
        }
        return { rows: [] };
      }
      if (/^SELECT client_submission_id/.test(sql)) {
        return { rows: Array.from(rows.values()).filter(r => r.status === 'fallback' || r.status === 'pending') };
      }
      if (/^SELECT count/.test(sql)) {
        const waiting = Array.from(rows.values()).filter(r => r.status === 'fallback' || r.status === 'pending');
        return { rows: [{ n: waiting.length, oldest: waiting.length ? waiting[0].created_at : null }] };
      }
      if (/^DELETE/.test(sql)) return { rows: [] };
      throw new Error('unexpected SQL: ' + sql.slice(0, 60));
    }
  };
}

/** sprintrep as a fake: answers per mode, records what it was sent. */
function fakeSprintrep(mode) {
  const calls = [];
  let n = 73;
  const issued = new Map();
  const fetchImpl = async (url, init) => {
    if (String(url).startsWith('https://res.cloudinary.com/')) {
      return new Response(Buffer.from([0xff, 0xd8, 0xff, 1]), { headers: { 'content-type': 'image/jpeg' } });
    }
    const m = mode.value;
    let envelope;
    let photos = 0;
    if (init.body instanceof FormData) {
      envelope = JSON.parse(init.body.get('envelope'));
      photos = init.body.getAll('photos').length;
    } else {
      envelope = JSON.parse(init.body);
    }
    calls.push({ url: String(url), auth: init.headers.authorization, envelope, photos });
    if (m === 'down') throw new TypeError('fetch failed');
    if (m === 'error') return new Response(JSON.stringify({ ok: false, error: 'Try again in a moment.' }), { status: 503 });
    if (m === 'invalid') return new Response(JSON.stringify({ ok: false, error: 'Please select the application.' }), { status: 400 });
    const cid = envelope.clientSubmissionId;
    if (!issued.has(cid)) issued.set(cid, 'WA-' + String(++n).padStart(4, '0'));
    return new Response(JSON.stringify({ ok: true, id: 'sub-' + cid, reference: issued.get(cid) }), { status: 200 });
  };
  return { calls, fetchImpl };
}

function fakeRes() {
  return {
    code: 200,
    body: null,
    status(c) { this.code = c; return this; },
    json(b) { this.body = b; return this; }
  };
}
const REQ = { headers: { 'x-forwarded-for': '198.51.100.7', 'user-agent': 'Mozilla/5.0 test', referer: 'https://alphasurfaces.com.au/warranty' }, ip: '127.0.0.1' };

test('switches: per form, aliases, sample forms together, and only when configured', () => {
  const on = sf.enabledForms(ENV);
  assert.ok(on.has('newsletter') && on.has('contact') && on.has('warranty'));
  assert.ok(on.has('order-sample') && on.has('sample-modal'), 'the two sample forms share the SR- series');
  assert.equal(sf.enabledForms({ FORMS_VIA_SPRINTREP: '' }).size, 0);
  assert.ok(sf.enabledForms({ FORMS_VIA_SPRINTREP: 'partner-contact' }).has('contact'));
  assert.equal(sf.formIdFor('Warranty Activation', {}, ENV), 'warranty');
  assert.equal(sf.formIdFor('Sample Request', { sampleItems: [] }, ENV), 'order-sample');
  assert.equal(sf.formIdFor('Sample Request', { stone_slug: 'x' }, ENV), 'sample-modal');
  assert.equal(sf.formIdFor('Enquiry', {}, ENV), null, 'enquiry is not switched on');
  assert.equal(sf.formIdFor('Showroom Check-In', {}, ENV), null);
  // Switched on but no key or secret: handled here, as before.
  assert.equal(sf.formIdFor('Warranty Activation', {}, { FORMS_VIA_SPRINTREP: 'warranty' }), null);
});

test('forwarder: sent to sprintrep with the secret, photos copied, the answer passed back, no local work', async () => {
  const mode = { value: 'ok' };
  const sp = fakeSprintrep(mode);
  const pool = fakePool();
  let local = 0;
  const res = fakeRes();
  await sf.handle(REQ, res, { pool, env: ENV, fetchImpl: sp.fetchImpl, queue: { enqueue() { throw new Error('no'); } } }, {
    formId: 'warranty',
    fields: { _client_submission_id: 'cid-1', name: 'W', email: 'w@example.test', installation_photos: ['https://res.cloudinary.com/demo/a.jpg', 'https://evil.example/b.jpg'] },
    sampleItems: [],
    done: ['staff_alert', 'crm'],
    localFallback: async () => { local += 1; return {}; },
    queueFallback: () => { throw new Error('no'); }
  });
  assert.deepEqual(res.body, { ok: true, id: 'sub-cid-1', reference: 'WA-0074' });
  assert.equal(local, 0, 'no Pipedrive, email or SMS from the website');
  assert.equal(sp.calls.length, 1);
  assert.equal(sp.calls[0].url, 'http://sprintrep.test/forms/' + KEY + '/warranty');
  assert.equal(sp.calls[0].auth, 'Bearer ' + SECRET);
  assert.equal(sp.calls[0].photos, 1, 'only the image host\'s photos are copied');
  assert.deepEqual(sp.calls[0].envelope.done, []);
  assert.equal(sp.calls[0].envelope.meta.ip, '198.51.100.7');
  assert.equal(pool.rows.get('cid-1').status, 'forwarded', 'the website keeps its own copy');
  // The browser retries (form-rescue): the stored answer, nothing sent again.
  const again = fakeRes();
  await sf.handle(REQ, again, { pool, env: ENV, fetchImpl: sp.fetchImpl }, {
    formId: 'warranty', fields: { _client_submission_id: 'cid-1' }, localFallback: async () => { local += 1; }
  });
  assert.equal(again.body.reference, 'WA-0074');
  assert.equal(sp.calls.length, 1);
});

test('fallback: sprintrep down or failing, the website does it all itself, then sends it later', async () => {
  for (const failure of ['down', 'error']) {
    const mode = { value: failure };
    const sp = fakeSprintrep(mode);
    const pool = fakePool();
    const did = [];
    const res = fakeRes();
    await sf.handle(REQ, res, { pool, env: ENV, fetchImpl: sp.fetchImpl, queue: { enqueue() {} } }, {
      formId: 'contact',
      fields: { _client_submission_id: 'cid-' + failure, name: 'P', email: 'p@example.test' },
      sampleItems: [],
      done: ['staff_alert', 'crm'],
      localFallback: async (fbRef) => { did.push(fbRef); return { id: 9 }; },
      queueFallback: () => { throw new Error('no'); }
    });
    assert.equal(res.code, 200);
    assert.equal(res.body.ok, true);
    assert.match(res.body.reference, /^FB-/);
    assert.deepEqual(did, [res.body.reference], 'Jess still gets the email and SMS; Pipedrive is written');
    const copy = pool.rows.get('cid-' + failure);
    assert.equal(copy.status, 'fallback');
    assert.deepEqual(copy.done, ['staff_alert', 'crm']);
    // sprintrep is back: the retry sends it once, marked as already done here.
    mode.value = 'ok';
    const stats = await sf.retryWaiting({ pool, env: ENV, fetchImpl: sp.fetchImpl }, 25);
    assert.equal(stats.sent, 1);
    const last = sp.calls[sp.calls.length - 1];
    assert.deepEqual(last.envelope.done, ['staff_alert', 'crm']);
    assert.equal(last.envelope.fallback, true);
    assert.equal(last.envelope.meta.fallbackReference, res.body.reference);
    assert.equal(copy.status, 'forwarded');
    assert.equal((await sf.retryWaiting({ pool, env: ENV, fetchImpl: sp.fetchImpl }, 25)).sent, 0, 'sent once');
  }
});

test('sprintrep refuses the answers: the visitor is told, nothing is done twice', async () => {
  const sp = fakeSprintrep({ value: 'invalid' });
  const pool = fakePool();
  const res = fakeRes();
  let local = 0;
  await sf.handle(REQ, res, { pool, env: ENV, fetchImpl: sp.fetchImpl }, {
    formId: 'warranty', fields: { _client_submission_id: 'bad-1' }, localFallback: async () => { local += 1; }
  });
  assert.equal(res.code, 400);
  assert.deepEqual(res.body, { ok: false, error: 'Please select the application.' });
  assert.equal(local, 0);
});

test('this server\'s database is down too: the file queue keeps it for sprintrep', async () => {
  const sp = fakeSprintrep({ value: 'down' });
  const queued = [];
  const pool = { async query() { throw new Error('db down'); } };
  sf._setReady(null);
  const res = fakeRes();
  await sf.handle(REQ, res, { pool, env: ENV, fetchImpl: sp.fetchImpl, queue: { enqueue: (r) => queued.push(r) } }, {
    formId: 'newsletter',
    fields: { email: 'n@example.test', consent: true },
    done: ['staff_alert', 'customer_email'],
    localFallback: async () => ({ id: 1 }),
    queueFallback: () => { throw new Error('no'); }
  });
  assert.equal(res.body.ok, true);
  assert.equal(queued.length, 1);
  assert.equal(queued[0].kind, 'sprintrep');
  assert.deepEqual(queued[0].meta.done, ['staff_alert', 'customer_email']);
  sf._setReady(null);
});

test('without a submission id the website makes one; an FB- reference is stable for an id', () => {
  assert.equal(sf.clientSubmissionId({ _client_submission_id: 'abc' }), 'abc');
  assert.equal(sf.clientSubmissionId({ _client_submission_id: 'bad id!' }), null);
  assert.equal(sf.fallbackReference('1234-abcd-5678'), 'FB-1234ABCD56');
});
