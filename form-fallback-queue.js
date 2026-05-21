const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

let queueDir = path.join(__dirname, 'data', 'form-fallback-queue');

function setQueueDir(dir) {
  queueDir = dir;
}

function ensureQueueDir() {
  fs.mkdirSync(queueDir, { recursive: true, mode: 0o700 });
}

function safeId(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 80);
}

function fallbackIdFor(record) {
  const provided = safeId(
    record?.fields?._client_submission_id ||
    record?.fields?.client_submission_id ||
    record?.fields?.submission_uuid
  );
  return provided || crypto.randomUUID();
}

function fileFor(id) {
  return path.join(queueDir, `${safeId(id)}.json`);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeJsonAtomic(file, data) {
  ensureQueueDir();
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

function enqueue(record) {
  ensureQueueDir();
  const id = fallbackIdFor(record);
  const file = fileFor(id);
  const now = new Date().toISOString();
  let existing = null;

  if (fs.existsSync(file)) {
    try {
      existing = readJson(file);
    } catch (err) {
      console.error('[form-fallback] existing queue item parse error:', err.message);
    }
  }

  const queued = {
    id,
    status: existing?.status || 'pending',
    attempts: existing?.attempts || 0,
    created_at: existing?.created_at || now,
    updated_at: now,
    replayed_at: existing?.replayed_at || null,
    last_error: existing?.last_error || null,
    kind: record.kind || existing?.kind || 'form',
    formType: record.formType || existing?.formType || 'Unknown',
    fields: record.fields || existing?.fields || {},
    sampleItems: record.sampleItems || existing?.sampleItems || [],
    meta: {
      ...(existing?.meta || {}),
      ...(record.meta || {})
    }
  };

  writeJsonAtomic(file, queued);
  return queued;
}

function list(status = 'pending') {
  ensureQueueDir();
  return fs.readdirSync(queueDir)
    .filter(name => name.endsWith('.json'))
    .map(name => path.join(queueDir, name))
    .map(file => {
      try {
        const item = readJson(file);
        item._file = file;
        return item;
      } catch (err) {
        console.error('[form-fallback] queue item parse error:', file, err.message);
        return null;
      }
    })
    .filter(Boolean)
    .filter(item => !status || item.status === status)
    .sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)));
}

function update(id, patch) {
  const file = fileFor(id);
  const current = fs.existsSync(file) ? readJson(file) : { id };
  const next = {
    ...current,
    ...patch,
    updated_at: new Date().toISOString()
  };
  writeJsonAtomic(file, next);
  return next;
}

function markReplayed(id, dbId, reference) {
  return update(id, {
    status: 'replayed',
    db_id: dbId || null,
    reference: reference || null,
    replayed_at: new Date().toISOString(),
    last_error: null
  });
}

function markFailed(item, err) {
  const attempts = (item.attempts || 0) + 1;
  return update(item.id, {
    status: attempts >= 288 ? 'failed' : 'pending',
    attempts,
    last_error: err && err.message ? err.message : String(err || 'Unknown error')
  });
}

module.exports = {
  setQueueDir,
  enqueue,
  list,
  update,
  markReplayed,
  markFailed
};
