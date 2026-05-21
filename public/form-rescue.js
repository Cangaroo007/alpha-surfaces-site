(function () {
  'use strict';
  if (window.__alphaFormRescueLoaded || !window.fetch || !window.localStorage) return;
  window.__alphaFormRescueLoaded = true;

  var STORAGE_KEY = 'alpha_surfaces_pending_forms_v1';
  var TARGETS = {
    '/api/order-sample': true,
    '/api/contact': true,
    '/api/subscribe': true,
    '/api/form-submit': true
  };
  var originalFetch = window.fetch.bind(window);

  function loadQueue() {
    try {
      return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}') || {};
    } catch (err) {
      return {};
    }
  }

  function saveQueue(queue) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(queue));
    } catch (err) {
      // Storage can fail in private browsing or when full. The server-side
      // fallback still protects accepted submissions.
    }
  }

  function makeId() {
    if (window.crypto && window.crypto.randomUUID) return window.crypto.randomUUID();
    return 'fs-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
  }

  function pathFor(input) {
    var raw = typeof input === 'string' ? input : (input && input.url);
    if (!raw) return null;
    try {
      return new URL(raw, window.location.origin).pathname;
    } catch (err) {
      return null;
    }
  }

  function headersObject(headers) {
    var out = {};
    if (!headers) return out;
    if (headers instanceof Headers) {
      headers.forEach(function (value, key) { out[key] = value; });
      return out;
    }
    Object.keys(headers).forEach(function (key) { out[key] = headers[key]; });
    return out;
  }

  function hasJsonContent(headers) {
    var value = '';
    Object.keys(headers || {}).forEach(function (key) {
      if (key.toLowerCase() === 'content-type') value = headers[key];
    });
    return /application\/json/i.test(value || '');
  }

  function prepare(input, init) {
    init = init || {};
    var path = pathFor(input);
    var method = String(init.method || 'GET').toUpperCase();
    if (!TARGETS[path] || method !== 'POST' || typeof init.body !== 'string') return null;

    var headers = headersObject(init.headers);
    if (!hasJsonContent(headers)) return null;

    var body;
    try {
      body = JSON.parse(init.body);
    } catch (err) {
      return null;
    }
    if (!body || typeof body !== 'object') return null;

    var id = body._client_submission_id || body.client_submission_id || body.submission_uuid || makeId();
    body._client_submission_id = id;

    var nextInit = Object.assign({}, init, {
      headers: headers,
      body: JSON.stringify(body)
    });
    var url = typeof input === 'string' ? input : input.url;
    var entry = {
      id: id,
      url: url,
      path: path,
      method: method,
      headers: headers,
      body: body,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      attempts: 0,
      nextAttemptAt: Date.now() + 30000
    };
    return { id: id, init: nextInit, entry: entry };
  }

  function remember(entry) {
    var queue = loadQueue();
    var existing = queue[entry.id] || {};
    queue[entry.id] = Object.assign({}, existing, entry, {
      createdAt: existing.createdAt || entry.createdAt,
      attempts: existing.attempts || entry.attempts
    });
    saveQueue(queue);
  }

  function forget(id) {
    var queue = loadQueue();
    if (!queue[id]) return;
    delete queue[id];
    saveQueue(queue);
  }

  function postpone(id, delayMs) {
    var queue = loadQueue();
    if (!queue[id]) return;
    queue[id].updatedAt = Date.now();
    queue[id].attempts = (queue[id].attempts || 0) + 1;
    queue[id].nextAttemptAt = Date.now() + delayMs;
    saveQueue(queue);
  }

  window.fetch = function (input, init) {
    var prepared = prepare(input, init);
    if (!prepared) return originalFetch(input, init);

    remember(prepared.entry);

    return originalFetch(input, prepared.init).then(function (response) {
      response.clone().json().then(function (json) {
        if (json && json.ok) forget(prepared.id);
        else postpone(prepared.id, 60000);
      }).catch(function () {
        if (response.ok) forget(prepared.id);
        else postpone(prepared.id, 60000);
      });
      return response;
    }).catch(function (err) {
      postpone(prepared.id, 60000);
      throw err;
    });
  };

  function replayPending() {
    var queue = loadQueue();
    var now = Date.now();
    Object.keys(queue).forEach(function (id) {
      var item = queue[id];
      if (!item || item.nextAttemptAt > now) return;
      item.body._client_submission_id = item.id;
      item.updatedAt = now;
      item.attempts = (item.attempts || 0) + 1;
      item.nextAttemptAt = now + Math.min(30 * 60000, 60000 * Math.max(1, item.attempts));
      queue[id] = item;
      saveQueue(queue);

      originalFetch(item.url, {
        method: item.method || 'POST',
        headers: item.headers || { 'Content-Type': 'application/json' },
        body: JSON.stringify(item.body),
        credentials: 'same-origin'
      }).then(function (response) {
        return response.clone().json().catch(function () { return { ok: response.ok }; });
      }).then(function (json) {
        if (json && json.ok) forget(id);
      }).catch(function () {
        postpone(id, 60000);
      });
    });
  }

  window.addEventListener('online', replayPending);
  setTimeout(replayPending, 3000);
  setInterval(replayPending, 2 * 60000);
})();
