/* ─── Submissions dashboard ───────────────────────────────────────────────
   Tabs:
     - Submissions (form_submissions table: Sample / Contact / Partner)
     - Newsletter  (newsletter_subscribers table)
     - Form Schemas (label/placeholder/required editor)

   Categories under Submissions are derived from form_type + store_location:
     all     → no filter
     sample  → form_type='Sample Request'
     contact → form_type='Contact Enquiry' AND store_location IS NULL/empty
     partner → form_type='Contact Enquiry' AND store_location IS NOT NULL
   The server understands ?category=sample|contact|partner; we don't pass
   form_type from the UI — categories cover all cases.
   ──────────────────────────────────────────────────────────────────────── */
(function () {
  'use strict';

  var PAGE_SIZE = 25;

  var state = {
    tab: 'submissions',          // 'submissions' | 'newsletter' | 'schemas'
    category: 'all',             // 'all' | 'sample' | 'contact' | 'partner'
    status: '',                  // '' | 'new' | 'actioned' | 'archived' (or active/unsubscribed/pending for newsletter)
    q: '',
    dateFrom: '',
    dateTo: '',
    offset: 0,
    counts: {},                  // headline counts from backend
    newsletterCounts: {}
  };

  var searchDebounce = null;

  // ─── Entry point ─────────────────────────────────────────────────────────
  async function renderFormsPanel() {
    var container = document.getElementById('forms-panel');
    if (!container) return;

    container.innerHTML =
      '<div class="forms-header">' +
        '<h2>📨 Form Submissions</h2>' +
        '<div class="forms-header-actions">' +
          '<button class="btn-tab-switch ' + (state.tab === 'submissions' ? 'active' : '') + '" id="tab-submissions">Submissions <span class="badge" id="badge-submissions"></span></button>' +
          '<button class="btn-tab-switch ' + (state.tab === 'newsletter'  ? 'active' : '') + '" id="tab-newsletter">Newsletter <span class="badge" id="badge-newsletter"></span></button>' +
          '<button class="btn-tab-switch ' + (state.tab === 'schemas'     ? 'active' : '') + '" id="tab-schemas">Form Schemas</button>' +
        '</div>' +
      '</div>' +
      '<div id="forms-tab-submissions" style="display:' + (state.tab === 'submissions' ? 'block' : 'none') + '"></div>' +
      '<div id="forms-tab-newsletter"  style="display:' + (state.tab === 'newsletter'  ? 'block' : 'none') + '"></div>' +
      '<div id="forms-tab-schemas"     style="display:' + (state.tab === 'schemas'     ? 'block' : 'none') + '"></div>' +
      '<div id="forms-toast" class="forms-toast hidden"></div>';

    document.getElementById('tab-submissions').onclick = function () { switchTab('submissions'); };
    document.getElementById('tab-newsletter').onclick  = function () { switchTab('newsletter');  };
    document.getElementById('tab-schemas').onclick     = function () { switchTab('schemas');     };

    if (state.tab === 'submissions') loadSubmissions();
    else if (state.tab === 'newsletter') loadNewsletter();
    else if (state.tab === 'schemas') loadSchemas();
  }

  function switchTab(tab) {
    state.tab = tab;
    state.offset = 0;
    state.q = '';
    state.status = '';
    state.dateFrom = '';
    state.dateTo = '';
    state.category = 'all';
    renderFormsPanel();
  }

  // ─── Submissions tab ─────────────────────────────────────────────────────
  async function loadSubmissions() {
    var container = document.getElementById('forms-tab-submissions');
    container.innerHTML = '<div class="forms-loading">Loading submissions…</div>';

    try {
      var params = new URLSearchParams({ limit: PAGE_SIZE, offset: state.offset });
      if (state.category && state.category !== 'all') params.set('category', state.category);
      if (state.status)   params.set('status',    state.status);
      if (state.q)        params.set('q',         state.q);
      if (state.dateFrom) params.set('date_from', state.dateFrom);
      if (state.dateTo)   params.set('date_to',   state.dateTo);

      var res = await fetch('/api/admin/submissions?' + params, { credentials: 'include' });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      var data = await res.json();
      if (!data.ok) throw new Error(data.error || 'Failed to load');

      state.counts = data.counts || {};
      updateBadges();

      container.innerHTML = renderSubmissionsView(data);
      wireSubmissionsControls();
    } catch (err) {
      container.innerHTML = '<div class="forms-error">Failed to load submissions: ' + escapeHtml(err.message) + '</div>';
    }
  }

  function renderSubmissionsView(data) {
    var c = state.counts || {};
    var categories = [
      { id: 'all',     label: 'All',           badge: c.new_total },
      { id: 'sample',  label: 'Sample Orders', badge: c.new_sample },
      { id: 'contact', label: 'Contact',       badge: c.new_contact },
      { id: 'partner', label: 'Partner',       badge: c.new_partner }
    ];

    var filterButtons = categories.map(function (cat) {
      var badge = cat.badge && parseInt(cat.badge) > 0
        ? '<span class="badge">' + cat.badge + '</span>' : '';
      return '<button class="sub-filter-btn ' + (state.category === cat.id ? 'active' : '') +
             '" data-cat="' + cat.id + '">' + cat.label + badge + '</button>';
    }).join('');

    var controls =
      '<div class="sub-controls">' +
        '<div class="ctrl"><label>Search</label><input type="search" id="sub-q" placeholder="Name, email, phone, message…" value="' + escapeAttr(state.q) + '"></div>' +
        '<div class="ctrl"><label>Status</label>' +
          '<select id="sub-status">' +
            '<option value="">Any</option>' +
            '<option value="new"      ' + (state.status === 'new'      ? 'selected' : '') + '>New (unactioned)</option>' +
            '<option value="actioned" ' + (state.status === 'actioned' ? 'selected' : '') + '>Actioned</option>' +
            '<option value="archived" ' + (state.status === 'archived' ? 'selected' : '') + '>Archived</option>' +
          '</select></div>' +
        '<div class="ctrl"><label>From</label><input type="date" id="sub-from" value="' + escapeAttr(state.dateFrom) + '"></div>' +
        '<div class="ctrl"><label>To</label><input type="date" id="sub-to" value="' + escapeAttr(state.dateTo) + '"></div>' +
        '<button class="ctrl-clear" id="sub-clear">Clear filters</button>' +
      '</div>';

    var toolbar =
      '<div class="sub-toolbar">' +
        '<div class="sub-filters">' + filterButtons + '</div>' +
        '<div class="sub-actions">' +
          '<button class="btn-export" id="sub-export">↓ Export All</button>' +
        '</div>' +
      '</div>';

    if (!data.submissions || !data.submissions.length) {
      return controls + toolbar +
        '<div class="sub-empty"><span class="sub-empty-icon">📭</span>No submissions match the current filters.</div>';
    }

    var rows = data.submissions.map(function (s) {
      var category = categoryFromSubmission(s);
      var typeClass = category === 'partner' ? 'partner'
                    : category === 'contact' ? 'contact'
                    : '';
      var typeLabel = category === 'partner' ? 'Partner'
                    : category === 'contact' ? 'Contact'
                    : 'Sample';
      var samplesHtml = s.sample_count > 0
        ? ' <span class="sub-samples" title="' + escapeAttr(s.samples) + '">— ' + escapeHtml(s.samples) + '</span>'
        : '';
      var location = s.store_location || s.state || '—';
      var phone = s.phone
        ? '<a href="tel:' + escapeAttr(s.phone) + '" onclick="event.stopPropagation()">' + escapeHtml(s.phone) + '</a>'
        : '—';
      var email = s.email
        ? '<a href="mailto:' + escapeAttr(s.email) + '" onclick="event.stopPropagation()">' + escapeHtml(s.email) + '</a>'
        : '—';
      var actionBtn = s.status === 'new'
        ? '<button class="btn-action" data-mark="' + s.id + '">Mark actioned</button>'
        : '';
      return '<tr class="sub-row ' + (s.status === 'new' ? 'sub-row-new' : '') + '" data-id="' + s.id + '">' +
        '<td class="sub-check"><input type="checkbox" class="submission-checkbox" value="' + s.id + '"></td>' +
        '<td class="sub-id">#' + s.id + '</td>' +
        '<td><span class="sub-type-badge ' + typeClass + '">' + typeLabel + '</span>' + samplesHtml + '</td>' +
        '<td>' + escapeHtml(s.name || '—') + '</td>' +
        '<td>' + email + '</td>' +
        '<td>' + phone + '</td>' +
        '<td>' + escapeHtml(location) + '</td>' +
        '<td>' + formatDateTime(s.submitted_at) + '</td>' +
        '<td><span class="sub-status sub-status-' + s.status + '">' + s.status + '</span></td>' +
        '<td>' + actionBtn + '</td>' +
      '</tr>';
    }).join('');

    var table =
      '<div class="sub-table-wrap"><table class="sub-table">' +
        '<thead><tr>' +
          '<th class="sub-check"><input type="checkbox" id="sub-select-all"></th>' +
          '<th>#</th><th>Type</th><th>Name</th><th>Email</th><th>Phone</th>' +
          '<th>Location</th><th>Submitted</th><th>Status</th><th></th>' +
        '</tr></thead>' +
        '<tbody>' + rows + '</tbody>' +
      '</table></div>';

    var pagination = renderPagination(state.offset, data.total);

    return controls + toolbar + table + pagination;
  }

  function categoryFromSubmission(s) {
    if (s.form_type === 'Sample Request') return 'sample';
    if (s.form_type === 'Contact Enquiry') {
      return (s.store_location && s.store_location.length) ? 'partner' : 'contact';
    }
    return 'other';
  }

  function wireSubmissionsControls() {
    document.querySelectorAll('#forms-tab-submissions .sub-filter-btn').forEach(function (btn) {
      btn.onclick = function () {
        state.category = btn.dataset.cat;
        state.offset = 0;
        loadSubmissions();
      };
    });

    var qEl = document.getElementById('sub-q');
    if (qEl) {
      qEl.oninput = function () {
        clearTimeout(searchDebounce);
        searchDebounce = setTimeout(function () {
          state.q = qEl.value.trim();
          state.offset = 0;
          loadSubmissions();
        }, 250);
      };
    }
    var statusEl = document.getElementById('sub-status');
    if (statusEl) statusEl.onchange = function () { state.status = statusEl.value; state.offset = 0; loadSubmissions(); };

    var fromEl = document.getElementById('sub-from');
    if (fromEl) fromEl.onchange = function () { state.dateFrom = fromEl.value; state.offset = 0; loadSubmissions(); };

    var toEl = document.getElementById('sub-to');
    if (toEl) toEl.onchange = function () { state.dateTo = toEl.value; state.offset = 0; loadSubmissions(); };

    var clearEl = document.getElementById('sub-clear');
    if (clearEl) clearEl.onclick = function () {
      state.q = ''; state.status = ''; state.dateFrom = ''; state.dateTo = '';
      state.offset = 0;
      loadSubmissions();
    };

    var exportEl = document.getElementById('sub-export');
    if (exportEl) exportEl.onclick = exportSubmissions;

    var selectAll = document.getElementById('sub-select-all');
    if (selectAll) selectAll.onchange = function () {
      document.querySelectorAll('.submission-checkbox').forEach(function (cb) {
        cb.checked = selectAll.checked;
      });
      updateExportButton();
    };
    document.querySelectorAll('.submission-checkbox').forEach(function (cb) {
      cb.onchange = updateExportButton;
      // Don't open the drawer when toggling the row's checkbox
      cb.onclick = function (e) { e.stopPropagation(); };
    });

    document.querySelectorAll('#forms-tab-submissions .sub-row').forEach(function (row) {
      row.onclick = function (e) {
        // ignore clicks on action buttons / phone / email links / checkboxes
        if (e.target.closest('.btn-action') || e.target.closest('a') || e.target.closest('.sub-check')) return;
        openDrawer(parseInt(row.dataset.id));
      };
    });
    document.querySelectorAll('#forms-tab-submissions [data-mark]').forEach(function (btn) {
      btn.onclick = function (e) {
        e.stopPropagation();
        markActioned(parseInt(btn.dataset.mark), btn);
      };
    });
    document.querySelectorAll('#forms-tab-submissions .sub-pagination button[data-offset]').forEach(function (btn) {
      btn.onclick = function () {
        state.offset = parseInt(btn.dataset.offset);
        loadSubmissions();
        scrollPanelTop();
      };
    });
  }

  function updateExportButton() {
    var checked = document.querySelectorAll('.submission-checkbox:checked');
    var btn = document.getElementById('sub-export');
    if (!btn) return;
    if (checked.length > 0) {
      btn.textContent = '↓ Export Selected (' + checked.length + ')';
      btn.classList.add('has-selection');
    } else {
      btn.textContent = '↓ Export All';
      btn.classList.remove('has-selection');
    }
    // Keep the master checkbox in sync with the row state
    var all = document.querySelectorAll('.submission-checkbox');
    var selectAll = document.getElementById('sub-select-all');
    if (selectAll) selectAll.checked = all.length > 0 && checked.length === all.length;
  }

  function exportSubmissions() {
    var checked = document.querySelectorAll('.submission-checkbox:checked');
    var url = '/api/admin/submissions/export';
    if (checked.length > 0) {
      var ids = Array.from(checked).map(function (cb) { return cb.value; });
      url += '?ids=' + ids.join(',');
    }
    window.location.href = url;
  }

  // ─── Detail drawer ───────────────────────────────────────────────────────
  function ensureDrawer() {
    var d = document.getElementById('sub-drawer');
    if (d) return d;
    var overlay = document.createElement('div');
    overlay.id = 'sub-drawer-overlay';
    overlay.className = 'sub-drawer-overlay';
    overlay.onclick = closeDrawer;
    document.body.appendChild(overlay);

    var drawer = document.createElement('aside');
    drawer.id = 'sub-drawer';
    drawer.className = 'sub-drawer';
    document.body.appendChild(drawer);
    return drawer;
  }

  async function openDrawer(id) {
    var drawer = ensureDrawer();
    var overlay = document.getElementById('sub-drawer-overlay');
    drawer.innerHTML = '<div class="forms-loading">Loading…</div>';
    drawer.classList.add('open');
    overlay.classList.add('open');
    document.querySelectorAll('.sub-row').forEach(function (r) { r.classList.remove('sub-row-active'); });
    var rowEl = document.querySelector('.sub-row[data-id="' + id + '"]');
    if (rowEl) rowEl.classList.add('sub-row-active');

    try {
      var res = await fetch('/api/admin/submissions/' + id, { credentials: 'include' });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      var data = await res.json();
      if (!data.ok) throw new Error(data.error || 'Failed');
      drawer.innerHTML = renderDrawer(data.submission, data.sampleItems);
      wireDrawer(data.submission);
    } catch (err) {
      drawer.innerHTML = '<div class="forms-error">Failed to load: ' + escapeHtml(err.message) + '</div>' +
        '<div class="sub-drawer-footer"><button id="sub-drawer-close-2">Close</button></div>';
      document.getElementById('sub-drawer-close-2').onclick = closeDrawer;
    }
  }

  function closeDrawer() {
    var drawer = document.getElementById('sub-drawer');
    var overlay = document.getElementById('sub-drawer-overlay');
    if (drawer) drawer.classList.remove('open');
    if (overlay) overlay.classList.remove('open');
    document.querySelectorAll('.sub-row').forEach(function (r) { r.classList.remove('sub-row-active'); });
  }

  function renderDrawer(s, items) {
    var category = categoryFromSubmission(s);
    var typeLabel = category === 'partner' ? 'Partner Enquiry'
                  : category === 'contact' ? 'Contact Enquiry'
                  : category === 'sample'  ? 'Sample Request'
                  : s.form_type;

    var fields = [
      ['Type',           '<span class="sub-type-badge ' + (category === 'partner' ? 'partner' : category === 'contact' ? 'contact' : '') + '">' + escapeHtml(typeLabel) + '</span>'],
      ['Submitted',      formatDateTime(s.submitted_at, true)],
      ['Status',         '<span class="sub-status sub-status-' + s.status + '">' + s.status + '</span>'],
      ['Name',           s.name || ''],
      ['Email',          s.email ? '<a href="mailto:' + escapeAttr(s.email) + '">' + escapeHtml(s.email) + '</a>' : ''],
      ['Phone',          s.phone ? '<a href="tel:' + escapeAttr(s.phone) + '">' + escapeHtml(s.phone) + '</a>' : ''],
      ['Company',        s.company || ''],
      ['Postcode',       s.postcode || ''],
      ['State',          s.state || ''],
      ['Store location', s.store_location || ''],
      ['Source',         s.source || ''],
      ['Consent',        s.consent ? '✓ Marketing emails' : '— No marketing consent'],
      ['Message',        s.message ? escapeHtml(s.message).replace(/\n/g, '<br>') : '']
    ];

    var fieldRows = fields.map(function (f) {
      var val = f[1];
      if (val === '' || val == null) {
        val = '<span class="muted">—</span>';
      } else if (typeof val === 'string' && val.indexOf('<') !== 0) {
        // not pre-escaped — escape it
        val = escapeHtml(val);
      }
      return '<div class="field-row"><div class="lbl">' + escapeHtml(f[0]) + '</div><div class="val">' + val + '</div></div>';
    }).join('');

    var stonesSection = '';
    if (items && items.length) {
      stonesSection =
        '<div class="sub-drawer-section">' +
          '<h4>Stones requested (' + items.length + ')</h4>' +
          '<ul class="sub-stones">' +
            items.map(function (it) {
              return '<li><span>' + escapeHtml(it.stone_name) + ' <span style="color:var(--text2);font-size:.7rem">(' + escapeHtml(it.stone_slug) + ')</span></span>' +
                     '<span class="collection">' + escapeHtml(it.collection || '—') + '</span></li>';
            }).join('') +
          '</ul>' +
        '</div>';
    }

    var statusActions =
      s.status === 'new'
        ? '<button class="primary" id="drw-action">Mark actioned</button>'
        : '<button id="drw-reopen">Reopen (mark new)</button>';

    return '' +
      '<div class="sub-drawer-header">' +
        '<div><h3>' + escapeHtml(typeLabel) + ' #' + s.id + '</h3>' +
          '<div class="meta">' + formatDateTime(s.submitted_at, true) + '</div></div>' +
        '<button class="sub-drawer-close" id="drw-close">✕</button>' +
      '</div>' +
      '<div class="sub-drawer-body">' +
        fieldRows +
        stonesSection +
      '</div>' +
      '<div class="sub-drawer-footer">' +
        statusActions +
        (s.status !== 'archived' ? '<button class="danger" id="drw-archive">Archive</button>' : '') +
        (s.email ? '<button id="drw-copy-email">Copy email</button>' : '') +
      '</div>';
  }

  function wireDrawer(s) {
    document.getElementById('drw-close').onclick = closeDrawer;

    var actBtn = document.getElementById('drw-action');
    if (actBtn) actBtn.onclick = function () { setSubmissionStatus(s.id, 'actioned'); };

    var reopenBtn = document.getElementById('drw-reopen');
    if (reopenBtn) reopenBtn.onclick = function () { setSubmissionStatus(s.id, 'new'); };

    var archBtn = document.getElementById('drw-archive');
    if (archBtn) archBtn.onclick = function () { setSubmissionStatus(s.id, 'archived'); };

    var copyBtn = document.getElementById('drw-copy-email');
    if (copyBtn) copyBtn.onclick = function () {
      navigator.clipboard.writeText(s.email).then(
        function () { showToast('Email copied: ' + s.email, 'success'); },
        function () { showToast('Copy failed', 'error'); }
      );
    };
  }

  async function setSubmissionStatus(id, status) {
    try {
      var res = await fetch('/api/admin/submissions/' + id, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ status: status })
      });
      var data = await res.json();
      if (!data.ok) throw new Error(data.error || 'Failed');
      showToast('Marked as ' + status, 'success');
      closeDrawer();
      loadSubmissions();
    } catch (err) {
      showToast('Error: ' + err.message, 'error');
    }
  }

  async function markActioned(id, btn) {
    btn.disabled = true; btn.textContent = '…';
    try {
      var res = await fetch('/api/admin/submissions/' + id, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ status: 'actioned' })
      });
      var data = await res.json();
      if (!data.ok) throw new Error(data.error || 'Failed');
      var row = btn.closest('.sub-row');
      row.classList.remove('sub-row-new');
      var statusEl = row.querySelector('.sub-status');
      statusEl.textContent = 'actioned';
      statusEl.className = 'sub-status sub-status-actioned';
      btn.parentElement.innerHTML = '';
      showToast('Marked as actioned', 'success');
      // Refresh badges (don't refetch full list — keeps user's place)
      refreshCounts();
    } catch (err) {
      btn.disabled = false; btn.textContent = 'Mark actioned';
      showToast('Error: ' + err.message, 'error');
    }
  }

  async function refreshCounts() {
    try {
      var res = await fetch('/api/admin/submissions?limit=1', { credentials: 'include' });
      var data = await res.json();
      if (data.ok) { state.counts = data.counts || {}; updateBadges(); }
    } catch (e) { /* non-fatal */ }
  }

  function updateBadges() {
    var c = state.counts || {};
    var subBadge = document.getElementById('badge-submissions');
    if (subBadge) {
      var total = parseInt(c.new_total) || 0;
      subBadge.textContent = total > 0 ? total : '';
      subBadge.style.display = total > 0 ? 'inline-block' : 'none';
    }
    // Re-render category badges
    var sn = parseInt(c.new_sample) || 0,
        cn = parseInt(c.new_contact) || 0,
        pn = parseInt(c.new_partner) || 0;
    setCatBadge('all',     sn + cn + pn);
    setCatBadge('sample',  sn);
    setCatBadge('contact', cn);
    setCatBadge('partner', pn);
  }

  function setCatBadge(cat, n) {
    var btn = document.querySelector('#forms-tab-submissions .sub-filter-btn[data-cat="' + cat + '"]');
    if (!btn) return;
    var existing = btn.querySelector('.badge');
    if (n > 0) {
      if (existing) existing.textContent = n;
      else btn.insertAdjacentHTML('beforeend', '<span class="badge">' + n + '</span>');
    } else if (existing) {
      existing.remove();
    }
  }

  // ─── Newsletter tab ──────────────────────────────────────────────────────
  async function loadNewsletter() {
    var container = document.getElementById('forms-tab-newsletter');
    container.innerHTML = '<div class="forms-loading">Loading subscribers…</div>';

    try {
      var params = new URLSearchParams({ limit: PAGE_SIZE, offset: state.offset });
      if (state.status)   params.set('status',    state.status);
      if (state.q)        params.set('q',         state.q);
      if (state.dateFrom) params.set('date_from', state.dateFrom);
      if (state.dateTo)   params.set('date_to',   state.dateTo);

      var res = await fetch('/api/admin/newsletter?' + params, { credentials: 'include' });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      var data = await res.json();
      if (!data.ok) throw new Error(data.error || 'Failed');

      state.newsletterCounts = data.counts || {};
      updateNewsletterBadge();

      container.innerHTML = renderNewsletterView(data);
      wireNewsletterControls();
    } catch (err) {
      container.innerHTML = '<div class="forms-error">Failed to load subscribers: ' + escapeHtml(err.message) + '</div>';
    }
  }

  function renderNewsletterView(data) {
    var c = state.newsletterCounts || {};
    var statusFilters = [
      { id: '',             label: 'All' },
      { id: 'active',       label: 'Active',       badge: c.active },
      { id: 'unsubscribed', label: 'Unsubscribed', badge: c.unsubscribed },
      { id: 'pending',      label: 'Pending',      badge: c.pending }
    ];

    var filterButtons = statusFilters.map(function (f) {
      var badge = f.badge && parseInt(f.badge) > 0 ? '<span class="badge">' + f.badge + '</span>' : '';
      return '<button class="sub-filter-btn ' + (state.status === f.id ? 'active' : '') +
             '" data-status="' + f.id + '">' + f.label + badge + '</button>';
    }).join('');

    var controls =
      '<div class="sub-controls">' +
        '<div class="ctrl"><label>Search email</label><input type="search" id="nl-q" placeholder="email@…" value="' + escapeAttr(state.q) + '"></div>' +
        '<div class="ctrl"><label>From</label><input type="date" id="nl-from" value="' + escapeAttr(state.dateFrom) + '"></div>' +
        '<div class="ctrl"><label>To</label><input type="date" id="nl-to" value="' + escapeAttr(state.dateTo) + '"></div>' +
        '<button class="ctrl-clear" id="nl-clear">Clear filters</button>' +
      '</div>';

    var toolbar =
      '<div class="sub-toolbar">' +
        '<div class="sub-filters">' + filterButtons + '</div>' +
        '<div class="sub-actions">' +
          '<button class="btn-export" id="nl-export">↓ Export filtered (CSV)</button>' +
          '<button class="btn-export-secondary" id="nl-export-all">↓ All</button>' +
        '</div>' +
      '</div>';

    if (!data.subscribers || !data.subscribers.length) {
      return controls + toolbar +
        '<div class="sub-empty"><span class="sub-empty-icon">📭</span>No subscribers match the current filters.</div>';
    }

    var rows = data.subscribers.map(function (sub) {
      var actionBtn = sub.status === 'active'
        ? '<button class="btn-action" data-unsub="' + sub.id + '">Unsubscribe</button>'
        : '';
      var src = sub.source_url
        ? '<span class="sub-samples" title="' + escapeAttr(sub.source_url) + '">' + escapeHtml(shortenUrl(sub.source_url)) + '</span>'
        : '—';
      return '<tr class="sub-row" data-id="' + sub.id + '">' +
        '<td class="sub-id">#' + sub.id + '</td>' +
        '<td><a href="mailto:' + escapeAttr(sub.email) + '" onclick="event.stopPropagation()">' + escapeHtml(sub.email) + '</a></td>' +
        '<td>' + formatDateTime(sub.consent_timestamp_utc) + '</td>' +
        '<td>' + src + '</td>' +
        '<td><span class="sub-status sub-status-' + sub.status + '">' + sub.status + '</span></td>' +
        '<td>' + actionBtn + '</td>' +
      '</tr>';
    }).join('');

    var table =
      '<div class="sub-table-wrap"><table class="sub-table">' +
        '<thead><tr>' +
          '<th>#</th><th>Email</th><th>Subscribed</th><th>Source page</th><th>Status</th><th></th>' +
        '</tr></thead>' +
        '<tbody>' + rows + '</tbody>' +
      '</table></div>';

    return controls + toolbar + table + renderPagination(state.offset, data.total);
  }

  function wireNewsletterControls() {
    document.querySelectorAll('#forms-tab-newsletter .sub-filter-btn').forEach(function (btn) {
      btn.onclick = function () {
        state.status = btn.dataset.status;
        state.offset = 0;
        loadNewsletter();
      };
    });

    var qEl = document.getElementById('nl-q');
    if (qEl) qEl.oninput = function () {
      clearTimeout(searchDebounce);
      searchDebounce = setTimeout(function () {
        state.q = qEl.value.trim();
        state.offset = 0;
        loadNewsletter();
      }, 250);
    };
    var fromEl = document.getElementById('nl-from');
    if (fromEl) fromEl.onchange = function () { state.dateFrom = fromEl.value; state.offset = 0; loadNewsletter(); };
    var toEl = document.getElementById('nl-to');
    if (toEl) toEl.onchange = function () { state.dateTo = toEl.value; state.offset = 0; loadNewsletter(); };
    var clearEl = document.getElementById('nl-clear');
    if (clearEl) clearEl.onclick = function () {
      state.q = ''; state.status = ''; state.dateFrom = ''; state.dateTo = '';
      state.offset = 0;
      loadNewsletter();
    };

    var exportEl = document.getElementById('nl-export');
    if (exportEl) exportEl.onclick = function () { exportNewsletter(false); };
    var exportAllEl = document.getElementById('nl-export-all');
    if (exportAllEl) exportAllEl.onclick = function () { exportNewsletter(true); };

    document.querySelectorAll('#forms-tab-newsletter [data-unsub]').forEach(function (btn) {
      btn.onclick = function (e) {
        e.stopPropagation();
        unsubscribe(parseInt(btn.dataset.unsub), btn);
      };
    });
    document.querySelectorAll('#forms-tab-newsletter .sub-pagination button[data-offset]').forEach(function (btn) {
      btn.onclick = function () {
        state.offset = parseInt(btn.dataset.offset);
        loadNewsletter();
        scrollPanelTop();
      };
    });
  }

  function exportNewsletter(unfiltered) {
    var params = new URLSearchParams();
    if (!unfiltered) {
      if (state.status)   params.set('status',    state.status);
      if (state.q)        params.set('q',         state.q);
      if (state.dateFrom) params.set('date_from', state.dateFrom);
      if (state.dateTo)   params.set('date_to',   state.dateTo);
    }
    var qs = params.toString();
    window.location.href = '/api/admin/newsletter/export' + (qs ? '?' + qs : '');
  }

  async function unsubscribe(id, btn) {
    if (!confirm('Unsubscribe this email? They will be moved to suppression.')) return;
    btn.disabled = true; btn.textContent = '…';
    try {
      var res = await fetch('/api/admin/newsletter/' + id, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ status: 'unsubscribed' })
      });
      var data = await res.json();
      if (!data.ok) throw new Error(data.error || 'Failed');
      showToast('Unsubscribed', 'success');
      loadNewsletter();
    } catch (err) {
      btn.disabled = false; btn.textContent = 'Unsubscribe';
      showToast('Error: ' + err.message, 'error');
    }
  }

  function updateNewsletterBadge() {
    var c = state.newsletterCounts || {};
    var badge = document.getElementById('badge-newsletter');
    if (!badge) return;
    var n = parseInt(c.active) || 0;
    badge.textContent = n > 0 ? n : '';
    badge.style.display = n > 0 ? 'inline-block' : 'none';
  }

  // ─── Schemas tab (kept from previous version) ────────────────────────────
  async function loadSchemas() {
    var container = document.getElementById('forms-tab-schemas');
    container.innerHTML = '<div class="forms-loading">Loading schemas…</div>';
    try {
      var res = await fetch('/api/admin/forms', { credentials: 'include' });
      var data = await res.json();
      container.innerHTML =
        '<p class="schema-intro">Edit labels, placeholders and required status for each form. Field names and types cannot be changed here — contact your developer to add or remove fields.</p>' +
        '<div class="schema-list">' +
        data.forms.map(function (form) {
          return '<div class="schema-card" id="schema-' + form.id + '">' +
            '<div class="schema-card-header"><div><h3>' + escapeHtml(form.label) + '</h3>' +
              '<span class="schema-meta">' + escapeHtml(form.endpoint) + ' · ' + form.fields.length + ' fields</span></div>' +
              '<button class="btn-save-schema" data-form="' + form.id + '">Save</button></div>' +
            '<p class="schema-page">' + escapeHtml(form.page) + '</p>' +
            '<table class="schema-fields-table"><thead><tr><th>Field</th><th>Type</th><th>Label</th><th>Placeholder</th><th>Required</th></tr></thead><tbody>' +
            form.fields.map(function (f, i) {
              return '<tr>' +
                '<td class="field-name">' + escapeHtml(f.name) + '</td>' +
                '<td class="field-type">' + escapeHtml(f.type) + '</td>' +
                '<td><input type="text" data-form="' + form.id + '" data-index="' + i + '" data-key="label" value="' + escapeAttr(f.label || '') + '" class="schema-input"></td>' +
                '<td><input type="text" data-form="' + form.id + '" data-index="' + i + '" data-key="placeholder" value="' + escapeAttr(f.placeholder || '') + '" class="schema-input"></td>' +
                '<td style="text-align:center"><input type="checkbox" data-form="' + form.id + '" data-index="' + i + '" data-key="required" ' + (f.required ? 'checked' : '') + ' class="schema-checkbox"></td>' +
              '</tr>';
            }).join('') +
            '</tbody></table></div>';
        }).join('') +
        '</div>';

      document.querySelectorAll('#forms-tab-schemas .btn-save-schema').forEach(function (btn) {
        btn.onclick = function () { saveSchema(btn.dataset.form); };
      });
    } catch (err) {
      container.innerHTML = '<div class="forms-error">Failed to load schemas: ' + escapeHtml(err.message) + '</div>';
    }
  }

  async function saveSchema(formId) {
    var card = document.getElementById('schema-' + formId);
    var btn = card.querySelector('.btn-save-schema');
    btn.disabled = true; btn.textContent = 'Saving…';
    try {
      var res = await fetch('/api/admin/forms', { credentials: 'include' });
      var data = await res.json();
      var form = data.forms.find(function (f) { return f.id === formId; });
      if (!form) throw new Error('Form not found');
      card.querySelectorAll('[data-form]').forEach(function (el) {
        if (el === btn) return;
        var i = parseInt(el.dataset.index);
        var key = el.dataset.key;
        if (Number.isNaN(i) || !key) return;
        form.fields[i][key] = el.type === 'checkbox' ? el.checked : el.value;
      });
      var saveRes = await fetch('/api/admin/forms/' + formId, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        credentials: 'include', body: JSON.stringify(form)
      });
      var saveData = await saveRes.json();
      if (!saveData.ok) throw new Error(saveData.error || 'Save failed');
      showToast('✓ ' + form.label + ' saved', 'success');
    } catch (err) {
      showToast('Error: ' + err.message, 'error');
    } finally {
      btn.disabled = false; btn.textContent = 'Save';
    }
  }

  // ─── Helpers ─────────────────────────────────────────────────────────────
  function renderPagination(offset, total) {
    var from = total > 0 ? offset + 1 : 0;
    var to   = Math.min(offset + PAGE_SIZE, total);
    return '<div class="sub-pagination">' +
      '<span>' + from + '–' + to + ' of ' + total + '</span>' +
      '<div class="pages">' +
        '<button data-offset="' + Math.max(0, offset - PAGE_SIZE) + '" ' + (offset > 0 ? '' : 'disabled') + '>← Prev</button>' +
        '<button data-offset="' + (offset + PAGE_SIZE) + '" ' + (offset + PAGE_SIZE < total ? '' : 'disabled') + '>Next →</button>' +
      '</div>' +
    '</div>';
  }

  function showToast(msg, type) {
    var toast = document.getElementById('forms-toast');
    if (!toast) return;
    toast.textContent = msg;
    toast.className = 'forms-toast ' + (type || 'success');
    setTimeout(function () { toast.className = 'forms-toast hidden'; }, 4000);
  }

  function scrollPanelTop() {
    var main = document.querySelector('.main');
    if (main) main.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function formatDateTime(iso, withTime) {
    if (!iso) return '—';
    try {
      var d = new Date(iso);
      var date = d.toLocaleDateString('en-AU', { day: '2-digit', month: 'short', year: 'numeric' });
      if (!withTime) return date;
      var time = d.toLocaleTimeString('en-AU', { hour: '2-digit', minute: '2-digit', hour12: false });
      return date + ' · ' + time;
    } catch (e) { return iso; }
  }

  function shortenUrl(url) {
    try {
      var u = new URL(url);
      return u.pathname === '/' ? u.host : u.host + u.pathname;
    } catch (e) { return url; }
  }

  function escapeHtml(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function escapeAttr(s) {
    return escapeHtml(s);
  }

  // ─── Init ────────────────────────────────────────────────────────────────
  // Re-render whenever the user switches into the Forms panel — keeps badges
  // and counts fresh when they come back from another panel.
  if (typeof window.showPanel === 'function') {
    var orig = window.showPanel;
    window.showPanel = function (id, el) {
      orig(id, el);
      if (id === 'forms') renderFormsPanel();
    };
  }
  window.addEventListener('DOMContentLoaded', function () {
    // Initial render (panel may be hidden but DOM is ready)
    renderFormsPanel();
    // Background fetch of headline counts so the sidebar badge has data.
    refreshCounts();
  });

  // Expose for debugging / inline handlers in admin.html
  window.renderFormsPanel = renderFormsPanel;
})();
