(function () {
  'use strict';

  var state = {
    tab: 'products',
    data: null,
    docs: [],
    activeSlug: null
  };

  function esc(v) {
    return String(v == null ? '' : v)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function collectionOptions(selected) {
    if (!state.data) return '';
    return state.data.collections.map(function (c) {
      return '<option value="' + esc(c.id) + '" ' + (c.id === selected ? 'selected' : '') + '>' + esc(c.name) + '</option>';
    }).join('');
  }

  function allStones() {
    if (!state.data) return [];
    return state.data.collections.flatMap(function (c) {
      return (c.stones || []).map(function (s) {
        s.collection_id = c.id;
        s.collection_name = c.name;
        return s;
      });
    });
  }

  async function loadCmsData() {
    var wrap = document.getElementById('managed-cms-panel');
    if (!wrap) return;
    wrap.innerHTML = '<div class="forms-loading">Loading managed content...</div>';
    try {
      var stonesRes = await fetch('/api/admin/cms/stones', { credentials: 'include' });
      state.data = await stonesRes.json();
      var docsRes = await fetch('/api/admin/cms/documents', { credentials: 'include' });
      var docsData = await docsRes.json();
      state.docs = docsData.documents || [];
      if (!state.activeSlug && allStones()[0]) state.activeSlug = allStones()[0].slug;
      renderManagedCms();
    } catch (err) {
      wrap.innerHTML = '<div class="forms-error">Failed to load managed CMS: ' + esc(err.message) + '</div>';
    }
  }

  function renderManagedCms() {
    var wrap = document.getElementById('managed-cms-panel');
    if (!wrap) return;
    wrap.innerHTML =
      '<div class="forms-header">' +
        '<h2>Managed Website Content</h2>' +
        '<div class="forms-header-actions">' +
          '<button class="btn-tab-switch ' + (state.tab === 'products' ? 'active' : '') + '" data-cms-tab="products">Products</button>' +
          '<button class="btn-tab-switch ' + (state.tab === 'documents' ? 'active' : '') + '" data-cms-tab="documents">Documents</button>' +
          '<button class="btn-tab-switch ' + (state.tab === 'collections' ? 'active' : '') + '" data-cms-tab="collections">Collections</button>' +
        '</div>' +
      '</div>' +
      '<p class="keys-panel-desc">These fields feed the new managed content APIs. Products and documents are the first client self-service layer; static pages can be migrated onto these APIs incrementally.</p>' +
      '<div id="managed-cms-body"></div>' +
      '<div id="managed-cms-toast" class="forms-toast hidden"></div>';

    wrap.querySelectorAll('[data-cms-tab]').forEach(function (btn) {
      btn.onclick = function () {
        state.tab = btn.dataset.cmsTab;
        renderManagedCms();
      };
    });

    if (state.tab === 'documents') renderDocuments();
    else if (state.tab === 'collections') renderCollections();
    else renderProducts();
  }

  function renderProducts() {
    var body = document.getElementById('managed-cms-body');
    var stones = allStones();
    var active = stones.find(function (s) { return s.slug === state.activeSlug; }) || stones[0];
    if (!active) {
      body.innerHTML = '<div class="sub-empty">No products found.</div>';
      return;
    }
    state.activeSlug = active.slug;

    var list = stones.map(function (s) {
      var flags = [];
      if (s.discontinued) flags.push('discontinued');
      if (s.images_pending || !s.image) flags.push('image needed');
      return '<button class="sub-filter-btn ' + (s.slug === active.slug ? 'active' : '') +
        '" data-stone="' + esc(s.slug) + '">' + esc(s.name) +
        (flags.length ? ' <span class="badge">' + esc(flags.join(', ')) + '</span>' : '') +
        '</button>';
    }).join('');

    body.innerHTML =
      '<div class="sub-toolbar"><div class="sub-filters" style="max-height:220px;overflow:auto">' + list + '</div>' +
      '<button class="btn-export" id="cms-new-product">+ Add Product</button></div>' +
      '<form id="cms-product-form" class="card">' +
        '<div class="field-row">' +
          '<div class="field"><label>Name</label><input name="name" value="' + esc(active.name) + '"></div>' +
          '<div class="field"><label>Slug</label><input name="slug" value="' + esc(active.slug) + '" disabled></div>' +
        '</div>' +
        '<div class="field-row">' +
          '<div class="field"><label>Collection</label><select name="collection_id">' + collectionOptions(active.collection_id) + '</select></div>' +
          '<div class="field"><label>Finish</label><input name="finish" value="' + esc(active.finish) + '"></div>' +
        '</div>' +
        '<div class="field"><label>Description</label><textarea name="description" rows="3">' + esc(active.description) + '</textarea></div>' +
        '<div class="field-row">' +
          '<div class="field"><label>Swatch / Main Image URL</label><input name="image_url" value="' + esc(active.image) + '"></div>' +
          '<div class="field"><label>Full Slab URL</label><input name="slab_url" value="' + esc(active.slab) + '"></div>' +
        '</div>' +
        '<div class="field-row">' +
          '<div class="field"><label>Thumbnail URL</label><input name="thumbnail_url" value="' + esc(active.thumbnail) + '"></div>' +
          '<div class="field"><label>Swatch URL</label><input name="swatch_url" value="' + esc(active.swatch) + '"></div>' +
        '</div>' +
        '<div class="field-row-3">' +
          '<label class="toggle-row"><span>Visible</span><input type="checkbox" name="visible" ' + (active.visible !== false ? 'checked' : '') + '></label>' +
          '<label class="toggle-row"><span>Discontinued</span><input type="checkbox" name="discontinued" ' + (active.discontinued ? 'checked' : '') + '></label>' +
          '<label class="toggle-row"><span>Images Pending</span><input type="checkbox" name="images_pending" ' + (active.images_pending ? 'checked' : '') + '></label>' +
        '</div>' +
        '<button class="btn btn-save" type="submit">Save Product</button>' +
      '</form>';

    body.querySelectorAll('[data-stone]').forEach(function (btn) {
      btn.onclick = function () {
        state.activeSlug = btn.dataset.stone;
        renderProducts();
      };
    });
    document.getElementById('cms-new-product').onclick = addProduct;
    document.getElementById('cms-product-form').onsubmit = saveProduct;
  }

  async function saveProduct(e) {
    e.preventDefault();
    var form = e.currentTarget;
    var fd = new FormData(form);
    var payload = {};
    fd.forEach(function (v, k) { payload[k] = v; });
    payload.visible = form.elements.visible.checked;
    payload.discontinued = form.elements.discontinued.checked;
    payload.images_pending = form.elements.images_pending.checked;
    payload.name = payload.name.trim();

    var res = await fetch('/api/admin/cms/stones/' + encodeURIComponent(state.activeSlug), {
      method: 'PUT',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) return toast('Product save failed.', 'error');
    toast('Product saved.', 'success');
    await loadCmsData();
  }

  async function addProduct() {
    var name = prompt('Product name');
    if (!name) return;
    var firstCollection = state.data.collections[0] && state.data.collections[0].id;
    var res = await fetch('/api/admin/cms/stones', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: name, collection_id: firstCollection, images_pending: true })
    });
    var data = await res.json();
    if (!res.ok) return toast(data.error || 'Could not add product.', 'error');
    state.activeSlug = data.stone.slug;
    await loadCmsData();
  }

  function renderCollections() {
    var body = document.getElementById('managed-cms-body');
    body.innerHTML = (state.data.collections || []).map(function (c) {
      return '<form class="card cms-collection-form" data-id="' + esc(c.id) + '">' +
        '<div class="card-header"><h3>' + esc(c.name) + '</h3><button class="btn-sm" type="submit">Save</button></div>' +
        '<div class="field-row"><div class="field"><label>Name</label><input name="name" value="' + esc(c.name) + '"></div>' +
        '<div class="field"><label>Sort Order</label><input name="sort_order" value="' + esc(c.sort_order || 0) + '"></div></div>' +
        '<div class="field"><label>Subtitle</label><textarea name="subtitle" rows="2">' + esc(c.subtitle) + '</textarea></div>' +
        '<div class="field"><label>Description</label><textarea name="description" rows="2">' + esc(c.description) + '</textarea></div>' +
        '<div class="field-row"><div class="field"><label>Hero Image URL</label><input name="hero_image_url" value="' + esc(c.hero_image) + '"></div>' +
        '<div class="field"><label>Swatch Image URL</label><input name="swatch_image_url" value="' + esc(c.swatch_image) + '"></div></div>' +
        '<label class="toggle-row"><span>Visible</span><input type="checkbox" name="visible" ' + (c.visible !== false ? 'checked' : '') + '></label>' +
      '</form>';
    }).join('');
    body.querySelectorAll('.cms-collection-form').forEach(function (form) {
      form.onsubmit = saveCollection;
    });
  }

  async function saveCollection(e) {
    e.preventDefault();
    var form = e.currentTarget;
    var fd = new FormData(form);
    var payload = {};
    fd.forEach(function (v, k) { payload[k] = v; });
    payload.visible = form.elements.visible.checked;
    var res = await fetch('/api/admin/cms/collections/' + encodeURIComponent(form.dataset.id), {
      method: 'PUT',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) return toast('Collection save failed.', 'error');
    toast('Collection saved.', 'success');
    await loadCmsData();
  }

  function renderDocuments() {
    var body = document.getElementById('managed-cms-body');
    body.innerHTML = state.docs.map(function (d) {
      return '<form class="card cms-doc-form" data-slug="' + esc(d.slug) + '">' +
        '<div class="card-header"><h3>' + esc(d.title) + '</h3><button class="btn-sm" type="submit">Save</button></div>' +
        '<div class="field-row"><div class="field"><label>Title</label><input name="title" value="' + esc(d.title) + '"></div>' +
        '<div class="field"><label>Category</label><input name="category" value="' + esc(d.category) + '"></div></div>' +
        '<div class="field"><label>Description</label><textarea name="description" rows="2">' + esc(d.description) + '</textarea></div>' +
        '<div class="field-row"><div class="field"><label>Public File URL</label><input name="file_url" value="' + esc(d.file_url) + '"></div>' +
        '<div class="field"><label>Sort Order</label><input name="sort_order" value="' + esc(d.sort_order || 0) + '"></div></div>' +
        '<label class="toggle-row"><span>Visible</span><input type="checkbox" name="visible" ' + (d.visible !== false ? 'checked' : '') + '></label>' +
        '<div class="field"><label>Replace File</label><input type="file" name="file"><button class="btn-sm" type="button" data-upload="' + esc(d.slug) + '">Upload Replacement</button></div>' +
      '</form>';
    }).join('');
    body.querySelectorAll('.cms-doc-form').forEach(function (form) {
      form.onsubmit = saveDocument;
    });
    body.querySelectorAll('[data-upload]').forEach(function (btn) {
      btn.onclick = uploadDocument;
    });
  }

  async function saveDocument(e) {
    e.preventDefault();
    var form = e.currentTarget;
    var fd = new FormData(form);
    var payload = {};
    fd.forEach(function (v, k) { if (k !== 'file') payload[k] = v; });
    payload.visible = form.elements.visible.checked;
    var res = await fetch('/api/admin/cms/documents/' + encodeURIComponent(form.dataset.slug), {
      method: 'PUT',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) return toast('Document save failed.', 'error');
    toast('Document saved.', 'success');
    await loadCmsData();
  }

  async function uploadDocument(e) {
    var slug = e.currentTarget.dataset.upload;
    var form = e.currentTarget.closest('form');
    var input = form.querySelector('input[type=file]');
    if (!input.files.length) return toast('Choose a file first.', 'warn');
    var fd = new FormData();
    fd.append('file', input.files[0]);
    var res = await fetch('/api/admin/cms/documents/' + encodeURIComponent(slug) + '/upload', {
      method: 'POST',
      credentials: 'include',
      body: fd
    });
    if (!res.ok) return toast('Upload failed.', 'error');
    toast('Replacement uploaded.', 'success');
    await loadCmsData();
  }

  function toast(msg, type) {
    var el = document.getElementById('managed-cms-toast');
    if (!el) return;
    el.textContent = msg;
    el.className = 'forms-toast ' + (type || 'success');
    setTimeout(function () { el.className = 'forms-toast hidden'; }, 3000);
  }

  window.renderManagedCmsPanel = loadCmsData;
})();
