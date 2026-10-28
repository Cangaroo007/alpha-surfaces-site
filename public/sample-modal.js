/* ═══════════════════════════════════════════════════
   ORDER A SAMPLE — Modal Popup Controller
   ═══════════════════════════════════════════════════ */
(function() {
  'use strict';

  // Create modal DOM once
  var backdrop = document.createElement('div');
  backdrop.className = 'sample-modal-backdrop';
  backdrop.id = 'sample-modal-backdrop';
  backdrop.innerHTML = '\
    <div class="sample-modal" id="sample-modal">\
      <button class="sample-modal-close" id="sample-modal-close">&times;</button>\
      <div class="sample-modal-header">\
        <h2 class="sample-modal-title">Order a sample</h2>\
        <p class="sample-modal-subtitle">We\u2019ll send you up to three samples. Please note we are unable to deliver to PO Box addresses.</p>\
      </div>\
      <div class="sample-modal-stone" id="sample-modal-stone" style="display:none;"></div>\
      <form class="sample-modal-form" action="#" method="POST">\
        <div class="smf-row">\
          <input type="text" class="smf-input" name="first_name" placeholder="First Name *" required>\
          <input type="text" class="smf-input" name="last_name" placeholder="Last Name *" required>\
        </div>\
        <input type="email" class="smf-input" name="email" placeholder="Email *" required>\
        <input type="tel" class="smf-input" name="phone" placeholder="Phone *" required>\
        <div class="smf-row">\
          <input type="text" class="smf-input" name="unit" placeholder="Unit / House No. *" required>\
          <input type="text" class="smf-input" name="street" placeholder="Street *" required>\
        </div>\
        <input type="text" class="smf-input" name="suburb" placeholder="Suburb *" required>\
        <div class="smf-row">\
          <input type="text" class="smf-input" name="postcode" placeholder="Postcode *" required>\
          <div style="flex:1;">\
            <select class="smf-select" name="state" required>\
              <option value="" disabled selected>State *</option>\
              <option value="QLD">QLD</option>\
              <option value="NSW">NSW</option>\
              <option value="VIC">VIC</option>\
              <option value="SA">SA</option>\
              <option value="WA">WA</option>\
              <option value="TAS">TAS</option>\
              <option value="NT">NT</option>\
              <option value="ACT">ACT</option>\
            </select>\
          </div>\
        </div>\
        <div>\
          <select class="smf-select" name="role" required>\
            <option value="" disabled selected>I am a... *</option>\
            <option value="Homeowner">Homeowner</option>\
            <option value="Stonemason">Stonemason</option>\
            <option value="Cabinet maker">Cabinet maker / kitchen company</option>\
            <option value="Project home builder">Project home builder</option>\
            <option value="Builder/developer">Builder / developer</option>\
            <option value="Architect">Architect</option>\
            <option value="Interior designer">Interior designer</option>\
            <option value="Tile outlet">Tile outlet / retailer</option>\
            <option value="Other">Other</option>\
          </select>\
        </div>\
        <div class="smf-sm" id="smf-sm" style="display:none">\
          <span class="smf-label">Who is making your benchtop?</span>\
          <label class="smf-radio"><input type="radio" name="stonemason_status" value="yes"> I already work with a stonemason or cabinetmaker</label>\
          <label class="smf-radio"><input type="radio" name="stonemason_status" value="no"> Not yet &mdash; please refer one who works with your stone</label>\
          <label class="smf-radio"><input type="radio" name="stonemason_status" value="unsure"> Not sure yet</label>\
          <label class="smf-radio"><input type="radio" name="stonemason_status" value="decline"> Prefer not to say</label>\
          <div id="smf-sm-lookup" style="display:none">\
            <input type="text" class="smf-input" name="stonemason_name" id="smf-sm-name" placeholder="Their business name" autocomplete="off">\
            <input type="hidden" name="stonemason_org_id" id="smf-sm-org">\
            <div id="smf-sm-results"></div>\
          </div>\
        </div>\
        <input type="hidden" name="stone_slug"       id="sample-modal-slug">\
        <input type="hidden" name="stone_name"       id="sample-modal-name">\
        <input type="hidden" name="stone_collection" id="sample-modal-collection">\
        <div class="smf-checkbox">\
          <input type="checkbox" id="sample-consent" name="consent">\
          <label for="sample-consent">I agree to receive updates from Alpha Surfaces.</label>\
        </div>\
        <div class="smf-submit-row">\
          <button type="submit" class="smf-submit">Submit</button>\
        </div>\
      </form>\
    </div>\
  ';
  document.body.appendChild(backdrop);

  var modal = document.getElementById('sample-modal');
  var closeBtn = document.getElementById('sample-modal-close');
  var stoneCard = document.getElementById('sample-modal-stone');
  var slugInput = document.getElementById('sample-modal-slug');
  var nameInput = document.getElementById('sample-modal-name');
  var collInput = document.getElementById('sample-modal-collection');

  function openModal(stoneName, stoneSlug, stoneImage, stoneCollection) {
    // Set stone info
    if (stoneName) {
      var imgHtml = stoneImage
        ? '<img src="' + stoneImage + '" alt="' + stoneName + '">'
        : '<div class="sample-modal-stone-ph"></div>';
      stoneCard.innerHTML = imgHtml +
        '<div><div class="sample-modal-stone-name">' + stoneName + '</div>' +
        '<div class="sample-modal-stone-coll">' + (stoneCollection || '') + '</div></div>';
      stoneCard.style.display = '';
      slugInput.value = stoneSlug || '';
      nameInput.value = stoneName || '';
      collInput.value = stoneCollection || '';
    } else {
      stoneCard.style.display = 'none';
      slugInput.value = '';
      nameInput.value = '';
      collInput.value = '';
    }
    backdrop.classList.add('open');
    document.body.style.overflow = 'hidden';
  }

  function closeModal() {
    backdrop.classList.remove('open');
    document.body.style.overflow = '';
  }

  // Close handlers
  closeBtn.addEventListener('click', closeModal);
  backdrop.addEventListener('click', function(e) {
    if (e.target === backdrop) closeModal();
  });
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && backdrop.classList.contains('open')) closeModal();
  });

  // Expose globally so stone cards can call it
  window.openSampleModal = openModal;

  // Auto-attach to dynamically created stone cards (MutationObserver)
  function attachSampleButtons() {
    var cards = document.querySelectorAll('.stone-card:not([data-sample-attached])');
    cards.forEach(function(card) {
      card.setAttribute('data-sample-attached', '1');

      var nameEl = card.querySelector('.stone-card-name');
      var finishEl = card.querySelector('.stone-card-finish');
      var imgEl = card.querySelector('.stone-card-image img');

      if (!nameEl) return;

      var btn = document.createElement('button');
      btn.className = 'stone-card-sample';
      btn.textContent = 'Order Sample';
      btn.addEventListener('click', function(e) {
        e.preventDefault();
        e.stopPropagation();
        var name = nameEl.textContent;
        var slug = '';
        var href = card.getAttribute('href') || '';
        var match = href.match(/\/surfaces\/([a-z0-9-]+)/);
        if (match) slug = match[1];
        var image = imgEl ? imgEl.getAttribute('src') : '';
        var coll = finishEl ? finishEl.textContent : '';
        openSampleModal(name, slug, image, coll);
      });

      var info = card.querySelector('.stone-card-info');
      if (info) info.appendChild(btn);
    });
  }

  // "Who is making your benchtop?" (ADR 0065) - the same question /order-sample asks, so
  // popup requests reach Pipedrive with the stonemason line too. Hidden for stonemasons.
  // Picking a listed company posts its Pipedrive org id (public/data/stonemasons.json).
  (function () {
    var form = backdrop.querySelector('.sample-modal-form');
    var role = form.querySelector('select[name="role"]');
    var block = document.getElementById('smf-sm');
    var lookup = document.getElementById('smf-sm-lookup');
    var name = document.getElementById('smf-sm-name');
    var org = document.getElementById('smf-sm-org');
    var results = document.getElementById('smf-sm-results');
    var list = null;
    function clearLookup() { name.value = ''; org.value = ''; results.innerHTML = ''; }
    function load() {
      if (list) return;
      list = [];
      fetch('/data/stonemasons.json')
        .then(function (r) { return r.json(); })
        .then(function (d) { list = Array.isArray(d) ? d : []; })
        .catch(function () { list = []; });
    }
    role.addEventListener('change', function () {
      var show = role.value && role.value !== 'Stonemason';
      block.style.display = show ? '' : 'none';
      if (!show) {
        var picked = form.querySelector('input[name="stonemason_status"]:checked');
        if (picked) picked.checked = false;
        lookup.style.display = 'none';
        clearLookup();
      }
    });
    Array.prototype.forEach.call(form.querySelectorAll('input[name="stonemason_status"]'), function (r) {
      r.addEventListener('change', function () {
        lookup.style.display = r.value === 'yes' ? '' : 'none';
        if (r.value === 'yes') load(); else clearLookup();
      });
    });
    name.addEventListener('input', function () {
      org.value = '';
      var q = name.value.trim().toLowerCase();
      if (q.length < 2 || !list || !list.length) { results.innerHTML = ''; return; }
      var hits = list.filter(function (x) { return (x.name || '').toLowerCase().indexOf(q) !== -1; })
        .sort(function (a, b) {
          var ap = (a.name || '').toLowerCase().indexOf(q) === 0;
          var bp = (b.name || '').toLowerCase().indexOf(q) === 0;
          return ap === bp ? 0 : (ap ? -1 : 1);
        }).slice(0, 5);
      results.innerHTML = '';
      hits.forEach(function (x) {
        var b = document.createElement('button');
        b.type = 'button';
        b.className = 'smf-sm-hit';
        b.textContent = x.name + (x.suburb ? ' \u00b7 ' + x.suburb + ' ' + (x.state || '') : '');
        b.addEventListener('click', function () {
          name.value = x.name || '';
          org.value = String(x.id || '');
          results.innerHTML = '';
        });
        results.appendChild(b);
      });
    });
  })();

  // Observe for dynamically added stone cards (from stones.json)
  var observer = new MutationObserver(function() {
    attachSampleButtons();
  });
  observer.observe(document.body, { childList: true, subtree: true });

  // Also run once after a delay for initial content
  setTimeout(attachSampleButtons, 500);

  document.addEventListener('submit', async function(e){
    if(!e.target.classList.contains('sample-modal-form'))return;
    e.preventDefault();
    var form=e.target;
    var btn=form.querySelector('[type="submit"]');
    var originalText=btn.textContent;
    btn.disabled=true;btn.textContent='Submitting…';
    try{
      var formData=Object.fromEntries(new FormData(form));
      var res=await fetch('/api/order-sample',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(formData)});
      var json=await res.json();
      if(json.ok){
        var modal=form.closest('[class*="modal"],[id*="modal"]')||form.parentElement;
        modal.innerHTML='<div style="padding:48px 24px;text-align:center"><div style="font-size:48px;margin-bottom:16px">✓</div><h2 style="color:#564D22;font-size:20px;margin:0 0 12px">Request received.</h2><p style="color:#666;font-size:15px;line-height:1.7;margin:0 auto;max-width:360px">Thank you, '+formData.first_name+'. We will be in touch within 2–3 business days.</p><button onclick="this.closest(\'[class*=modal],[id*=modal]\').style.display=\'none\'" style="margin-top:24px;padding:12px 28px;background:#564D22;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:14px">Close</button></div>';
      }else{throw new Error(json.error||'Submission failed');}
    }catch(err){
      btn.disabled=false;btn.textContent=originalText;
      var errEl=document.createElement('p');
      errEl.style.cssText='color:#c0392b;font-size:13px;text-align:center;margin:8px 0 0';
      errEl.textContent=err.message||'Something went wrong. Please try again.';
      form.appendChild(errEl);
    }
  });
})();
