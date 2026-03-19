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
          <select class="smf-select" name="role">\
            <option value="" disabled selected>I am a...</option>\
            <option value="homeowner">Homeowner</option>\
            <option value="designer">Designer / Architect</option>\
            <option value="builder">Builder</option>\
            <option value="fabricator">Fabricator</option>\
            <option value="developer">Developer</option>\
            <option value="other">Other</option>\
          </select>\
        </div>\
        <input type="hidden" name="stone_slug" id="sample-modal-slug">\
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
    } else {
      stoneCard.style.display = 'none';
      slugInput.value = '';
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

  // Observe for dynamically added stone cards (from stones.json)
  var observer = new MutationObserver(function() {
    attachSampleButtons();
  });
  observer.observe(document.body, { childList: true, subtree: true });

  // Also run once after a delay for initial content
  setTimeout(attachSampleButtons, 500);
})();
