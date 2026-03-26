/* ═══════════════════════════════════════════
   SLAB LIGHTBOX — Click close-up to see full slab
   Runs on product pages after stones.json data loads
   ═══════════════════════════════════════════ */
(function() {
  'use strict';

  // Inject lightbox styles
  var style = document.createElement('style');
  style.textContent =
    '.slab-lightbox{position:fixed;inset:0;z-index:200;background:rgba(0,0,0,0.85);display:flex;align-items:center;justify-content:center;opacity:0;pointer-events:none;transition:opacity 0.3s ease;cursor:zoom-out;}' +
    '.slab-lightbox.open{opacity:1;pointer-events:auto;}' +
    '.slab-lightbox img{max-width:92vw;max-height:90vh;object-fit:contain;border-radius:4px;box-shadow:0 8px 40px rgba(0,0,0,0.4);}' +
    '.slab-lightbox-close{position:absolute;top:20px;right:24px;background:none;border:none;color:#fff;font-size:32px;cursor:pointer;opacity:0.7;padding:8px;line-height:1;z-index:201;}' +
    '.slab-lightbox-close:hover{opacity:1;}' +
    '.slab-lightbox-label{position:absolute;bottom:20px;left:50%;transform:translateX(-50%);color:#fff;font-family:"Degular",sans-serif;font-size:14px;opacity:0.6;letter-spacing:0.5px;}' +
    '.intro-swatch img.has-slab{cursor:zoom-in;}';
  document.head.appendChild(style);

  // Create lightbox DOM
  var overlay = document.createElement('div');
  overlay.className = 'slab-lightbox';
  overlay.innerHTML =
    '<button class="slab-lightbox-close" aria-label="Close">&times;</button>' +
    '<img src="" alt="Full slab view">' +
    '<span class="slab-lightbox-label">Full slab view</span>';
  document.body.appendChild(overlay);

  var lbImg = overlay.querySelector('img');
  var closeBtn = overlay.querySelector('.slab-lightbox-close');

  function closeLightbox() {
    overlay.classList.remove('open');
  }

  closeBtn.addEventListener('click', closeLightbox);
  overlay.addEventListener('click', function(e) {
    if (e.target === overlay) closeLightbox();
  });
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeLightbox();
  });

  // Public API — called from product page JS after stone data loads
  window.initSlabLightbox = function(slabUrl, stoneName) {
    if (!slabUrl) return;
    var swatchImg = document.querySelector('.intro-swatch img');
    if (!swatchImg) return;

    swatchImg.classList.add('has-slab');
    swatchImg.title = 'Click to view full slab';
    swatchImg.addEventListener('click', function() {
      lbImg.src = slabUrl;
      lbImg.alt = stoneName + ' — full slab';
      overlay.classList.add('open');
    });
  };
})();
