/* ═══════════════════════════════════════════
   FLOATING "ORDER YOUR SAMPLES" POPUP
   Shows after 3s, dismissible, sessionStorage
   ═══════════════════════════════════════════ */
(function() {
  if (sessionStorage.getItem('sample-popup-dismissed')) return;

  var popup = document.createElement('div');
  popup.id = 'sample-popup';
  popup.innerHTML =
    '<button id="sample-popup-close" aria-label="Close">&times;</button>' +
    '<p class="sp-heading">Order your samples now!</p>' +
    '<p class="sp-body">Love our surfaces? Order up to 4 samples and experience their true beauty, first hand.</p>' +
    '<a href="/order-sample.html" class="sp-cta">Order Now</a>';

  // Inject styles
  var style = document.createElement('style');
  style.textContent =
    '#sample-popup{position:fixed;bottom:24px;right:24px;z-index:150;width:320px;background:#fff;border-radius:8px;box-shadow:0 8px 32px rgba(0,0,0,0.15);padding:28px 24px 24px;opacity:0;transform:translateY(20px);transition:opacity 0.4s ease,transform 0.4s ease;pointer-events:none;}' +
    '#sample-popup.visible{opacity:1;transform:translateY(0);pointer-events:auto;}' +
    '#sample-popup-close{position:absolute;top:10px;right:12px;background:none;border:none;font-size:22px;color:#000;opacity:0.3;cursor:pointer;padding:4px 8px;line-height:1;}' +
    '#sample-popup-close:hover{opacity:0.8;}' +
    '.sp-heading{font-family:"Concrette S",serif;font-weight:700;font-size:22px;color:#000;line-height:1.2;margin:0 0 10px;}' +
    '.sp-body{font-family:"Degular",sans-serif;font-weight:400;font-size:14px;color:#000;opacity:0.65;line-height:1.5;margin:0 0 20px;}' +
    '.sp-cta{display:block;background:#564d22;color:#fff;font-family:"Degular",sans-serif;font-weight:500;font-size:15px;text-align:center;padding:10px 0;border-radius:8px;text-decoration:none;letter-spacing:0.3px;}' +
    '.sp-cta:hover{opacity:0.9;}' +
    '@media(max-width:768px){#sample-popup{bottom:16px;right:16px;left:16px;width:auto;}}';
  document.head.appendChild(style);
  document.body.appendChild(popup);

  // Show after 3 seconds
  setTimeout(function() {
    popup.classList.add('visible');
  }, 3000);

  // Close
  document.getElementById('sample-popup-close').addEventListener('click', function() {
    popup.classList.remove('visible');
    sessionStorage.setItem('sample-popup-dismissed', '1');
    setTimeout(function() { popup.remove(); }, 400);
  });
})();
