(function () {
  'use strict';
  if (!window.__alphaFormRescueLoaded) {
    const rescueScript = document.createElement('script');
    rescueScript.src = '/form-rescue.js?v=2';
    rescueScript.async = false;
    document.head.appendChild(rescueScript);
  }
  document.addEventListener('DOMContentLoaded', function () {
    const form = document.querySelector('form.contact-form');
    if (!form) return;
    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      const btn = form.querySelector('[type="submit"]');
      const originalText = btn.textContent;
      btn.disabled = true;
      btn.textContent = 'Sending…';
      try {
        const data = Object.fromEntries(new FormData(form));
        data.source = window.location.pathname;
        const res  = await fetch('/api/contact', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data)
        });
        const json = await res.json();
        if (json.ok) {
          form.innerHTML = `<div style="padding:32px 0;text-align:center">
            <p style="font-size:18px;color:#564D22;font-weight:500;margin:0 0 8px">
              Thank you, ${data.name.split(' ')[0]}.
            </p>
            <p style="color:#666;font-size:15px;margin:0;line-height:1.6">
              We've received your enquiry and will be in touch shortly.
            </p></div>`;
        } else { throw new Error(json.error || 'Submission failed'); }
      } catch (err) {
        btn.disabled = false;
        btn.textContent = originalText;
        let el = form.querySelector('.form-error');
        if (!el) {
          el = document.createElement('p');
          el.className = 'form-error';
          el.style.cssText = 'color:#c0392b;font-size:14px;margin:12px 0 0;text-align:center';
          form.appendChild(el);
        }
        el.textContent = err.message || 'Something went wrong. Please call us on 1300 257 420.';
      }
    });
  });
})();
