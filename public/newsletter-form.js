(function(){
  'use strict';
  var CONSENT_TEXT='Yes, I\'d like to receive emails from Alpha Surfaces about new collections, products and events. I can unsubscribe anytime.';
  var DISCLAIMER='By subscribing you agree to receive marketing emails from <strong>Alpha Surfaces Pty Ltd</strong> (ABN 21 677 729 350). Your information is handled in accordance with our <a href="/privacy.html" target="_blank" rel="noopener">Privacy Policy</a>. You can unsubscribe at any time.';
  function upgradeFooterForms(){
    var widgets=document.querySelectorAll('.footer-email-form, form.footer-email-form');
    widgets.forEach(function(widget){
      widget.innerHTML='<div class="nl-fields"><input type="email" class="footer-email-input" name="email" placeholder="Email address" autocomplete="email" required /><button type="button" class="footer-email-btn" id="nl-submit">Subscribe</button></div><div class="nl-consent-wrap"><label class="nl-consent-label"><input type="checkbox" name="consent" class="nl-consent-checkbox" required /><span>'+CONSENT_TEXT+'</span></label></div><div style="margin-top:6px;font-size:11px;color:#9e9980;line-height:1.5">'+DISCLAIMER+'</div><p class="nl-message" style="display:none"></p>';
      var btn=widget.querySelector('#nl-submit');
      var emailEl=widget.querySelector('input[type="email"]');
      var consentEl=widget.querySelector('input[type="checkbox"]');
      var msgEl=widget.querySelector('.nl-message');
      btn.addEventListener('click',async function(){
        var email=emailEl.value.trim();
        var consent=consentEl.checked;
        if(!email||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){showMsg(msgEl,'Please enter a valid email address.','error');return;}
        if(!consent){showMsg(msgEl,'Please tick the checkbox to subscribe.','error');return;}
        btn.disabled=true;btn.textContent='Subscribing…';
        try{
          var res=await fetch('/api/subscribe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email,consent:true})});
          var json=await res.json();
          if(json.ok){widget.innerHTML='<p style="color:#f3f1e6;font-size:15px;line-height:1.6;margin:0">✓ You\'re subscribed. Welcome to Alpha Surfaces.</p>';}
          else{throw new Error(json.error||'Subscription failed');}
        }catch(err){
          btn.disabled=false;btn.textContent='Subscribe';
          showMsg(msgEl,err.message||'Something went wrong. Please try again.','error');
        }
      });
    });
  }
  function showMsg(el,text,type){
    el.textContent=text;el.style.display='block';
    el.style.color=type==='error'?'#fca5a5':'#86efac';
    el.style.fontSize='13px';el.style.marginTop='8px';
  }
  var style=document.createElement('style');
  style.textContent='.nl-fields{display:flex;gap:8px;margin-bottom:10px}.nl-fields .footer-email-input{flex:1}.nl-consent-wrap{margin:8px 0 4px}.nl-consent-label{display:flex;align-items:flex-start;gap:8px;cursor:pointer}.nl-consent-label input[type="checkbox"]{margin-top:3px;flex-shrink:0;accent-color:#564D22;width:15px;height:15px;cursor:pointer}.nl-consent-label span{font-size:12px;color:#c5c0a8;line-height:1.5}';
  document.head.appendChild(style);
  if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',upgradeFooterForms);}
  else{upgradeFooterForms();}
})();
