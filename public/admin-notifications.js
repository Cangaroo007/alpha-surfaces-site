// Notifications admin — per-form SMS + email recipient routing with cadence.
// Settings live at GET/PUT /api/admin/notifications. Test fires at POST .../test.
var NOTIF_STATE = null;
var NOTIF_DIRTY = {}; // formId -> true when unsaved changes
async function renderNotificationsPanel(){
  var container=document.getElementById('notifications-panel');
  if(!container)return;
  container.innerHTML='<div class="forms-header"><h2>Notifications</h2>'
    +'<div class="notif-header-actions">'
    +'<button class="btn-export" onclick="fireDigestNow(this)">Send daily digest now</button>'
    +'</div></div>'
    +'<p class="schema-intro">Configure who gets notified for each form. <strong>Instant</strong> sends per submission. <strong>Daily</strong> sends a consolidated digest at 5pm Brisbane time.</p>'
    +'<div id="notif-cards"><div class="loading">Loading…</div></div>'
    +'<div id="notif-toast" class="forms-toast hidden"></div>';
  await loadNotifications();
}
async function loadNotifications(){
  var cards=document.getElementById('notif-cards');
  try{
    var res=await fetch('/api/admin/notifications',{credentials:'include'});
    var data=await res.json();
    NOTIF_STATE=data;
    NOTIF_DIRTY={};
    if(!data.notifications||!Object.keys(data.notifications).length){
      cards.innerHTML='<p class="sub-empty">No notification settings yet.</p>';
      return;
    }
    cards.innerHTML=Object.keys(data.notifications).map(function(formId){
      return renderFormCard(formId,data.notifications[formId]);
    }).join('');
  }catch(err){
    cards.innerHTML='<p class="error">Failed to load notifications: '+err.message+'</p>';
  }
}
function renderFormCard(formId,n){
  return '<div class="schema-card notif-card" id="notif-'+formId+'">'
    +'<div class="schema-card-header">'
      +'<div><h3>'+n.label+'</h3><span class="schema-meta">Form ID: '+formId+'</span></div>'
      +'<div class="notif-card-actions">'
        +'<button class="btn-test" onclick="testForm(\''+formId+'\',this)">Send test</button>'
        +'<button class="btn-save-schema" onclick="saveNotif(\''+formId+'\')">Save</button>'
      +'</div>'
    +'</div>'
    +renderChannel(formId,'sms',n.sms||{enabled:false,recipients:[]})
    +renderChannel(formId,'email',n.email||{enabled:false,recipients:[]})
  +'</div>';
}
function renderChannel(formId,channel,block){
  var rows=(block.recipients||[]).map(function(r,i){
    return renderRecipient(formId,channel,i,r);
  }).join('');
  return '<div class="notif-channel">'
    +'<div class="notif-channel-header">'
      +'<label class="notif-toggle"><input type="checkbox" '+(block.enabled?'checked':'')+' onchange="toggleChannel(\''+formId+'\',\''+channel+'\',this.checked)" /> '
      +'<strong>'+(channel==='sms'?'SMS':'Email')+' notifications</strong></label>'
      +'<button class="btn-add-recipient" onclick="addRecipient(\''+formId+'\',\''+channel+'\')">+ Add recipient</button>'
    +'</div>'
    +'<table class="notif-recipients">'
      +'<thead><tr>'
        +'<th>Name</th>'
        +'<th>'+(channel==='sms'?'Phone (+61…)':'Email')+'</th>'
        +'<th>Cadence</th>'
        +'<th>On</th>'
        +'<th></th>'
      +'</tr></thead>'
      +'<tbody id="recipients-'+formId+'-'+channel+'">'+(rows||'<tr class="notif-empty"><td colspan="5">No recipients yet.</td></tr>')+'</tbody>'
    +'</table>'
  +'</div>';
}
function renderRecipient(formId,channel,i,r){
  var valKey=channel==='sms'?'phone':'email';
  var valType=channel==='sms'?'tel':'email';
  var valPlaceholder=channel==='sms'?'+61400000000':'name@example.com';
  return '<tr data-form="'+formId+'" data-channel="'+channel+'" data-index="'+i+'">'
    +'<td><input type="text" class="schema-input" placeholder="e.g. Belinda" value="'+esc(r.name||'')+'" oninput="updateRecipient(\''+formId+'\',\''+channel+'\','+i+',\'name\',this.value)" /></td>'
    +'<td><input type="'+valType+'" class="schema-input" placeholder="'+valPlaceholder+'" value="'+esc(r[valKey]||'')+'" oninput="updateRecipient(\''+formId+'\',\''+channel+'\','+i+',\''+valKey+'\',this.value)" /></td>'
    +'<td><select class="schema-input" onchange="updateRecipient(\''+formId+'\',\''+channel+'\','+i+',\'cadence\',this.value)">'
      +'<option value="instant"'+(r.cadence==='instant'?' selected':'')+'>Instant</option>'
      +'<option value="daily"'+(r.cadence==='daily'?' selected':'')+'>Daily 5pm</option>'
    +'</select></td>'
    +'<td style="text-align:center"><input type="checkbox" class="schema-checkbox" '+(r.enabled!==false?'checked':'')+' onchange="updateRecipient(\''+formId+'\',\''+channel+'\','+i+',\'enabled\',this.checked)" /></td>'
    +'<td><button class="btn-remove-recipient" onclick="removeRecipient(\''+formId+'\',\''+channel+'\','+i+')">×</button></td>'
  +'</tr>';
}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;');}
function markDirty(formId){NOTIF_DIRTY[formId]=true;
  var btn=document.querySelector('#notif-'+formId+' .btn-save-schema');
  if(btn){btn.textContent='Save *';btn.classList.add('dirty');}
}
function toggleChannel(formId,channel,enabled){
  NOTIF_STATE.notifications[formId][channel]=NOTIF_STATE.notifications[formId][channel]||{enabled:false,recipients:[]};
  NOTIF_STATE.notifications[formId][channel].enabled=enabled;
  markDirty(formId);
}
function addRecipient(formId,channel){
  var block=NOTIF_STATE.notifications[formId][channel]=NOTIF_STATE.notifications[formId][channel]||{enabled:true,recipients:[]};
  block.recipients=block.recipients||[];
  var blank={name:'',cadence:'instant',enabled:true};
  blank[channel==='sms'?'phone':'email']='';
  block.recipients.push(blank);
  // Re-render just the tbody for this channel
  var tbody=document.getElementById('recipients-'+formId+'-'+channel);
  tbody.innerHTML=block.recipients.map(function(r,i){return renderRecipient(formId,channel,i,r);}).join('');
  markDirty(formId);
}
function removeRecipient(formId,channel,index){
  var block=NOTIF_STATE.notifications[formId][channel];
  if(!block||!block.recipients)return;
  block.recipients.splice(index,1);
  var tbody=document.getElementById('recipients-'+formId+'-'+channel);
  tbody.innerHTML=block.recipients.length
    ?block.recipients.map(function(r,i){return renderRecipient(formId,channel,i,r);}).join('')
    :'<tr class="notif-empty"><td colspan="5">No recipients yet.</td></tr>';
  markDirty(formId);
}
function updateRecipient(formId,channel,index,key,value){
  var block=NOTIF_STATE.notifications[formId][channel];
  if(!block||!block.recipients||!block.recipients[index])return;
  block.recipients[index][key]=value;
  markDirty(formId);
}
async function saveNotif(formId){
  var card=document.getElementById('notif-'+formId);
  var btn=card.querySelector('.btn-save-schema');
  btn.disabled=true;btn.textContent='Saving…';
  try{
    var payload=NOTIF_STATE.notifications[formId];
    var res=await fetch('/api/admin/notifications/'+formId,{
      method:'PUT',
      headers:{'Content-Type':'application/json'},
      credentials:'include',
      body:JSON.stringify(payload)
    });
    var data=await res.json();
    if(!data.ok)throw new Error(data.error||'Save failed');
    delete NOTIF_DIRTY[formId];
    showNotifToast('✓ '+payload.label+' saved','success');
    btn.textContent='Save';btn.classList.remove('dirty');
  }catch(err){
    showNotifToast('Error: '+err.message,'error');
    btn.textContent='Save *';
  }finally{btn.disabled=false;}
}
async function testForm(formId,btn){
  btn.disabled=true;btn.textContent='Sending…';
  try{
    var res=await fetch('/api/admin/notifications/'+formId+'/test',{
      method:'POST',credentials:'include'
    });
    var data=await res.json();
    if(!data.ok)throw new Error(data.error||'Test failed');
    var summary=data.results||[];
    if(!summary.length){showNotifToast('No recipients configured for this form yet.','error');return;}
    var ok=summary.filter(function(r){return r.ok;}).length;
    var fail=summary.length-ok;
    showNotifToast('Test sent: '+ok+' succeeded'+(fail?', '+fail+' failed':''),fail?'error':'success');
  }catch(err){showNotifToast('Error: '+err.message,'error');}
  finally{btn.disabled=false;btn.textContent='Send test';}
}
async function fireDigestNow(btn){
  if(!confirm('Fire the daily digest now? This will send to all recipients with cadence=Daily.'))return;
  btn.disabled=true;btn.textContent='Sending…';
  try{
    var res=await fetch('/api/admin/notifications/_digest-now',{method:'POST',credentials:'include'});
    var data=await res.json();
    if(!data.ok)throw new Error(data.reason||data.error||'Digest failed');
    showNotifToast('Digest fired: '+(data.sent||0)+' messages across '+(data.formsCovered||0)+' form(s)','success');
  }catch(err){showNotifToast('Error: '+err.message,'error');}
  finally{btn.disabled=false;btn.textContent='Send daily digest now';}
}
function showNotifToast(msg,type){
  var toast=document.getElementById('notif-toast');
  toast.textContent=msg;
  toast.className='forms-toast '+type;
  setTimeout(function(){toast.className='forms-toast hidden';},4000);
}
window.addEventListener('DOMContentLoaded',renderNotificationsPanel);
