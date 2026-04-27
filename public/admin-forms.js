var currentFormType='', currentOffset=0;
var PAGE_SIZE=20;
async function renderFormsPanel(){
  var container=document.getElementById('forms-panel');
  if(!container)return;
  container.innerHTML='<div class="forms-header"><h2>Forms</h2><div class="forms-header-actions"><button class="btn-tab-switch active" id="btn-submissions" onclick="switchFormsTab(\'submissions\')">Submissions</button><button class="btn-tab-switch" id="btn-schemas" onclick="switchFormsTab(\'schemas\')">Form Schemas</button></div></div><div id="forms-tab-submissions"><div class="loading">Loading…</div></div><div id="forms-tab-schemas" style="display:none"><div class="loading">Loading…</div></div><div id="forms-toast" class="forms-toast hidden"></div>';
  loadSubmissionsTab('',0);
  loadSchemasTab();
}
function switchFormsTab(tab){
  document.getElementById('forms-tab-submissions').style.display=tab==='submissions'?'block':'none';
  document.getElementById('forms-tab-schemas').style.display=tab==='schemas'?'block':'none';
  document.getElementById('btn-submissions').classList.toggle('active',tab==='submissions');
  document.getElementById('btn-schemas').classList.toggle('active',tab==='schemas');
}
async function loadSubmissionsTab(formType,offset){
  currentFormType=formType||''; currentOffset=offset||0;
  var container=document.getElementById('forms-tab-submissions');
  container.innerHTML='<div class="loading">Loading submissions…</div>';
  try{
    var params=new URLSearchParams({limit:PAGE_SIZE,offset:currentOffset});
    if(currentFormType)params.set('form_type',currentFormType);
    var res=await fetch('/api/admin/submissions?'+params,{credentials:'include'});
    var data=await res.json();
    var types=['All','Sample Request','Contact Enquiry','Newsletter'];
    container.innerHTML='<div class="sub-toolbar"><div class="sub-filters">'+
      types.map(function(t){return '<button class="sub-filter-btn'+(currentFormType===(t==='All'?'':t)?' active':'')+'" onclick="loadSubmissionsTab(\''+(t==='All'?'':t)+'\',0)">'+t+'</button>';}).join('')+
      '</div><div class="sub-actions"><button class="btn-export" onclick="exportSubmissions(\''+currentFormType+'\')">↓ Export CSV</button></div></div>'+
      (data.submissions.length===0?'<p class="sub-empty">No submissions yet.</p>':
      '<div class="sub-table-wrap"><table class="sub-table"><thead><tr><th>#</th><th>Type</th><th>Name</th><th>Email</th><th>Phone</th><th>Location</th><th>Date</th><th>Status</th><th></th></tr></thead><tbody>'+
      data.submissions.map(function(s){return '<tr class="sub-row'+(s.status==='new'?' sub-row-new':'')+'"><td class="sub-id">'+s.id+'</td><td><span class="sub-type-badge">'+s.form_type+'</span></td><td>'+(s.name||'—')+'</td><td>'+(s.email||'—')+'</td><td>'+(s.phone||'—')+'</td><td>'+(s.store_location||s.state||'—')+'</td><td>'+new Date(s.submitted_at).toLocaleDateString('en-AU')+'</td><td><span class="sub-status sub-status-'+s.status+'">'+s.status+'</span></td><td>'+(s.status==='new'?'<button class="btn-action" onclick="markActioned('+s.id+',this)">Mark actioned</button>':'')+'</td></tr>';}).join('')+
      '</tbody></table></div><div class="sub-pagination"><span>'+(currentOffset+1)+'–'+Math.min(currentOffset+PAGE_SIZE,data.total)+' of '+data.total+'</span><div>'+
      (currentOffset>0?'<button onclick="loadSubmissionsTab(\''+currentFormType+'\','+(currentOffset-PAGE_SIZE)+')">← Prev</button>':'')+
      (currentOffset+PAGE_SIZE<data.total?'<button onclick="loadSubmissionsTab(\''+currentFormType+'\','+(currentOffset+PAGE_SIZE)+')">Next →</button>':'')+
      '</div></div>');
  }catch(err){container.innerHTML='<p class="error">Failed to load: '+err.message+'</p>';}
}
async function markActioned(id,btn){
  btn.disabled=true;btn.textContent='…';
  try{
    await fetch('/api/admin/submissions/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({status:'actioned'})});
    var row=btn.closest('.sub-row');
    row.classList.remove('sub-row-new');
    row.querySelector('.sub-status').textContent='actioned';
    row.querySelector('.sub-status').className='sub-status sub-status-actioned';
    btn.parentElement.innerHTML='';
    showFormsToast('Marked as actioned','success');
  }catch(err){btn.disabled=false;btn.textContent='Mark actioned';showFormsToast('Error: '+err.message,'error');}
}
function exportSubmissions(formType){
  var params=formType?'?form_type='+encodeURIComponent(formType):'';
  window.location.href='/api/admin/submissions/export'+params;
}
async function loadSchemasTab(){
  var container=document.getElementById('forms-tab-schemas');
  try{
    var res=await fetch('/api/admin/forms',{credentials:'include'});
    var data=await res.json();
    container.innerHTML='<p class="schema-intro">Edit labels, placeholders and required status. Field names and types cannot be changed here — contact your developer.</p><div class="schema-list">'+
      data.forms.map(function(form){return '<div class="schema-card" id="schema-'+form.id+'"><div class="schema-card-header"><div><h3>'+form.label+'</h3><span class="schema-meta">'+form.endpoint+' · '+form.fields.length+' fields</span></div><button class="btn-save-schema" onclick="saveSchema(\''+form.id+'\')">Save</button></div><p class="schema-page">'+form.page+'</p><table class="schema-fields-table"><thead><tr><th>Field</th><th>Type</th><th>Label</th><th>Placeholder</th><th>Required</th></tr></thead><tbody>'+
      form.fields.map(function(f,i){return '<tr><td class="field-name">'+f.name+'</td><td class="field-type">'+f.type+'</td><td><input type="text" data-form="'+form.id+'" data-index="'+i+'" data-key="label" value="'+(f.label||'').replace(/"/g,'&quot;')+'" class="schema-input" /></td><td><input type="text" data-form="'+form.id+'" data-index="'+i+'" data-key="placeholder" value="'+(f.placeholder||'').replace(/"/g,'&quot;')+'" class="schema-input" /></td><td style="text-align:center"><input type="checkbox" data-form="'+form.id+'" data-index="'+i+'" data-key="required" '+(f.required?'checked':'')+' class="schema-checkbox" /></td></tr>';}).join('')+
      '</tbody></table></div>';}).join('')+'</div>';
  }catch(err){container.innerHTML='<p class="error">Failed to load schemas: '+err.message+'</p>';}
}
async function saveSchema(formId){
  var card=document.getElementById('schema-'+formId);
  var btn=card.querySelector('.btn-save-schema');
  btn.disabled=true;btn.textContent='Saving…';
  try{
    var res=await fetch('/api/admin/forms',{credentials:'include'});
    var data=await res.json();
    var form=data.forms.find(function(f){return f.id===formId;});
    if(!form)throw new Error('Form not found');
    card.querySelectorAll('[data-form]').forEach(function(el){
      var i=parseInt(el.dataset.index);
      var key=el.dataset.key;
      form.fields[i][key]=el.type==='checkbox'?el.checked:el.value;
    });
    var saveRes=await fetch('/api/admin/forms/'+formId,{method:'PUT',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify(form)});
    var saveData=await saveRes.json();
    if(!saveData.ok)throw new Error(saveData.error||'Save failed');
    showFormsToast('✓ '+form.label+' saved','success');
  }catch(err){showFormsToast('Error: '+err.message,'error');}
  finally{btn.disabled=false;btn.textContent='Save';}
}
function showFormsToast(msg,type){
  var toast=document.getElementById('forms-toast');
  toast.textContent=msg;
  toast.className='forms-toast '+type;
  setTimeout(function(){toast.className='forms-toast hidden';},4000);
}
window.addEventListener('DOMContentLoaded',renderFormsPanel);
