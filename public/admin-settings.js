// admin-settings.js — Settings panel for Railway env var management

const SETTINGS_GROUPS = [
  {
    id: 'notifications',
    label: 'Notifications',
    icon: '🔔',
    vars: [
      { key: 'ALERT_EMAIL_TO',  label: 'Alert Email Address', type: 'email',
        hint: 'Who receives email alerts when a form is submitted' },
      { key: 'TWILIO_TO',       label: 'SMS Alert Number',    type: 'tel',
        hint: 'Mobile number to receive SMS alerts (include country code, e.g. +61...)' }
    ]
  },
  {
    id: 'instagram',
    label: 'Instagram Feed',
    icon: '📸',
    vars: [
      { key: 'INSTAGRAM_ACCESS_TOKEN', label: 'Access Token',      type: 'password',
        hint: 'Generated from Meta Developer dashboard — expires every 60 days' },
      { key: 'INSTAGRAM_ACCOUNT_ID',   label: 'Instagram Account ID', type: 'text',
        hint: 'Numeric ID from Meta Developer dashboard (e.g. 17841400000000000)' }
    ]
  },
  {
    id: 'email',
    label: 'Email (SMTP)',
    icon: '📧',
    vars: [
      { key: 'SMTP_USER', label: 'Email Address', type: 'email',
        hint: 'The email account used to send notifications' },
      { key: 'SMTP_PASS', label: 'App Password',  type: 'password',
        hint: 'App password from Microsoft account security settings' },
      { key: 'SMTP_HOST', label: 'SMTP Host',     type: 'text',
        hint: 'smtp.office365.com for Microsoft 365' },
      { key: 'SMTP_PORT', label: 'SMTP Port',     type: 'text',
        hint: '587 for Microsoft 365' }
    ]
  },
  {
    id: 'twilio',
    label: 'Twilio SMS',
    icon: '💬',
    vars: [
      { key: 'TWILIO_ACCOUNT_SID', label: 'Account SID',  type: 'text',     hint: 'From Twilio Console dashboard' },
      { key: 'TWILIO_AUTH_TOKEN',  label: 'Auth Token',   type: 'password', hint: 'From Twilio Console dashboard' },
      { key: 'TWILIO_FROM',        label: 'Twilio Number',type: 'tel',      hint: 'Your Twilio phone number (e.g. +1...)' }
    ]
  }
];

function renderSettingsPanel() {
  const container = document.getElementById('settings-panel');
  if (!container) return;

  const env = window.location.hostname.includes('preview') ||
              window.location.hostname.includes('staging') ? 'staging' : 'production';

  container.innerHTML = `
    <div class="settings-header">
      <h2>Site Settings</h2>
      <span class="settings-env-badge ${env}">${env}</span>
    </div>
    <p class="settings-intro">Changes are applied to the <strong>${env}</strong> environment and take effect immediately on the next deployment.</p>
    ${SETTINGS_GROUPS.map(group => `
      <div class="settings-group" id="group-${group.id}">
        <div class="settings-group-header">
          <span class="settings-group-icon">${group.icon}</span>
          <h3>${group.label}</h3>
          <button class="btn-save-group" onclick="saveGroup('${group.id}')">Save ${group.label}</button>
        </div>
        ${group.vars.map(v => `
          <div class="settings-field">
            <label for="var-${v.key}">${v.label}</label>
            <div class="settings-input-wrap">
              <input
                id="var-${v.key}"
                type="${v.type === 'password' ? 'password' : 'text'}"
                placeholder="${v.type === 'password' ? '••••••••' : 'Not set'}"
                data-key="${v.key}"
                autocomplete="off"
              />
              ${v.type === 'password' ? `
                <button class="btn-reveal" onclick="toggleReveal('var-${v.key}', this)">Show</button>
              ` : ''}
            </div>
            <span class="settings-hint">${v.hint}</span>
          </div>
        `).join('')}
      </div>
    `).join('')}
    <div id="settings-toast" class="settings-toast hidden"></div>
  `;
}

function toggleReveal(inputId, btn) {
  const input = document.getElementById(inputId);
  if (input.type === 'password') {
    input.type = 'text';
    btn.textContent = 'Hide';
  } else {
    input.type = 'password';
    btn.textContent = 'Show';
  }
}

async function saveGroup(groupId) {
  const group = SETTINGS_GROUPS.find(g => g.id === groupId);
  if (!group) return;

  const vars = {};
  let hasValues = false;
  for (const v of group.vars) {
    const input = document.getElementById(`var-${v.key}`);
    if (input && input.value.trim()) {
      vars[v.key] = input.value.trim();
      hasValues = true;
    }
  }

  if (!hasValues) {
    showToast('No values entered — nothing to save.', 'warn');
    return;
  }

  const btn = document.querySelector(`#group-${groupId} .btn-save-group`);
  const originalText = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Saving…';

  try {
    const res = await fetch('/api/admin/railway-vars', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ vars })
    });
    const data = await res.json();
    if (data.ok) {
      showToast(`✓ ${group.label} saved — redeploy to apply`, 'success');
      // Clear sensitive fields
      for (const v of group.vars) {
        if (v.type === 'password') {
          const input = document.getElementById(`var-${v.key}`);
          if (input) input.value = '';
        }
      }
    } else {
      throw new Error(data.error || 'Save failed');
    }
  } catch (err) {
    showToast(`Error: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = originalText;
  }
}

function showToast(msg, type = 'success') {
  const toast = document.getElementById('settings-toast');
  toast.textContent = msg;
  toast.className = `settings-toast ${type}`;
  setTimeout(() => toast.className = 'settings-toast hidden', 4000);
}

window.addEventListener('DOMContentLoaded', renderSettingsPanel);
