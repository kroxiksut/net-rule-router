import { api, tr, localize, applyAppearance, request, reportError, setNotice, readProfile, writeProfile, updateLanguageField, originsFor, renderConnection, renderWebRtc } from './common.js';

localize();
const globalForm = document.getElementById('global-form');
const profileForm = document.getElementById('profile-form');
const webRtcForm = document.getElementById('webrtc-form');
let snapshot;
let busy = false;

function setBusy(value) {
  busy = value;
  document.querySelector('main').setAttribute('aria-busy', String(value));
  for (const button of document.querySelectorAll('form button, #profile-list button')) button.disabled = value;
}

function renderProfiles() {
  const list = document.getElementById('profile-list');
  list.replaceChildren();
  document.getElementById('empty-profiles').hidden = snapshot.profiles.length > 0;
  for (const profile of snapshot.profiles) {
    const item = document.createElement('li');
    const description = document.createElement('div');
    const host = document.createElement('strong');
    host.textContent = profile.host;
    const scope = document.createElement('span');
    scope.textContent = tr(profile.includeSubdomains ? 'list_subdomains' : 'list_exact');
    const mode = document.createElement('span');
    mode.textContent = profile.languageMode === 'manual' ? tr('list_manual', profile.language) : tr(profile.languageMode === 'inherit' ? 'mode_global_inherit' : `mode_${profile.languageMode}`);
    description.append(host, scope, mode);
    const edit = document.createElement('button');
    edit.type = 'button';
    edit.textContent = tr('edit');
    edit.setAttribute('aria-label', tr('edit_host', profile.host));
    edit.addEventListener('click', () => {
      writeProfile(profileForm, profile);
      profileForm.elements.host.focus();
      profileForm.scrollIntoView({ block: 'center' });
    });
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.textContent = tr('restore_inheritance');
    remove.setAttribute('aria-label', tr('inherit_host', profile.host));
    remove.addEventListener('click', () => deleteProfile(profile.host));
    item.append(description, edit, remove);
    list.append(item);
  }
}

async function refresh() {
  const reply = await request({ type: 'getState' });
  snapshot = reply.state;
  renderConnection(reply);
  globalForm.elements.languageMode.value = snapshot.global.languageMode;
  globalForm.elements.language.value = snapshot.global.language || '';
  updateLanguageField(globalForm);
  const webRtcSupported = reply.capabilities.webRtc;
  renderWebRtc(reply);
  webRtcForm.hidden = !webRtcSupported;
  document.getElementById('webrtc-restore').hidden = !(snapshot.webRtc?.enabled || snapshot.webRtc?.owned);
  renderProfiles();
}

async function finishMutation(message, successKey) {
  try {
    await request({ ...message, baseRevision: snapshot.revision, confirmed: true });
  } catch (error) {
    await refresh().catch(() => {});
    throw error;
  }
  await refresh();
  setNotice(successKey, 'success');
}

globalForm.elements.languageMode.addEventListener('change', () => updateLanguageField(globalForm));
profileForm.elements.languageMode.addEventListener('change', () => updateLanguageField(profileForm));
profileForm.addEventListener('reset', () => {
  queueMicrotask(() => updateLanguageField(profileForm));
});

globalForm.addEventListener('submit', async event => {
  event.preventDefault();
  if (busy || !snapshot) return;
  setBusy(true);
  try {
    const global = { languageMode: globalForm.elements.languageMode.value, language: globalForm.elements.language.value.trim() };
    if (global.languageMode === 'manual') {
      if (!await api.permissions.request({ origins: ['*://*/*'] })) throw new Error('permission_denied');
    }
    await finishMutation({ type: 'saveGlobal', global }, 'saved_reload');
  } catch (error) {
    reportError(error);
  } finally {
    setBusy(false);
  }
});

profileForm.addEventListener('submit', async event => {
  event.preventDefault();
  if (busy || !snapshot) return;
  setBusy(true);
  try {
    const profile = readProfile(profileForm);
    if (profile.languageMode === 'manual') {
      if (!await api.permissions.request({ origins: originsFor(profile) })) throw new Error('permission_denied');
    }
    const inherited = profile.languageMode === 'inherit';
    await finishMutation(inherited ? { type: 'deleteProfile', host: profile.host } : { type: 'saveProfile', profile }, inherited ? 'inherited_reload' : 'saved_reload');
    profileForm.reset();
  } catch (error) {
    reportError(error);
  } finally {
    setBusy(false);
  }
});

async function deleteProfile(host) {
  if (busy || !snapshot || !globalThis.confirm(tr('inherit_confirm'))) return;
  setBusy(true);
  try {
    await finishMutation({ type: 'deleteProfile', host }, 'inherited_reload');
  } catch (error) {
    reportError(error);
  } finally {
    setBusy(false);
  }
}

webRtcForm.addEventListener('submit', async event => {
  event.preventDefault();
  if (busy || !snapshot) return;
  if (!webRtcForm.elements.acknowledge.checked) {
    setNotice('webrtc_confirm_required', 'warning');
    webRtcForm.elements.acknowledge.focus();
    return;
  }
  setBusy(true);
  try {
    if (!await api.permissions.request({ permissions: ['privacy'] })) throw new Error('permission_denied');
    await finishMutation({ type: 'setWebRtc', enabled: true }, 'webrtc_saved');
    webRtcForm.elements.acknowledge.checked = false;
  } catch (error) {
    reportError(error);
  } finally {
    setBusy(false);
  }
});

document.getElementById('webrtc-restore').addEventListener('click', async () => {
  if (busy || !snapshot) return;
  setBusy(true);
  try {
    await finishMutation({ type: 'setWebRtc', enabled: false }, 'webrtc_restored');
  } catch (error) {
    reportError(error);
  } finally {
    setBusy(false);
  }
});

for (const id of ['theme', 'font']) {
  const select = document.getElementById(id);
  select.value = localStorage.getItem(`nrr-${id}`) || 'system';
  select.addEventListener('change', () => {
    localStorage.setItem(`nrr-${id}`, select.value);
    applyAppearance();
  });
}

updateLanguageField(profileForm);
refresh().catch(error => {
  reportError(error);
  setBusy(true);
});
