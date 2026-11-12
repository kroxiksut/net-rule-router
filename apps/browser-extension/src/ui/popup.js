import { api, tr, localize, request, reportError, setNotice, readProfile, writeProfile, updateLanguageField, originsFor, setBusy, renderConnection, renderWebRtc } from './common.js';

localize();
const form = document.getElementById('site-form');
let snapshot;
let currentHost;
let busy = false;

function updateScope() {
  document.getElementById('scope').textContent = tr(
    form.elements.languageMode.value === 'inherit' ? 'scope_inherited' : form.elements.includeSubdomains.checked ? 'scope_subdomains' : 'scope_exact',
    currentHost || '',
  );
}

async function refresh() {
  const reply = await request({ type: 'getState' });
  snapshot = reply.state;
  renderConnection(reply);
  const profiles = snapshot.profiles.filter(profile => profile.languageMode !== 'inherit');
  const exact = profiles.find(profile => profile.host === currentHost);
  const broader = profiles.filter(profile => profile.includeSubdomains && currentHost.endsWith(`.${profile.host}`)).sort((a, b) => b.host.length - a.host.length)[0];
  const inherited = document.getElementById('inherited-profile');
  inherited.hidden = Boolean(exact || !broader);
  if (!exact && broader) {
    const value = broader.languageMode === 'manual' ? tr('list_manual', broader.language) : tr(`mode_${broader.languageMode}`);
    inherited.textContent = tr('broader_profile', [broader.host, value]);
  }
  writeProfile(form, exact || { host: currentHost, includeSubdomains: false, languageMode: 'inherit', language: '' });
  renderWebRtc(reply);
  updateScope();
}

document.getElementById('open-options').addEventListener('click', () => {
  api.runtime.openOptionsPage().catch(reportError);
});
form.elements.languageMode.addEventListener('change', () => {
  updateLanguageField(form);
  updateScope();
});
form.elements.includeSubdomains.addEventListener('change', updateScope);

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (busy || !snapshot) return;
  busy = true;
  setBusy(form, true);
  try {
    const profile = readProfile(form);
    if (profile.languageMode === 'manual') {
      const granted = await api.permissions.request({ origins: originsFor(profile) });
      if (!granted) throw new Error('permission_denied');
    }
    const inherited = profile.languageMode === 'inherit';
    const change = inherited ? { type: 'deleteProfile', host: profile.host } : { type: 'saveProfile', profile };
    await request({ ...change, baseRevision: snapshot.revision, confirmed: true });
    await refresh();
    setNotice(inherited ? 'inherited_reload' : 'saved_reload', 'success');
  } catch (error) {
    await refresh().catch(() => {});
    reportError(error);
  } finally {
    busy = false;
    setBusy(form, false);
  }
});

document.getElementById('inherit').addEventListener('click', async () => {
  if (busy || !snapshot) return;
  if (!globalThis.confirm(tr('inherit_confirm'))) return;
  busy = true;
  setBusy(form, true);
  try {
    await request({ type: 'deleteProfile', host: currentHost, baseRevision: snapshot.revision, confirmed: true });
    await refresh();
    setNotice('inherited_reload', 'success');
  } catch (error) {
    await refresh().catch(() => {});
    reportError(error);
  } finally {
    busy = false;
    setBusy(form, false);
  }
});

async function initialize() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  const url = new URL(tab?.url || 'about:blank');
  if (!['http:', 'https:'].includes(url.protocol)) {
    form.hidden = true;
    document.getElementById('current-host').textContent = tr('unsupported_page');
    setNotice('open_website');
    const reply = await request({ type: 'getState' });
    renderConnection(reply);
    renderWebRtc(reply);
    return;
  }
  currentHost = url.hostname.replace(/\.$/u, '');
  document.getElementById('current-host').textContent = currentHost;
  await refresh();
}

initialize().catch(error => {
  form.hidden = true;
  reportError(error);
});
