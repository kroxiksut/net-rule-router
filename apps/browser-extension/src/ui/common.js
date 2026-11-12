export const api = globalThis.browser ?? globalThis.chrome;

export function tr(key, substitutions) {
  return api.i18n.getMessage(key, substitutions) || key;
}

export function localize() {
  document.documentElement.lang = api.i18n.getUILanguage();
  for (const element of document.querySelectorAll('[data-i18n]')) {
    element.textContent = tr(element.dataset.i18n);
  }
  document.title = tr(document.body.dataset.title);
  applyAppearance();
}

export function applyAppearance() {
  const theme = localStorage.getItem('nrr-theme') || 'system';
  const font = localStorage.getItem('nrr-font') || 'system';
  document.documentElement.dataset.theme = theme;
  document.documentElement.dataset.font = font;
}

export function setNotice(key, tone = 'info') {
  const notice = document.getElementById('notice');
  notice.textContent = tr(key);
  notice.dataset.tone = tone;
  notice.hidden = false;
}

export function reportError(error) {
  const code = typeof error === 'string' ? error : error?.message;
  const translated = api.i18n.getMessage(`error_${String(code || '').replace(/[^a-zA-Z0-9_]/g, '')}`);
  const notice = document.getElementById('notice');
  notice.textContent = translated || tr('error_generic');
  notice.dataset.tone = 'error';
  notice.hidden = false;
}

export async function request(message) {
  const reply = await api.runtime.sendMessage(message);
  if (!reply?.ok) throw new Error(reply?.error || 'unavailable');
  return reply;
}

export function normalizedHost(value) {
  const text = value.trim();
  if (!text || text.length > 253 || /[\s/@?#:*\\]/u.test(text)) {
    throw new Error('invalid_host');
  }
  const hostname = new URL(`https://${text}/`).hostname.replace(/\.$/u, '');
  if (!hostname || hostname.length > 253) throw new Error('invalid_host');
  return hostname;
}

export function originsFor(profile) {
  return [`*://${profile.includeSubdomains ? '*.' : ''}${profile.host}/*`];
}

export function readProfile(form) {
  return {
    host: normalizedHost(form.elements.host.value),
    includeSubdomains: form.elements.includeSubdomains.checked,
    languageMode: form.elements.languageMode.value,
    language: form.elements.language.value.trim(),
  };
}

export function writeProfile(form, profile) {
  form.elements.host.value = profile.host;
  form.elements.includeSubdomains.checked = profile.includeSubdomains;
  form.elements.languageMode.value = profile.languageMode;
  form.elements.language.value = profile.language || '';
  updateLanguageField(form);
}

export function updateLanguageField(form) {
  const manual = form.elements.languageMode.value === 'manual';
  form.elements.language.disabled = !manual;
  form.elements.language.required = manual;
  if (form.elements.includeSubdomains) form.elements.includeSubdomains.disabled = form.elements.languageMode.value === 'inherit';
}

export function setBusy(form, busy) {
  form.setAttribute('aria-busy', String(busy));
  for (const button of form.querySelectorAll('button')) button.disabled = busy;
}

export function renderConnection(reply) {
  document.getElementById('connection').textContent = tr('standalone');
  document.getElementById('pending').hidden = !reply.state.pending;
}

export function renderWebRtc(reply) {
  const state = reply.state.webRtc;
  const drift = state?.enabled && !state?.owned;
  const active = state?.owned;
  const key = !reply.capabilities.webRtc ? 'webrtc_unavailable' : drift ? 'webrtc_drift' : active ? 'webrtc_owned' : 'webrtc_unchanged';
  const element = document.getElementById('webrtc-state');
  element.textContent = tr(key);
  element.dataset.tone = drift ? 'warning' : 'info';
}
