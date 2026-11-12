const STATE_KEY = 'profilesV1';
const MAX_PROFILES = 100;
const MODES = { inherit: 0, system: 1, manual: 2, route: 3 };
const WEBRTC_POLICY = 'disable_non_proxied_udp';
const RESOURCE_TYPES = ['main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font', 'object', 'xmlhttprequest', 'ping', 'media', 'websocket', 'other'];

function fail(code) {
  throw new Error(code);
}

export function normalizeHost(value) {
  if (typeof value !== 'string' || value.length > 253 || !value || /[\s/:?#@\\*]/u.test(value)) {
    fail('invalid_host');
  }
  let host;
  try {
    host = new URL(`https://${value}`).hostname.replace(/\.$/u, '');
  } catch {
    fail('invalid_host');
  }
  if (!host || host.length > 253 || !host.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))) {
    fail('invalid_host');
  }
  return host;
}

function language(value) {
  if (typeof value !== 'string' || value.length > 64 || !/^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$/u.test(value)) {
    fail('invalid_language');
  }
  try {
    return Intl.getCanonicalLocales(value)[0];
  } catch {
    return fail('invalid_language');
  }
}

function settings(value, site = false) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('invalid_request');
  const mode = value.languageMode;
  if (!Object.hasOwn(MODES, mode) || (!site && mode === 'inherit')) fail('invalid_request');
  const result = { languageMode: mode, language: mode === 'manual' ? language(value.language) : 'en' };
  if (site) {
    if (typeof value.includeSubdomains !== 'boolean') fail('invalid_request');
    result.host = normalizeHost(value.host);
    result.includeSubdomains = value.includeSubdomains;
  }
  return result;
}

export function emptyState() {
  return {
    schemaVersion: 1, revision: 0,
    global: { languageMode: 'system', language: 'en' }, profiles: [],
    webRtc: { owned: false, enabled: false }, pending: false,
    pendingLanguage: false, pendingWebRtc: false,
  };
}

export function validateState(value) {
  if (!value || value.schemaVersion !== 1 || !Number.isSafeInteger(value.revision) || value.revision < 0
      || !Array.isArray(value.profiles) || value.profiles.length > MAX_PROFILES
      || typeof value.pending !== 'boolean' || typeof value.webRtc?.owned !== 'boolean'
      || typeof value.webRtc?.enabled !== 'boolean'
      || (value.pendingLanguage !== undefined && typeof value.pendingLanguage !== 'boolean')
      || (value.pendingWebRtc !== undefined && typeof value.pendingWebRtc !== 'boolean')) fail('storage_corrupt');
  const profiles = value.profiles.map(profile => settings(profile, true));
  if (new Set(profiles.map(profile => profile.host)).size !== profiles.length) fail('storage_corrupt');
  return {
    schemaVersion: 1, revision: value.revision, global: settings(value.global), profiles,
    webRtc: { owned: value.webRtc.owned, enabled: value.webRtc.enabled }, pending: value.pending,
    pendingLanguage: value.pendingLanguage ?? value.pending,
    pendingWebRtc: value.pendingWebRtc ?? false,
  };
}

function hostRegex(host, includeSubdomains) {
  const escaped = host.replace(/\./gu, '\\.');
  const prefix = includeSubdomains ? '(?:[a-z0-9-]+\\.)*' : '';
  return `^https?://${prefix}${escaped}\\.?(?::[0-9]+)?/`;
}

export function buildLanguageRules(state, resolveMode) {
  const rules = [];
  const add = (profile, priority, condition, isSite) => {
    const mode = resolveMode(isSite ? MODES[profile.languageMode] : 0, MODES[state.global.languageMode], 1, 0, 1);
    if (![1, 2].includes(mode)) fail(mode === 5 ? 'route_unavailable' : 'unsupported');
    if (mode === 1 && !isSite) return;
    const selectedLanguage = profile.languageMode === 'inherit' ? state.global.language : profile.language;
    const action = mode === 1
      ? { type: 'allow' }
      : { type: 'modifyHeaders', requestHeaders: [{ header: 'accept-language', operation: 'set', value: selectedLanguage }] };
    rules.push({ id: rules.length + 1, priority, action, condition: { ...condition, resourceTypes: RESOURCE_TYPES } });
  };
  add(state.global, 1, { regexFilter: '^https?://' }, false);
  for (const profile of state.profiles) {
    if (profile.languageMode === 'inherit') continue;
    const depth = profile.host.split('.').length;
    add(profile, depth * 2 + (profile.includeSubdomains ? 0 : 1), {
      regexFilter: hostRegex(profile.host, profile.includeSubdomains),
      isUrlFilterCaseSensitive: false,
    }, true);
  }
  return rules;
}

export function createController(api, resolveMode, capabilities = { webRtc: true }) {
  let queue = Promise.resolve();
  async function read() {
    const data = await api.storage.local.get(STATE_KEY);
    if (!Object.hasOwn(data, STATE_KEY)) return emptyState();
    try {
      return validateState(data[STATE_KEY]);
    } catch {
      return fail('storage_corrupt');
    }
  }
  async function write(state) {
    try {
      await api.storage.local.set({ [STATE_KEY]: state });
    } catch {
      fail('storage_failed');
    }
  }
  async function ensurePermissions(state) {
    const origins = [];
    if (state.pendingLanguage) {
      if (state.global.languageMode === 'manual') origins.push('*://*/*');
      for (const profile of state.profiles) {
        if (profile.languageMode === 'manual' || (profile.languageMode === 'inherit' && state.global.languageMode === 'manual')) {
          origins.push(`*://${profile.includeSubdomains ? '*.' : ''}${profile.host}/*`);
        }
      }
    }
    if (origins.length && !await api.permissions.contains({ origins })) fail('permission_required');
    if (state.pendingWebRtc && state.webRtc.enabled && !await api.permissions.contains({ permissions: ['privacy'] })) fail('permission_required');
  }
  async function apply(state, scopes = { language: state.pendingLanguage, webRtc: state.pendingWebRtc }) {
    await ensurePermissions({ ...state, pendingLanguage: scopes.language, pendingWebRtc: scopes.webRtc });
    if (state.pendingLanguage && scopes.language) {
      const rules = buildLanguageRules(state, resolveMode);
      const currentRules = await api.declarativeNetRequest.getDynamicRules();
      await api.declarativeNetRequest.updateDynamicRules({ removeRuleIds: currentRules.map(rule => rule.id), addRules: rules });
      state.pendingLanguage = false;
      state.pending = state.pendingWebRtc;
      await write(state);
    }
    const setting = api.privacy?.network?.webRTCIPHandlingPolicy;
    if (state.pendingWebRtc && scopes.webRtc) {
      if (!capabilities.webRtc) fail('unsupported');
      if (!setting) fail('unsupported');
      const current = await setting.get({});
      if (state.webRtc.enabled) {
        if (!['controllable_by_this_extension', 'controlled_by_this_extension'].includes(current.levelOfControl)) fail('conflict');
        await setting.set({ value: WEBRTC_POLICY, scope: 'regular' });
        const applied = await setting.get({});
        if (applied.value !== WEBRTC_POLICY || applied.levelOfControl !== 'controlled_by_this_extension') fail('apply_failed');
        state.webRtc.owned = true;
      } else {
        if (current.levelOfControl === 'controlled_by_this_extension' && current.value === WEBRTC_POLICY) {
          await setting.clear({ scope: 'regular' });
        }
        state.webRtc.owned = false;
      }
      state.pendingWebRtc = false;
    }
    state.pending = state.pendingLanguage || state.pendingWebRtc;
    await write(state);
  }
  async function execute(message, sender) {
    const trustedUrls = ['ui/popup.html', 'ui/options.html'].map(path => api.runtime.getURL(path));
    if (sender?.id !== api.runtime.id || sender.origin === 'null'
        || !trustedUrls.some(url => sender.url === url || sender.url?.startsWith(`${url}?`))) fail('untrusted_sender');
    if (!message || typeof message !== 'object' || typeof message.type !== 'string') fail('invalid_request');
    const state = await read();
    if (message.type === 'getState') {
      const setting = api.privacy?.network?.webRTCIPHandlingPolicy;
      if (state.webRtc.owned) {
        try {
          const current = setting && await setting.get({});
          state.webRtc.owned = current?.value === WEBRTC_POLICY && current.levelOfControl === 'controlled_by_this_extension';
        } catch {
          state.webRtc.owned = false;
        }
      }
      return { ok: true, state, integration: 'standalone', capabilities: {
        language: true, timezone: false, route: false,
        webRtc: capabilities.webRtc,
      } };
    }
    if (message.confirmed !== true) fail('consent_required');
    if (message.baseRevision !== state.revision) fail('conflict');
    switch (message.type) {
      case 'saveProfile': {
        const profile = settings(message.profile, true);
        if (profile.languageMode === 'inherit') {
          state.profiles = state.profiles.filter(item => item.host !== profile.host);
          break;
        }
        const index = state.profiles.findIndex(item => item.host === profile.host);
        if (index < 0) {
          if (state.profiles.length >= MAX_PROFILES) fail('too_many_profiles');
          state.profiles.push(profile);
        } else state.profiles[index] = profile;
        break;
      }
      case 'deleteProfile':
        state.profiles = state.profiles.filter(profile => profile.host !== normalizeHost(message.host));
        break;
      case 'saveGlobal':
        state.global = settings(message.global);
        break;
      case 'setWebRtc':
        if (!capabilities.webRtc) fail('unsupported');
        if (typeof message.enabled !== 'boolean') fail('invalid_request');
        state.webRtc.enabled = message.enabled;
        break;
      default:
        fail('invalid_request');
    }
    buildLanguageRules(state, resolveMode);
    const scopes = { language: message.type !== 'setWebRtc', webRtc: message.type === 'setWebRtc' };
    if (scopes.webRtc) state.pendingWebRtc = true;
    else state.pendingLanguage = true;
    await ensurePermissions({ ...state, pendingLanguage: scopes.language, pendingWebRtc: scopes.webRtc });
    if (state.revision === Number.MAX_SAFE_INTEGER) fail('invalid_state');
    state.revision += 1;
    state.pending = true;
    // Persist the requested state before touching browser settings so interruption is recoverable.
    await write(state);
    try {
      await apply(state, scopes);
    } catch {
      fail('apply_failed');
    }
    return { ok: true };
  }
  function serialize(work) {
    const result = queue.then(work);
    queue = result.catch(() => {});
    return result;
  }
  return {
    handle: (message, sender) => serialize(() => execute(message, sender)),
    recover: () => serialize(async () => {
      const state = await read();
      if (state.pending) await apply(state);
    }),
  };
}
