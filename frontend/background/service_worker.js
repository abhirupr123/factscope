const PROD_BASE = 'https://factscope-api.onrender.com';
const DEV_BASE = 'http://localhost:8000';

let API_BASE = PROD_BASE;

const _apiReady = (async () => {
  try {
    const resp = await fetch(`${DEV_BASE}/health`, { signal: AbortSignal.timeout(1500) });
    if (resp.ok) { API_BASE = DEV_BASE; return; }
  } catch { /* dev server not running */ }
  API_BASE = PROD_BASE;
})();

const SESSION_TOKEN_KEY = 'factscope_session_token';
const SESSION_EXPIRY_KEY = 'factscope_session_expires_at';
const TELEMETRY_ENABLED_KEY = 'factscope_telemetry_enabled';
const HISTORY_KEY = 'factscope_history';
let _sessionPromise = null;

function storageGet(keys) {
  return new Promise((resolve) => {
    chrome.storage.local.get(keys, resolve);
  });
}

function storageSet(values) {
  return new Promise((resolve) => chrome.storage.local.set(values, resolve));
}

function storageRemove(keys) {
  return new Promise((resolve) => chrome.storage.local.remove(keys, resolve));
}

async function getSessionToken(forceRefresh = false) {
  await _apiReady;
  if (!forceRefresh) {
    const stored = await storageGet([SESSION_TOKEN_KEY, SESSION_EXPIRY_KEY]);
    const expiresAt = Date.parse(stored[SESSION_EXPIRY_KEY] || '');
    if (stored[SESSION_TOKEN_KEY] && expiresAt > Date.now() + 5 * 60 * 1000) {
      return stored[SESSION_TOKEN_KEY];
    }
    if (_sessionPromise) return _sessionPromise;
  } else {
    await storageRemove([SESSION_TOKEN_KEY, SESSION_EXPIRY_KEY]);
  }

  _sessionPromise = (async () => {
    const response = await fetch(`${API_BASE}/v1/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!response.ok) throw new Error(`Session service returned ${response.status}`);
    const session = await response.json();
    if (!session.access_token || !session.expires_at) throw new Error('Invalid session response');
    await storageSet({
      [SESSION_TOKEN_KEY]: session.access_token,
      [SESSION_EXPIRY_KEY]: session.expires_at,
    });
    return session.access_token;
  })();

  try {
    return await _sessionPromise;
  } finally {
    _sessionPromise = null;
  }
}

async function apiFetch(path, options = {}, retryAuth = true) {
  const token = await getSessionToken();
  const headers = new Headers(options.headers || {});
  headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (response.status === 401 && retryAuth) {
    await getSessionToken(true);
    return apiFetch(path, options, false);
  }
  return response;
}

async function recordTelemetry(event) {
  const allowedEvents = new Set([
    'page_scan_completed',
    'image_scan_completed',
    'scan_failed',
    'history_cleared',
  ]);
  if (!allowedEvents.has(event)) return;
  const stored = await storageGet([TELEMETRY_ENABLED_KEY]);
  if (stored[TELEMETRY_ENABLED_KEY] !== true) return;
  try {
    await apiFetch('/v1/telemetry', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event }),
    });
  } catch {
    // Telemetry is best-effort and never affects product behavior.
  }
}

function sendTabMessage(tabId, message) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(response);
      }
    });
  });
}

async function ensureFactScopeInjected(tabId) {
  try {
    const response = await sendTabMessage(tabId, { type: 'factscope-ping' });
    if (response?.ready) return;
  } catch {
    // The page has not received the action-triggered script yet.
  }
  await chrome.scripting.insertCSS({ target: { tabId }, files: ['content/overlay.css'] });
  await chrome.scripting.executeScript({ target: { tabId }, files: ['content/content_script.js'] });
}

async function startPageScan(tabId) {
  await ensureFactScopeInjected(tabId);
  await sendTabMessage(tabId, { type: 'factscope-start-page-scan' });
}

/* ── Context menu for image verification ──────────────────────────── */

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'factscope-verify-image',
    title: 'Verify image with FactScope',
    contexts: ['image'],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'factscope-verify-image' && info.srcUrl) {
    try {
      await ensureFactScopeInjected(tab.id);
      await sendTabMessage(tab.id, {
        type: 'factscope-verify-image-start',
        imageUrl: info.srcUrl,
        pageUrl: info.pageUrl || tab.url,
      });
    } catch (error) {
      console.warn('FactScope cannot run on this page:', error.message);
    }
  }
});

/* ── Badge indicator ──────────────────────────────────────────────── */

function updateBadge(tabId, score) {
  const text = String(Math.round(score));
  const color = score >= 70 ? '#22c55e' : score >= 40 ? '#f59e0b' : '#ef4444';
  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeTextColor({ color: '#ffffff', tabId });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    chrome.action.setBadgeText({ text: '', tabId });
  }
});

/* ── Scan history helpers ────────────────────────────────────────── */

const MAX_HISTORY = 15;

function saveHistoryEntry(entry) {
  chrome.storage.local.get(HISTORY_KEY, (data) => {
    const history = data[HISTORY_KEY] || [];
    history.unshift(entry);
    if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
    chrome.storage.local.set({ [HISTORY_KEY]: history });
  });
}

/* ── Message routing ──────────────────────────────────────────────── */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'start-page-scan') {
    (async () => {
      try {
        await startPageScan(message.tabId);
        sendResponse({ success: true });
      } catch {
        sendResponse({ success: false, error: 'FactScope cannot run on this page.' });
      }
    })();
    return true;
  }

  if (message.type === 'update-badge') {
    const tabId = sender.tab?.id;
    if (tabId && typeof message.score === 'number') {
      updateBadge(tabId, message.score);
    }
    return false;
  }

  if (message.type === 'analyze') {
    (async () => {
      await _apiReady;
      const payload = { ...message.payload };
      try {
        const r = await apiFetch('/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (r.status === 429) {
          const rl = await r.json();
          sendResponse({
            trust_score: 0,
            verdict: 'rate_limited',
            explanation: `Daily scan limit reached (${rl.used}/${rl.limit}). Resets at midnight UTC.`,
            evidence: [],
            rate_limit: rl,
          });
          return;
        }
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        const data = await r.json();
        if (data.verdict !== 'error') {
          const url = payload.url || sender.tab?.url || '';
          let domain = '';
          try { domain = new URL(url).hostname; } catch {}
          saveHistoryEntry({
            url,
            title: payload.title || sender.tab?.title || domain,
            domain,
            score: data.trust_score,
            verdict: data.verdict,
            type: 'page',
            timestamp: Date.now(),
          });
        }
        sendResponse(data);
        void recordTelemetry('page_scan_completed');
      } catch (err) {
        console.error('FactScope backend error:', err);
        void recordTelemetry('scan_failed');
        sendResponse({
          trust_score: 50,
          verdict: 'unknown',
          explanation: 'FactScope could not complete the analysis. Please try again.',
          evidence: [],
        });
      }
    })();
    return true;
  }

  if (message.type === 'verify-image') {
    (async () => {
      await _apiReady;
      const payload = { ...message.payload };
      try {
        const r = await apiFetch('/analyze/verify-image', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (r.status === 429) {
          const rl = await r.json();
          sendResponse({
            authenticity_score: 0,
            verdict: 'rate_limited',
            explanation: `Daily scan limit reached (${rl.used}/${rl.limit}). Resets at midnight UTC.`,
            evidence: [],
            rate_limit: rl,
          });
          return;
        }
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        const data = await r.json();
        if (data.verdict !== 'error') {
          const pageUrl = payload.page_url || sender.tab?.url || '';
          let domain = '';
          try { domain = new URL(pageUrl).hostname; } catch {}
          saveHistoryEntry({
            url: pageUrl,
            title: sender.tab?.title || domain,
            domain,
            score: data.authenticity_score,
            verdict: data.verdict,
            type: 'image',
            timestamp: Date.now(),
          });
        }
        sendResponse(data);
        void recordTelemetry('image_scan_completed');
      } catch (err) {
        console.error('FactScope image verify error:', err);
        void recordTelemetry('scan_failed');
        sendResponse({
          authenticity_score: 50,
          verdict: 'uncertain',
          explanation: 'FactScope could not complete the image analysis. Please try again.',
          evidence: [],
        });
      }
    })();
    return true;
  }

  if (message.type === 'get-claims') {
    (async () => {
      await _apiReady;
      try {
        const r = await apiFetch(`/claims/${encodeURIComponent(message.fingerprint)}`);
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        sendResponse(await r.json());
      } catch (err) {
        sendResponse({ pending: true, fact_checks: null });
      }
    })();
    return true;
  }

  if (message.type === 'flag-content') {
    (async () => {
      await _apiReady;
      try {
        const r = await apiFetch('/flag', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            fingerprint: message.fingerprint,
            category: message.category,
            justification: message.justification,
            source_urls: message.source_urls || null,
          }),
        });
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        const data = await r.json();
        sendResponse(data);
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }

  if (message.type === 'vote') {
    (async () => {
      await _apiReady;
      try {
        const r = await apiFetch('/vote', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            fingerprint: message.fingerprint,
            vote: message.vote,
          }),
        });
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        sendResponse(await r.json());
      } catch (err) {
        sendResponse({ success: false });
      }
    })();
    return true;
  }

  if (message.type === 'get-community-notes') {
    (async () => {
      await _apiReady;
      try {
        const r = await apiFetch(`/community-notes/${encodeURIComponent(message.fingerprint)}`);
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        sendResponse(await r.json());
      } catch (err) {
        sendResponse({ notes: [], vote_stats: { likes: 0, dislikes: 0 }, flag_count: 0 });
      }
    })();
    return true;
  }

  if (message.type === 'get-usage') {
    (async () => {
      await _apiReady;
      try {
        const r = await apiFetch('/user/usage');
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        sendResponse(await r.json());
      } catch (err) {
        sendResponse({ error: err.message });
      }
    })();
    return true;
  }

  if (message.type === 'redeem-key') {
    (async () => {
      await _apiReady;
      try {
        const r = await apiFetch('/redeem-key', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key: message.key }),
        });
        const data = await r.json();
        sendResponse(data);
      } catch (err) {
        sendResponse({ error: err.message });
      }
    })();
    return true;
  }

  if (message.type === 'share-result') {
    (async () => {
      await _apiReady;
      try {
        const r = await apiFetch('/share', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(message.payload),
        });
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        sendResponse(await r.json());
      } catch (err) {
        sendResponse({ error: err.message });
      }
    })();
    return true;
  }

  if (message.type === 'record-telemetry') {
    void recordTelemetry(message.event);
    sendResponse({ success: true });
    return false;
  }

  if (message.type === 'delete-server-data') {
    (async () => {
      try {
        const response = await apiFetch('/v1/data', { method: 'DELETE' });
        const data = await response.json();
        if (!response.ok) {
          sendResponse({ success: false, error: data.message || 'Deletion failed.' });
          return;
        }
        await storageRemove([HISTORY_KEY]);
        sendResponse({ success: true, deleted: data.deleted || {} });
      } catch {
        sendResponse({ success: false, error: 'Could not delete server data. Please try again.' });
      }
    })();
    return true;
  }
});

if (globalThis.__FACTSCOPE_SESSION_TEST__) {
  globalThis.__FACTSCOPE_SESSION__ = { apiFetch, getSessionToken };
}
