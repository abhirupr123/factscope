const PROD_BASE = 'https://factscope-api.onrender.com';
const DEV_BASE = 'http://localhost:8000';

let API_BASE = PROD_BASE;

const _apiReady = (async () => {
  try {
    const resp = await fetch(`${DEV_BASE}/models/info`, { signal: AbortSignal.timeout(1500) });
    if (resp.ok) { API_BASE = DEV_BASE; return; }
  } catch { /* dev server not running */ }
  API_BASE = PROD_BASE;
})();

function getUserId() {
  return new Promise((resolve) => {
    chrome.storage.local.get('factscope_user_id', (data) => {
      if (data.factscope_user_id) {
        resolve(data.factscope_user_id);
      } else {
        const id = crypto.randomUUID();
        chrome.storage.local.set({ factscope_user_id: id });
        resolve(id);
      }
    });
  });
}

/* ── Context menu for image verification ──────────────────────────── */

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'factscope-verify-image',
    title: 'Verify image with FactScope',
    contexts: ['image'],
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'factscope-verify-image' && info.srcUrl) {
    chrome.tabs.sendMessage(tab.id, {
      type: 'factscope-verify-image-start',
      imageUrl: info.srcUrl,
      pageUrl: info.pageUrl || tab.url,
    });
  }
});

/* ── Message routing ──────────────────────────────────────────────── */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'analyze') {
    (async () => {
      await _apiReady;
      const userId = await getUserId();
      const payload = { ...message.payload, user_id: userId };
      try {
        const r = await fetch(`${API_BASE}/analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        const data = await r.json();
        sendResponse(data);
      } catch (err) {
        console.error('FactScope backend error:', err);
        sendResponse({
          trust_score: 0,
          verdict: 'error',
          explanation: `Could not reach the FactScope backend. (${err.message})`,
          evidence: [],
        });
      }
    })();
    return true;
  }

  if (message.type === 'verify-image') {
    (async () => {
      await _apiReady;
      const userId = await getUserId();
      const payload = { ...message.payload, user_id: userId };
      try {
        const r = await fetch(`${API_BASE}/analyze/verify-image`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        const data = await r.json();
        sendResponse(data);
      } catch (err) {
        console.error('FactScope image verify error:', err);
        sendResponse({
          authenticity_score: 0,
          verdict: 'error',
          explanation: `Could not reach the FactScope backend. (${err.message})`,
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
        const r = await fetch(`${API_BASE}/claims/${encodeURIComponent(message.fingerprint)}`);
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
      const userId = await getUserId();
      try {
        const r = await fetch(`${API_BASE}/flag`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            fingerprint: message.fingerprint,
            user_id: userId,
            reason: message.reason || null,
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
});
