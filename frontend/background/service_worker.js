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
  chrome.storage.local.get('factscope_history', (data) => {
    const history = data.factscope_history || [];
    history.unshift(entry);
    if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
    chrome.storage.local.set({ factscope_history: history });
  });
}

/* ── Message routing ──────────────────────────────────────────────── */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
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
      const userId = await getUserId();
      try {
        const r = await fetch(`${API_BASE}/vote`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            fingerprint: message.fingerprint,
            user_id: userId,
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
        const r = await fetch(`${API_BASE}/community-notes/${encodeURIComponent(message.fingerprint)}`);
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        sendResponse(await r.json());
      } catch (err) {
        sendResponse({ notes: [], vote_stats: { likes: 0, dislikes: 0 }, flag_count: 0 });
      }
    })();
    return true;
  }

  if (message.type === 'share-result') {
    (async () => {
      await _apiReady;
      try {
        const r = await fetch(`${API_BASE}/share`, {
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
});
