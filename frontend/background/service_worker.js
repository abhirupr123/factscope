const BACKEND_URL = 'http://localhost:8000/analyze';
const IMAGE_VERIFY_URL = 'http://localhost:8000/analyze/verify-image';

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
    fetch(BACKEND_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(message.payload),
    })
      .then((r) => {
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        return r.json();
      })
      .then((data) => sendResponse(data))
      .catch((err) => {
        console.error('FactScope backend error:', err);
        sendResponse({
          trust_score: 0,
          verdict: 'error',
          explanation: `Could not reach the FactScope backend. Make sure it is running on localhost:8000. (${err.message})`,
          evidence: [],
        });
      });

    return true;
  }

  if (message.type === 'verify-image') {
    fetch(IMAGE_VERIFY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(message.payload),
    })
      .then((r) => {
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        return r.json();
      })
      .then((data) => sendResponse(data))
      .catch((err) => {
        console.error('FactScope image verify error:', err);
        sendResponse({
          authenticity_score: 0,
          verdict: 'error',
          explanation: `Could not reach the FactScope backend. (${err.message})`,
          evidence: [],
        });
      });

    return true;
  }
});
