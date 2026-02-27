const BACKEND_URL = 'http://localhost:8000/analyze';

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

    return true; // keep channel open for async sendResponse
  }
});
