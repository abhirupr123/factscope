const BACKEND_URL = 'http://localhost:8000/analyze'; // your backend URL

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'analyze') {
    fetch(BACKEND_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(message.payload)
    }).then(r => r.json()).then(data => sendResponse(data)).catch(()=> sendResponse(null));
    return true;
  }
});
