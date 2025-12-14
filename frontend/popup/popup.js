const statusEl = document.getElementById('status');
const resultEl = document.getElementById('last-result');
const scanButton = document.getElementById('scan-tab');

const setStatus = (text, variant = 'idle') => {
  statusEl.textContent = text;
  statusEl.className = `pill pill-${variant}`;
};

scanButton.addEventListener('click', async () => {
  setStatus('Requesting...', 'active');
  resultEl.textContent = 'Looking at the current tab...';

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => window.dispatchEvent(new CustomEvent('factscope-scan'))
    });

    setStatus('Scanning', 'done');
    resultEl.textContent = 'Badges will refresh on the page you just scanned.';
  } catch (err) {
    console.error('FactScope scan trigger failed:', err);
    setStatus('Error', 'error');
    resultEl.textContent = 'Could not trigger the scan. Check permissions and reload.';
  }
});
