const resultEl = document.getElementById('last-result');
const scanButton = document.getElementById('scan-tab');

scanButton.addEventListener('click', async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab?.id) {
      resultEl.textContent = 'No active tab found.';
      return;
    }

    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => window.dispatchEvent(new CustomEvent('factscope-scan')),
    });

    window.close();
  } catch (err) {
    console.error('FactScope scan trigger failed:', err);
    setStatus('Error', 'error');
    resultEl.textContent = 'Could not trigger the scan. Check permissions and reload the page.';
  }
});
