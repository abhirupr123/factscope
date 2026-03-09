const resultEl = document.getElementById('last-result');
const scanButton = document.getElementById('scan-tab');
const historyList = document.getElementById('history-list');
const historySection = document.getElementById('history-section');
const clearBtn = document.getElementById('clear-history');

const VERDICT_LABELS = {
  authentic: 'Authentic',
  likely_authentic: 'Likely Authentic',
  uncertain: 'Uncertain',
  suspicious: 'Suspicious',
  ai_generated: 'AI Generated',
  likely_ai_generated: 'Likely AI-Generated',
  possibly_manipulated: 'Possibly Manipulated',
  phishing: 'Phishing Alert',
  error: 'Error',
};

function scoreColor(score) {
  if (score >= 70) return '#16a34a';
  if (score >= 40) return '#d97706';
  return '#dc2626';
}

function relativeTime(ts) {
  const diff = Math.floor((Date.now() - ts) / 1000);
  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
  return new Date(ts).toLocaleDateString();
}

function truncate(str, len) {
  if (!str) return '';
  return str.length > len ? str.slice(0, len) + '\u2026' : str;
}

function renderHistory(history) {
  if (!history || history.length === 0) {
    historySection.style.display = 'none';
    return;
  }

  historySection.style.display = 'block';
  historyList.innerHTML = history.map((entry) => {
    const color = scoreColor(entry.score);
    const label = VERDICT_LABELS[entry.verdict] || entry.verdict;
    const typeIcon = entry.type === 'image' ? '\uD83D\uDDBC' : '\uD83D\uDCC4';
    const title = truncate(entry.title || entry.domain || 'Unknown', 38);
    const domain = entry.domain || '';

    return `<div class="history-item" data-url="${entry.url || ''}">
      <div class="history-score" style="border-color:${color};color:${color}">${Math.round(entry.score)}</div>
      <div class="history-info">
        <span class="history-item-title">${typeIcon} ${title}</span>
        <span class="history-meta">${label} \u00b7 ${domain ? domain + ' \u00b7 ' : ''}${relativeTime(entry.timestamp)}</span>
      </div>
    </div>`;
  }).join('');

  historyList.querySelectorAll('.history-item').forEach((item) => {
    item.addEventListener('click', () => {
      const url = item.dataset.url;
      if (url) chrome.tabs.create({ url });
    });
  });
}

chrome.storage.local.get('factscope_history', (data) => {
  renderHistory(data.factscope_history);
});

clearBtn.addEventListener('click', () => {
  chrome.storage.local.remove('factscope_history', () => {
    renderHistory([]);
  });
});

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
    resultEl.textContent = 'Could not trigger the scan. Check permissions and reload the page.';
  }
});
