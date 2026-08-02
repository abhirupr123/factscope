const resultEl = document.getElementById('last-result');
const scanButton = document.getElementById('scan-tab');
const historyList = document.getElementById('history-list');
const historySection = document.getElementById('history-section');
const clearBtn = document.getElementById('clear-history');
const telemetryToggle = document.getElementById('telemetry-enabled');
const deleteServerDataBtn = document.getElementById('delete-server-data');
const privacyStatus = document.getElementById('privacy-status');

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

function escapeHTML(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function safeHistoryURL(value) {
  try {
    const parsed = new URL(String(value ?? ''));
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return '';
    if (parsed.username || parsed.password) return '';
    return escapeHTML(parsed.href);
  } catch {
    return '';
  }
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
    const label = escapeHTML(VERDICT_LABELS[entry.verdict] || entry.verdict);
    const typeIcon = entry.type === 'image' ? '\uD83D\uDDBC' : '\uD83D\uDCC4';
    const title = escapeHTML(truncate(entry.title || entry.domain || 'Unknown', 38));
    const domain = escapeHTML(entry.domain || '');
    const url = safeHistoryURL(entry.url);

    return `<div class="history-item" data-url="${url}">
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

/* ── Usage bar ──────────────────────────────────────────────────── */

const usageBar = document.getElementById('usage-bar');
const usageTier = document.getElementById('usage-tier');
const usageText = document.getElementById('usage-text');
const usageFill = document.getElementById('usage-fill');

function updateUsageUI(info) {
  if (!info || info.error) return;
  usageBar.style.display = 'block';

  usageTier.textContent = info.tier;
  usageTier.className = 'tier-badge ' + info.tier;

  const used = info.used || 0;
  const limit = info.limit || 10;
  const remaining = info.remaining ?? (limit - used);
  usageText.textContent = `${used}/${limit} scans today`;

  const pct = Math.min(100, (used / limit) * 100);
  usageFill.style.width = pct + '%';
  usageFill.className = 'progress-fill' +
    (pct >= 90 ? ' danger' : pct >= 70 ? ' warning' : '');
}

chrome.runtime.sendMessage({ type: 'get-usage' }, updateUsageUI);

clearBtn.addEventListener('click', () => {
  chrome.storage.local.remove('factscope_history', () => {
    renderHistory([]);
    chrome.runtime.sendMessage({ type: 'record-telemetry', event: 'history_cleared' });
  });
});

scanButton.addEventListener('click', async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab?.id) {
      resultEl.textContent = 'No active tab found.';
      return;
    }

    chrome.runtime.sendMessage({ type: 'start-page-scan', tabId: tab.id }, (response) => {
      if (chrome.runtime.lastError || !response?.success) {
        resultEl.textContent = response?.error || 'FactScope cannot run on this page.';
        return;
      }
      window.close();
    });
  } catch (err) {
    console.error('FactScope scan trigger failed:', err);
    resultEl.textContent = 'Could not trigger the scan. Check permissions and reload the page.';
  }
});

chrome.storage.local.get('factscope_telemetry_enabled', (data) => {
  telemetryToggle.checked = data.factscope_telemetry_enabled === true;
});

telemetryToggle.addEventListener('change', () => {
  chrome.storage.local.set({ factscope_telemetry_enabled: telemetryToggle.checked });
  privacyStatus.textContent = telemetryToggle.checked
    ? 'Anonymous telemetry enabled.'
    : 'Anonymous telemetry disabled.';
  privacyStatus.className = 'privacy-status';
});

deleteServerDataBtn.addEventListener('click', () => {
  const confirmed = window.confirm(
    'Delete scans, image scans, votes, flags, shares, telemetry, and tier data from the FactScope server? A minimal session and current quota record are retained temporarily to prevent abuse.'
  );
  if (!confirmed) return;
  deleteServerDataBtn.disabled = true;
  privacyStatus.textContent = 'Deleting server data...';
  privacyStatus.className = 'privacy-status';
  chrome.runtime.sendMessage({ type: 'delete-server-data' }, (response) => {
    deleteServerDataBtn.disabled = false;
    if (response?.success) {
      renderHistory([]);
      privacyStatus.textContent = 'Server data and local scan history deleted.';
      privacyStatus.className = 'privacy-status';
    } else {
      privacyStatus.textContent = response?.error || 'Deletion failed. Please try again.';
      privacyStatus.className = 'privacy-status error';
    }
  });
});

/* ── License key redemption ─────────────────────────────────────── */

const redeemBtn = document.getElementById('redeem-btn');
const licenseInput = document.getElementById('license-key');
const redeemMsg = document.getElementById('redeem-msg');

redeemBtn?.addEventListener('click', () => {
  const key = licenseInput.value.trim();
  if (!key) return;

  redeemBtn.disabled = true;
  redeemBtn.textContent = '...';
  redeemMsg.textContent = '';
  redeemMsg.className = 'redeem-msg';

  chrome.runtime.sendMessage({ type: 'redeem-key', key }, (resp) => {
    redeemBtn.disabled = false;
    redeemBtn.textContent = 'Activate';

    if (resp?.success) {
      redeemMsg.textContent = `Upgraded to ${resp.tier}!`;
      redeemMsg.className = 'redeem-msg success';
      licenseInput.value = '';
      chrome.runtime.sendMessage({ type: 'get-usage' }, updateUsageUI);
    } else {
      redeemMsg.textContent = resp?.message || 'Invalid or used key.';
      redeemMsg.className = 'redeem-msg error';
    }
  });
});