const ONBOARDING_KEY = 'factscope_onboarding_complete_v1';
const resultEl = document.getElementById('last-result');
const scanButton = document.getElementById('scan-tab');
const onboarding = document.getElementById('onboarding');
const onboardingScanButton = document.getElementById('onboarding-scan');
const onboardingExploreButton = document.getElementById('onboarding-explore');
const mainView = document.getElementById('main-view');
const historyList = document.getElementById('history-list');
const historySection = document.getElementById('history-section');
const clearBtn = document.getElementById('clear-history');
const telemetryToggle = document.getElementById('telemetry-enabled');
const deleteServerDataBtn = document.getElementById('delete-server-data');
const privacyStatus = document.getElementById('privacy-status');

function showMainView() {
  onboarding.hidden = true;
  mainView.hidden = false;
}

function completeOnboarding(callback) {
  chrome.storage.local.set({ [ONBOARDING_KEY]: true }, () => {
    showMainView();
    if (callback) callback();
  });
}

chrome.storage.local.get(ONBOARDING_KEY, (data) => {
  const completed = data[ONBOARDING_KEY] === true;
  onboarding.hidden = completed;
  mainView.hidden = !completed;
});

const V1_RESULT_LABELS = {
  supported: 'Evidence supports claims',
  contradicted: 'Evidence contradicts claims',
  mixed: 'Mixed evidence',
  insufficient_evidence: 'Insufficient evidence',
  processing: 'Evidence processing',
  not_applicable: 'No factual verdict',
  no_indicators_detected: 'No clear manipulation indicators',
  possible_manipulation: 'Possible editing or compositing',
  likely_manipulated: 'Edited or composited image detected',
  likely_ai_generated: 'Likely AI-generated',
  uncertain: 'Uncertain',
};

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
    const status = entry.type === 'image' ? entry.manipulation_status : entry.evidence_status;
    const statusLabel = status ? (V1_RESULT_LABELS[status] || status.replace(/_/g, ' ')) : null;
    const confidence = status && entry.confidence ? ` (${entry.confidence} confidence)` : '';
    const label = escapeHTML(statusLabel ? `${statusLabel}${confidence}` : (VERDICT_LABELS[entry.verdict] || entry.verdict));
    const typeIcon = entry.type === 'image' ? '\uD83D\uDDBC' : '\uD83D\uDCC4';
    const title = escapeHTML(truncate(entry.title || entry.domain || 'Unknown', 38));
    const domain = escapeHTML(entry.domain || '');
    const url = safeHistoryURL(entry.url);

    return `<div class="history-item" data-url="${url}">
      <div class="history-score" title="Legacy score" style="border-color:${color};color:${color}">${Math.round(entry.score)}</div>
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
  usageBar.hidden = false;

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

async function startPageScan() {
  try {
    scanButton.disabled = true;
    resultEl.textContent = 'Preparing the scan…';
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab?.id) {
      resultEl.textContent = 'No active tab was found. Open a webpage and try again.';
      scanButton.disabled = false;
      return;
    }
    if (!/^https?:\/\//i.test(tab.url || '')) {
      resultEl.textContent = 'This browser page cannot be scanned. Open a regular webpage and try again.';
      resultEl.className = 'hint error';
      scanButton.disabled = false;
      return;
    }

    chrome.runtime.sendMessage({ type: 'start-page-scan', tabId: tab.id }, (response) => {
      scanButton.disabled = false;
      if (chrome.runtime.lastError || !response?.success) {
        resultEl.textContent = response?.error || 'FactScope cannot run on this page.';
        resultEl.className = 'hint error';
        return;
      }
      resultEl.className = 'hint';
      window.close();
    });
  } catch (err) {
    console.error('FactScope scan trigger failed:', err);
    scanButton.disabled = false;
    resultEl.textContent = 'Could not start the scan. Reload this page and try again.';
    resultEl.className = 'hint error';
  }
}

scanButton.addEventListener('click', startPageScan);
onboardingScanButton.addEventListener('click', () => completeOnboarding(startPageScan));
onboardingExploreButton.addEventListener('click', () => completeOnboarding(() => scanButton.focus()));

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
    'Delete scans, image scans, scan-access metadata, votes, flags, shares, telemetry, and tier data from the FactScope server? A minimal session and current quota record are retained temporarily to prevent abuse.'
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

/* Developer-only local evidence evaluation export (disabled in production).
const evaluationSection = document.getElementById('evaluation-section');
const evaluationCount = document.getElementById('evaluation-count');
const evaluationList = document.getElementById('evaluation-list');
const evaluationStatus = document.getElementById('evaluation-status');
const exportEvaluationBtn = document.getElementById('export-evaluation');
const clearEvaluationBtn = document.getElementById('clear-evaluation');
const disableEvaluationBtn = document.getElementById('disable-evaluation');

function runtimeMessage(message) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) resolve({ success: false, error: chrome.runtime.lastError.message });
      else resolve(response || {});
    });
  });
}

function renderEvaluationState(state) {
  if (!state?.enabled) {
    evaluationSection.hidden = true;
    return;
  }
  evaluationSection.hidden = false;
  const cases = Array.isArray(state.cases) ? state.cases : [];
  const sourceTotal = cases.reduce((sum, item) => sum + (item.source_count || 0), 0);
  evaluationCount.textContent = `${cases.length} case${cases.length === 1 ? '' : 's'} ready · ${sourceTotal} evidence link${sourceTotal === 1 ? '' : 's'}`;
  exportEvaluationBtn.disabled = cases.length === 0;
  clearEvaluationBtn.disabled = cases.length === 0;
  evaluationList.replaceChildren();

  for (const item of cases) {
    const row = document.createElement('div');
    row.className = 'evaluation-item';
    const info = document.createElement('div');
    info.className = 'evaluation-item-info';
    const publisher = document.createElement('span');
    publisher.className = 'evaluation-publisher';
    publisher.textContent = item.publisher || 'Unknown public publisher';
    const meta = document.createElement('span');
    meta.className = 'evaluation-meta';
    meta.textContent = `${item.modality === 'image' ? 'Image caption' : 'Article'} · ${item.claim_count} claims · ${item.source_count} links`;
    info.append(publisher, meta);
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'evaluation-remove';
    remove.textContent = 'Remove';
    remove.addEventListener('click', async () => {
      await runtimeMessage({ type: 'remove-evaluation-case', auditCaseId: item.audit_case_id });
      await refreshEvaluationState();
    });
    row.append(info, remove);
    evaluationList.append(row);
  }
}

async function refreshEvaluationState() {
  renderEvaluationState(await runtimeMessage({ type: 'get-evaluation-state' }));
}

exportEvaluationBtn.addEventListener('click', async () => {
  evaluationStatus.textContent = 'Preparing privacy-filtered JSONL...';
  const response = await runtimeMessage({ type: 'export-evaluation-cases' });
  if (!response?.success || !Array.isArray(response.cases) || !response.cases.length) {
    evaluationStatus.textContent = response?.error || 'No cases with displayed evidence are ready.';
    return;
  }
  const jsonl = `${response.cases.map((item) => JSON.stringify(item)).join('\n')}\n`;
  const blobUrl = URL.createObjectURL(new Blob([jsonl], { type: 'application/x-ndjson' }));
  const link = document.createElement('a');
  link.href = blobUrl;
  link.download = `factscope-evidence-${new Date().toISOString().slice(0, 10)}.jsonl`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
  evaluationStatus.textContent = `Exported ${response.cases.length} privacy-filtered cases.`;
});

clearEvaluationBtn.addEventListener('click', async () => {
  if (!window.confirm('Clear all locally captured evaluation cases? This cannot be undone.')) return;
  await runtimeMessage({ type: 'clear-evaluation-cases' });
  evaluationStatus.textContent = 'Local evaluation cases cleared.';
  await refreshEvaluationState();
});

disableEvaluationBtn.addEventListener('click', async () => {
  if (!window.confirm('Disable evaluation mode? Existing cases remain local until you clear them.')) return;
  await runtimeMessage({ type: 'disable-evaluation-mode' });
  evaluationSection.hidden = true;
});

// Developer-only evaluation UI. Uncomment locally together with evaluation_capture.js.
// void refreshEvaluationState();
*/
