(() => {
  const SCAN_EVENT = 'factscope-scan';

  /* ── Communication with service worker ────────────────────────────── */

  function analyzePayload(payload) {
    return new Promise((resolve) => {
      if (!chrome.runtime?.id) {
        resolve({
          trust_score: 0,
          verdict: 'error',
          explanation: 'Extension was reloaded. Please refresh this page (Ctrl+R) and try again.',
          evidence: [],
        });
        return;
      }
      chrome.runtime.sendMessage({ type: 'analyze', payload }, (response) => {
        if (chrome.runtime.lastError) {
          resolve({
            trust_score: 0,
            verdict: 'error',
            explanation: 'Lost connection to FactScope. Please refresh this page (Ctrl+R) and try again.',
            evidence: [],
          });
          return;
        }
        resolve(response);
      });
    });
  }

  /* ── Page content extraction ──────────────────────────────────────── */

  function extractPageContent() {
    const title = document.title || '';
    const url = window.location.href;

    const clone = document.body.cloneNode(true);
    clone.querySelectorAll('script, style, nav, footer, header, iframe, noscript, aside, [role="banner"], [role="navigation"]').forEach((el) => el.remove());

    const lines = clone.innerText
      ?.split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 2);
    const text = (lines || []).join('\n').substring(0, 2500);

    const links = [
      ...new Set(
        Array.from(document.querySelectorAll('a[href]'))
          .map((a) => a.href)
          .filter((h) => h.startsWith('http'))
          .slice(0, 10),
      ),
    ];

    return {
      text: `URL: ${url}\nPage title: ${title}\n\n${text}`,
      links,
      sample_img: null,
    };
  }

  /* ── UI helpers ───────────────────────────────────────────────────── */

  function removePanel() {
    const existing = document.getElementById('factscope-panel');
    if (existing) existing.remove();
  }

  function scoreColor(score) {
    if (score > 70) return '#10b981';
    if (score > 40) return '#f59e0b';
    return '#ef4444';
  }

  const VERDICT_LABELS = {
    authentic: 'Authentic',
    misleading: 'Potentially Misleading',
    ai_generated: 'Likely AI-Generated',
    spam: 'Spam Detected',
    phishing: 'Phishing Alert',
    suspicious: 'Suspicious',
    error: 'Analysis Error',
    unknown: 'Unknown',
  };

  function verdictLabel(verdict) {
    return VERDICT_LABELS[verdict] || verdict;
  }

  function showScanningIndicator() {
    removePanel();
    const panel = document.createElement('div');
    panel.id = 'factscope-panel';
    panel.className = 'factscope-popup';
    panel.innerHTML = `
      <div class="tl-header">
        <div class="logo-dot">FS</div>
        <div class="tl-meta">
          <div class="tl-title">FactScope</div>
          <div class="tl-score" style="color:#2563eb">Scanning&hellip;</div>
        </div>
      </div>
      <div class="tl-body">Analyzing this page for misinformation, spam, and AI-generated content&hellip;</div>
    `;
    document.body.appendChild(panel);
  }

  function showResultPanel(result) {
    removePanel();
    const score = result.trust_score;
    const color = scoreColor(score);
    const label = verdictLabel(result.verdict);
    const evidenceHTML = (result.evidence || [])
      .filter((e) => e && !e.includes('unstructured'))
      .map((e) => `<li>${e}</li>`)
      .join('');

    const panel = document.createElement('div');
    panel.id = 'factscope-panel';
    panel.className = 'factscope-popup';
    panel.innerHTML = `
      <div class="tl-header">
        <div class="logo-dot">FS</div>
        <div class="tl-meta">
          <div class="tl-title">FactScope</div>
          <div class="tl-verdict" style="color:${color}">${label}</div>
        </div>
        <button class="tl-close" aria-label="Close">&times;</button>
      </div>
      <div class="tl-scorebar">
        <div class="tl-scorebar-fill" style="width:${score}%; background:${color}"></div>
      </div>
      <div class="tl-score-label"><span style="color:${color}; font-weight:700">${score}%</span> trust score</div>
      <div class="tl-body">${result.explanation || 'No explanation available.'}</div>
      ${evidenceHTML ? `<div class="tl-evidence"><strong>Supporting evidence</strong><ul>${evidenceHTML}</ul></div>` : ''}
    `;
    panel.querySelector('.tl-close').addEventListener('click', removePanel);
    document.body.appendChild(panel);
  }

  /* ── Scan orchestration ───────────────────────────────────────────── */

  async function scanPage() {
    showScanningIndicator();
    const payload = extractPageContent();
    const result = await analyzePayload(payload);

    if (result && result.trust_score !== undefined) {
      showResultPanel(result);
    } else {
      showResultPanel({
        trust_score: 0,
        verdict: 'error',
        explanation: 'Could not analyze this page. Make sure the FactScope backend is running.',
        evidence: [],
      });
    }
  }

  window.addEventListener(SCAN_EVENT, scanPage);
})();
