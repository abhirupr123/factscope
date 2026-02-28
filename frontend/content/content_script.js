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

  /* ── Metadata extraction ──────────────────────────────────────────── */

  function extractMetadata() {
    const og = (prop) => document.querySelector(`meta[property="og:${prop}"]`)?.content || null;
    const meta = (name) => document.querySelector(`meta[name="${name}"]`)?.content || null;

    const author =
      meta('author') ||
      og('article:author') ||
      document.querySelector('[rel="author"]')?.textContent?.trim() ||
      document.querySelector('.author, .byline, [itemprop="author"]')?.textContent?.trim() ||
      null;

    const publishDate =
      document.querySelector('meta[property="article:published_time"]')?.content ||
      document.querySelector('time[datetime]')?.getAttribute('datetime') ||
      meta('date') ||
      null;

    let jsonLdType = null;
    try {
      for (const el of document.querySelectorAll('script[type="application/ld+json"]')) {
        const data = JSON.parse(el.textContent);
        const item = Array.isArray(data) ? data[0] : data;
        if (item?.['@type']) {
          jsonLdType = item['@type'];
          break;
        }
      }
    } catch { /* skip malformed JSON-LD */ }

    return {
      author: author?.substring(0, 100) || null,
      publish_date: publishDate || null,
      description: og('description') || meta('description') || null,
      og_type: og('type') || null,
      site_name: og('site_name') || null,
      json_ld_type: jsonLdType,
    };
  }

  /* ── Article body detection ───────────────────────────────────────── */

  function extractArticleBody() {
    const ARTICLE_SELECTORS = [
      'article',
      '[role="main"]',
      'main',
      '.article-body',
      '.post-content',
      '.entry-content',
      '.story-body',
      '#article-body',
      '.article__body',
      '.post-body',
    ];

    let root = null;
    for (const sel of ARTICLE_SELECTORS) {
      root = document.querySelector(sel);
      if (root && root.innerText?.trim().length > 100) break;
      root = null;
    }

    const source = root || document.body;
    const clone = source.cloneNode(true);
    clone
      .querySelectorAll('script, style, nav, footer, header, iframe, noscript, aside, form, [role="banner"], [role="navigation"], [role="complementary"], .ad, .ads, .advertisement, .social-share, .related-posts, .comments')
      .forEach((el) => el.remove());

    const lines = clone.innerText
      ?.split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 3);

    return (lines || []).join('\n').substring(0, 3000);
  }

  /* ── Full page extraction ─────────────────────────────────────────── */

  function extractPageContent() {
    const metadata = extractMetadata();
    const text = extractArticleBody();

    const links = [
      ...new Set(
        Array.from(document.querySelectorAll('a[href]'))
          .map((a) => a.href)
          .filter((h) => h.startsWith('http'))
          .slice(0, 10),
      ),
    ];

    return {
      url: window.location.href,
      title: document.title || '',
      text,
      links,
      metadata,
      sample_img: null,
    };
  }

  /* ── UI constants ─────────────────────────────────────────────────── */

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

  const VERDICT_ICONS = {
    authentic: '\u2714',
    misleading: '\u26A0',
    ai_generated: '\u2699',
    spam: '\u26D4',
    phishing: '\u{1F6A8}',
    suspicious: '\u2753',
    error: '\u2716',
    unknown: '\u2022',
  };

  function verdictLabel(v) { return VERDICT_LABELS[v] || v; }
  function verdictIcon(v) { return VERDICT_ICONS[v] || ''; }
  function scoreColor(s) { return s > 70 ? '#10b981' : s > 40 ? '#f59e0b' : '#ef4444'; }

  /* ── UI rendering ─────────────────────────────────────────────────── */

  function removePanel() {
    const el = document.getElementById('factscope-panel');
    if (el) el.remove();
  }

  function createPanel(html) {
    removePanel();
    const panel = document.createElement('div');
    panel.id = 'factscope-panel';
    panel.className = 'factscope-popup';
    panel.innerHTML = html;
    document.body.appendChild(panel);
    return panel;
  }

  function showScanningIndicator() {
    createPanel(`
      <div class="fs-header">
        <div class="fs-logo">FS</div>
        <div class="fs-header-text">
          <div class="fs-brand">FactScope</div>
          <div class="fs-subtitle">Analyzing page&hellip;</div>
        </div>
      </div>
      <div class="fs-loader"><div class="fs-loader-bar"></div></div>
      <div class="fs-body fs-scanning-text">Checking for misinformation, spam, and AI-generated content&hellip;</div>
    `);
  }

  function showResultPanel(result) {
    const score = result.trust_score;
    const color = scoreColor(score);
    const label = verdictLabel(result.verdict);
    const icon = verdictIcon(result.verdict);

    const evidenceItems = (result.evidence || [])
      .filter((e) => e && !e.includes('unstructured'))
      .map((e) => `<li>${e}</li>`)
      .join('');

    const sourceInfo = result.source_info;
    const sourceHTML = sourceInfo
      ? `<div class="fs-source">${[sourceInfo.site_name, sourceInfo.author, sourceInfo.publish_date].filter(Boolean).join(' &middot; ')}</div>`
      : '';

    // Structural signals -- only show notable ones (|delta| >= 5), in plain English
    const notableSignals = (result.structural_signals || [])
      .filter((s) => Math.abs(s.delta) >= 5)
      .map((s) => {
        const icon = s.delta > 0 ? '\u2714' : '\u26A0';
        return `<li>${icon} ${s.detail}</li>`;
      })
      .join('');

    const signalsHTML = notableSignals
      ? `<details class="fs-details"><summary class="fs-details-summary">Why this score?</summary><ul class="fs-details-list">${notableSignals}</ul></details>`
      : '';

    const panel = createPanel(`
      <div class="fs-header">
        <div class="fs-logo">FS</div>
        <div class="fs-header-text">
          <div class="fs-brand">FactScope</div>
        </div>
        <button class="fs-close" aria-label="Close">&times;</button>
      </div>
      <div class="fs-verdict-row">
        <span class="fs-verdict-icon">${icon}</span>
        <span class="fs-verdict-label" style="color:${color}">${label}</span>
      </div>
      <div class="fs-scorebar"><div class="fs-scorebar-fill" style="width:${score}%;background:${color}"></div></div>
      <div class="fs-score-text"><strong style="color:${color}">${score}%</strong> trust score</div>
      ${sourceHTML}
      <div class="fs-divider"></div>
      <div class="fs-body">${result.explanation || 'No explanation available.'}</div>
      ${evidenceItems ? `<div class="fs-evidence"><div class="fs-evidence-title">Supporting evidence</div><ul>${evidenceItems}</ul></div>` : ''}
      ${signalsHTML}
      <div class="fs-footer">Scanned by FactScope</div>
    `);
    panel.querySelector('.fs-close').addEventListener('click', removePanel);
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
