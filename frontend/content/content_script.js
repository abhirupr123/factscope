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

  /* ── Video detection ───────────────────────────────────────────────── */

  const AI_VIDEO_DOMAINS = ['runway', 'runwayml', 'pika', 'sora', 'synthesia', 'heygen', 'colossyan', 'deepbrain', 'd-id'];

  function extractVideoInfo() {
    const url = window.location.href;
    const hostname = window.location.hostname;

    let videoInfo = null;

    // YouTube page
    if (hostname.includes('youtube.com') || hostname.includes('youtu.be')) {
      videoInfo = {
        platform: 'youtube',
        title: document.querySelector('meta[name="title"]')?.content || document.title,
        channel: document.querySelector('[itemprop="author"] link[itemprop="name"]')?.content
          || document.querySelector('#channel-name a')?.textContent?.trim() || null,
        description: document.querySelector('meta[name="description"]')?.content || null,
      };
    }

    // Vimeo page
    if (hostname.includes('vimeo.com')) {
      videoInfo = {
        platform: 'vimeo',
        title: document.title,
        channel: document.querySelector('[itemprop="author"]')?.textContent?.trim() || null,
        description: document.querySelector('meta[name="description"]')?.content || null,
      };
    }

    // AI video platform detection
    if (AI_VIDEO_DOMAINS.some((d) => hostname.includes(d))) {
      videoInfo = videoInfo || { platform: 'ai_video', title: document.title };
      videoInfo.ai_platform = true;
      videoInfo.platform_name = AI_VIDEO_DOMAINS.find((d) => hostname.includes(d));
    }

    // Embedded videos on any page
    if (!videoInfo) {
      const iframes = document.querySelectorAll('iframe[src]');
      for (const iframe of iframes) {
        const src = iframe.src || '';
        if (src.includes('youtube.com') || src.includes('vimeo.com')) {
          videoInfo = { platform: 'embedded', embed_src: src.substring(0, 200) };
          break;
        }
      }
      const videoEls = document.querySelectorAll('video[src], video source[src]');
      if (!videoInfo && videoEls.length > 0) {
        videoInfo = { platform: 'html5_video', video_count: videoEls.length };
      }
    }

    return videoInfo;
  }

  /* ── Full page extraction ─────────────────────────────────────────── */

  function extractPageContent() {
    const metadata = extractMetadata();
    const text = extractArticleBody();
    const videoInfo = extractVideoInfo();

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
      video_info: videoInfo,
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

  const FC_STATUS_ICONS = {
    verified: '\u2714',
    disputed: '\u2716',
    mixed: '\u26A0',
    no_fact_check_found: '\u2022',
  };

  const FC_STATUS_LABELS = {
    verified: 'Verified',
    disputed: 'Disputed',
    mixed: 'Mixed',
  };

  const CORR_ICONS = {
    widely_reported: '\u2714',
    multiple_sources: '\u2714',
    lightly_reported: '\u2139',
    not_corroborated: '\u26A0',
  };

  const CORR_LABELS = {
    widely_reported: 'Widely reported',
    multiple_sources: 'Multiple sources',
    lightly_reported: 'Lightly reported',
    not_corroborated: 'Not corroborated',
  };

  function buildFactChecksHTML(factChecks) {
    if (!factChecks || factChecks.length === 0) return '';

    const items = factChecks.map((fc) => {
      const hasFactCheck = fc.status && fc.status !== 'no_fact_check_found';
      const corr = fc.corroboration || 'not_corroborated';
      const sourceCount = fc.source_count || 0;

      let primaryClass, primaryIcon, primaryLabel, secondaryHTML;

      if (hasFactCheck) {
        primaryClass = `fs-claim-${fc.status.replace(/_/g, '-')}`;
        primaryIcon = FC_STATUS_ICONS[fc.status] || '\u2022';
        primaryLabel = FC_STATUS_LABELS[fc.status] || fc.status;
        const sourceLink = fc.source_url && fc.source
          ? ` <a class="fs-claim-source" href="${fc.source_url}" target="_blank" rel="noopener">${fc.source}</a>`
          : (fc.source ? ` <span class="fs-claim-source">${fc.source}</span>` : '');
        secondaryHTML = sourceLink;
        if (sourceCount > 0) {
          secondaryHTML += ` <span class="fs-corr-count">${sourceCount} source${sourceCount !== 1 ? 's' : ''}</span>`;
        }
      } else {
        primaryClass = `fs-claim-${corr.replace(/_/g, '-')}`;
        primaryIcon = CORR_ICONS[corr] || '\u2022';
        primaryLabel = CORR_LABELS[corr] || corr;
        if (sourceCount > 0) {
          primaryLabel += ` (${sourceCount} source${sourceCount !== 1 ? 's' : ''})`;
        }
        secondaryHTML = '';
      }

      return `<div class="fs-factcheck-item ${primaryClass}"><span class="fs-claim-icon">${primaryIcon}</span><div class="fs-claim-body"><span class="fs-claim-text">${fc.claim}</span><div class="fs-claim-meta"><span class="fs-claim-badge">${primaryLabel}</span>${secondaryHTML}</div></div></div>`;
    }).join('');

    return `<div class="fs-factchecks"><div class="fs-factchecks-title">Claim analysis</div>${items}</div>`;
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

    const factChecksHTML = buildFactChecksHTML(result.fact_checks);

    const notableSignals = (result.structural_signals || [])
      .filter((s) => Math.abs(s.delta) >= 5)
      .map((s) => {
        const sIcon = s.delta > 0 ? '\u2714' : '\u26A0';
        return `<li>${sIcon} ${s.detail}</li>`;
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
      ${factChecksHTML}
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
