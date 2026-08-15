(() => {
  if (window.__FACTSCOPE_CONTENT_SCRIPT_LOADED__) return;
  window.__FACTSCOPE_CONTENT_SCRIPT_LOADED__ = true;

  const SCAN_EVENT = 'factscope-scan';
  const CONSENT_KEY = 'factscope_scan_consent_version';
  const CONSENT_VERSION = 1;

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

  function ensureScanConsent(kind) {
    return new Promise((resolve) => {
      chrome.storage.local.get(CONSENT_KEY, (stored) => {
        if (stored[CONSENT_KEY] === CONSENT_VERSION) {
          resolve(true);
          return;
        }

        const isImage = kind === 'image';
        const panel = createPanel(`
          <div class="fs-header">
            <div class="fs-header-text">
              <div class="fs-brand">Before your first scan</div>
              <div class="fs-subtitle">You choose when FactScope receives content</div>
            </div>
          </div>
          <div class="fs-consent-body">
            <p>${isImage
              ? 'Image verification sends the selected image URL, the page URL, and nearby caption or post context.'
              : 'Page verification sends the page URL, title, extracted text, metadata, and a small set of links.'}</p>
            <p>This information goes to the FactScope backend and its configured AI and fact-checking providers. Raw scans are retained for no more than 30 days.</p>
            <p>Optional telemetry is off by default and never contains page text, titles, claims, full URLs, or image URLs.</p>
            <div class="fs-consent-actions">
              <button type="button" class="fs-consent-decline">Not now</button>
              <button type="button" class="fs-consent-accept">Continue and scan</button>
            </div>
            <a class="fs-consent-link" href="https://factscope.netlify.app/privacy" target="_blank" rel="noopener noreferrer">Privacy policy</a>
          </div>
        `);

        let settled = false;
        const finish = (accepted) => {
          if (settled) return;
          settled = true;
          removePanel();
          resolve(accepted);
        };
        panel.querySelector('.fs-consent-decline').addEventListener('click', () => finish(false));
        panel.querySelector('.fs-consent-accept').addEventListener('click', () => {
          chrome.storage.local.set({ [CONSENT_KEY]: CONSENT_VERSION }, () => finish(true));
        });
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
      og_image: og('image') || meta('twitter:image') || null,
      canonical_url: document.querySelector('link[rel="canonical"]')?.href || null,
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

  const RECOVERY_STATES = {
    offline: {
      icon: '\u21AF', title: 'You’re offline', tone: 'warning', action: 'Try again',
      advice: 'Reconnect to the internet before retrying this scan.',
    },
    cold_start: {
      icon: '\u25F7', title: 'FactScope is waking up', tone: 'info', action: 'Try again in a moment',
      advice: 'The free beta service may need a short moment to start after being idle.',
    },
    timeout: {
      icon: '\u23F1', title: 'Analysis took too long', tone: 'warning', action: 'Try again',
      advice: 'A slower page, image host, or provider may have delayed this request.',
    },
    provider_failure: {
      icon: '\u26A0', title: 'Analysis provider unavailable', tone: 'warning', action: 'Try again later',
      advice: 'No verdict was produced from this failed attempt.',
    },
    server_busy: {
      icon: '\u25F7', title: 'FactScope is busy', tone: 'info', action: 'Try again shortly',
      advice: 'Capacity is temporarily full. Your page has not been given a factual verdict.',
    },
    blocked_image: {
      icon: '\uD83D\uDDBC', title: 'Image could not be accessed', tone: 'warning', action: 'Try image again',
      advice: 'Some sites block external image access. You can also try another copy of the image.',
    },
    unsupported_page: {
      icon: '\u2298', title: 'This page cannot be scanned', tone: 'neutral', action: '',
      advice: 'Chrome internal pages, extension pages, and some protected viewers do not allow FactScope to run.',
    },
    request_too_large: {
      icon: '\u2637', title: 'This page is too large to scan', tone: 'neutral', action: '',
      advice: 'Try a shorter article or a post containing the specific claim you want to investigate.',
    },
    connection_problem: {
      icon: '\u21BB', title: 'Could not reach FactScope', tone: 'warning', action: 'Try again',
      advice: 'Check your connection. If it is working, the service may be temporarily unavailable.',
    },
  };

  function classifyRecoveryState(result, modality = 'page') {
    if (!result || result.verdict === 'rate_limited') return null;
    const explanation = String(result.explanation || '').toLowerCase();
    const classification = result.content_classification || {};
    let state = result.error_state || '';
    if (!state && classification.content_type === 'unsupported_page') state = 'unsupported_page';
    if (!state && result.processing_state === 'failed') {
      if (modality === 'image' && /could not fetch|protected or too large|image retrieval/.test(explanation)) state = 'blocked_image';
      else if (/timed out|timeout/.test(explanation)) state = 'timeout';
      else if (/provider|model|analysis service/.test(explanation)) state = 'provider_failure';
      else state = 'connection_problem';
    }
    const incompleteLegacyResult = !result.fingerprint || result.retryable === true;
    if (!state && incompleteLegacyResult && modality === 'image' && /could not fetch|protected or too large|image retrieval/.test(explanation)) state = 'blocked_image';
    if (!state && incompleteLegacyResult && /timed out|timeout/.test(explanation)) state = 'timeout';
    if (!state && incompleteLegacyResult && /provider unavailable|provider failed|model unavailable/.test(explanation)) state = 'provider_failure';
    if (!state && result.verdict === 'error') state = 'connection_problem';
    if (!state) return null;
    const presentation = RECOVERY_STATES[state] || RECOVERY_STATES.connection_problem;
    return {
      ...presentation,
      state,
      message: result.explanation || presentation.advice,
      requestId: result.request_id || '',
      retryable: result.retryable !== false && Boolean(presentation.action),
    };
  }

  function showRecoveryPanel(result, modality, retryAction) {
    const recovery = classifyRecoveryState(result, modality);
    if (!recovery) return false;
    const reference = recovery.requestId
      ? `<div class="fs-recovery-reference">Reference: ${recovery.requestId}</div>`
      : '';
    const retry = recovery.retryable && typeof retryAction === 'function'
      ? `<button type="button" class="fs-retry-btn">${recovery.action}</button>`
      : '';
    const panel = createPanel(`
      <div class="fs-header">
        <div class="fs-logo"><svg viewBox="0 0 100 100" width="28" height="28"><circle cx="50" cy="50" r="46" fill="#4F46E5"/><circle cx="50" cy="50" r="38" fill="#6366F1"/><circle cx="50" cy="50" r="30" fill="#4F46E5"/><polyline points="33,52 45,64 68,38" fill="none" stroke="#fff" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
        <div class="fs-header-text"><div class="fs-brand">FactScope</div><div class="fs-subtitle">${modality === 'image' ? 'Image verification' : 'Page verification'}</div></div>
        <div class="fs-header-actions"><button class="fs-close" aria-label="Close">&times;</button></div>
      </div>
      <section class="fs-recovery fs-recovery-${recovery.tone}" role="status" aria-live="polite">
        <div class="fs-recovery-icon" aria-hidden="true">${recovery.icon}</div>
        <h2>${recovery.title}</h2>
        <p>${recovery.message}</p>
        <p class="fs-recovery-advice">${recovery.advice}</p>
        ${reference}${retry}
      </section>
      <div class="fs-footer">No factual verdict was produced</div>
    `);
    panel.querySelector('.fs-close').addEventListener('click', removePanel);
    const retryButton = panel.querySelector('.fs-retry-btn');
    if (retryButton) {
      retryButton.addEventListener('click', () => {
        retryButton.disabled = true;
        retryButton.textContent = 'Retrying…';
        retryAction();
      });
    }
    return true;
  }
  function escapeHTML(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function safeHTTPURL(value) {
    try {
      const parsed = new URL(String(value ?? ''));
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return '';
      if (parsed.username || parsed.password) return '';
      return escapeHTML(parsed.href);
    } catch {
      return '';
    }
  }

  function sanitizeForHTML(value, key = '') {
    if (value === null || value === undefined) return value;
    if (typeof value === 'string') {
      return key.toLowerCase().includes('url') ? safeHTTPURL(value) : escapeHTML(value);
    }
    if (typeof value !== 'object') return value;
    if (value.__factscopeSanitized) return value;

    if (Array.isArray(value)) {
      const sanitized = value.map((item) => sanitizeForHTML(item, key));
      Object.defineProperty(sanitized, '__factscopeSanitized', { value: true });
      return sanitized;
    }

    const sanitized = {};
    for (const [childKey, childValue] of Object.entries(value)) {
      sanitized[childKey] = sanitizeForHTML(childValue, childKey);
    }
    Object.defineProperty(sanitized, '__factscopeSanitized', { value: true });
    return sanitized;
  }

  if (globalThis.__FACTSCOPE_SECURITY_TEST__) {
    globalThis.__FACTSCOPE_SECURITY__ = {
      escapeHTML, safeHTTPURL, sanitizeForHTML,
    };
  }

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
        <div class="fs-logo"><svg viewBox="0 0 100 100" width="28" height="28"><circle cx="50" cy="50" r="46" fill="#4F46E5"/><circle cx="50" cy="50" r="38" fill="#6366F1"/><circle cx="50" cy="50" r="30" fill="#4F46E5"/><polyline points="33,52 45,64 68,38" fill="none" stroke="#fff" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
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
    related_topic: '\uD83D\uDD0D',
    not_corroborated: '\u26A0',
  };

  const CORR_LABELS = {
    widely_reported: 'Widely reported',
    multiple_sources: 'Multiple sources',
    lightly_reported: 'Lightly reported',
    related_topic: 'Related topic covered',
    not_corroborated: 'Not corroborated',
  };

  function buildFactChecksHTML(factChecks) {
    if (!Array.isArray(factChecks)) return '';
    if (factChecks.length === 0) {
      return '<div class="fs-factchecks"><div class="fs-factchecks-title">Claim analysis</div><div class="fs-body">No checkable factual claims were identified in the extracted article text. This does not mean the article contains no factual claims.</div></div>';
    }

    factChecks = sanitizeForHTML(factChecks);
    const items = factChecks.map((fc) => {
      const isOpinion = fc.status === 'opinion';
      const hasFactCheck = !isOpinion && fc.status && fc.status !== 'no_fact_check_found';
      const corr = fc.corroboration || 'not_corroborated';
      const sourceCount = fc.source_count || 0;

      let primaryClass, primaryIcon, primaryLabel, secondaryHTML;

      if (isOpinion) {
        primaryClass = 'fs-claim-opinion';
        primaryIcon = '\uD83D\uDCAC';
        primaryLabel = 'Opinion / Not a factual claim';
        secondaryHTML = '';
      } else if (hasFactCheck) {
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

      let articlesHTML = '';
      if (fc.related_articles && fc.related_articles.length > 0) {
        const articleItems = fc.related_articles.slice(0, 3).map((a) => {
          const link = a.url
            ? `<a class="fs-article-link" href="${a.url}" target="_blank" rel="noopener">${a.title}</a>`
            : `<span>${a.title}</span>`;
          const src = a.source ? `<span class="fs-article-source">${a.source}</span>` : '';
          return `<li>${link} ${src}</li>`;
        }).join('');
        articlesHTML = `<ul class="fs-related-articles">${articleItems}</ul>`;
      }

      return `<div class="fs-factcheck-item ${primaryClass}"><span class="fs-claim-icon">${primaryIcon}</span><div class="fs-claim-body"><span class="fs-claim-text">${fc.claim}</span><div class="fs-claim-meta"><span class="fs-claim-badge">${primaryLabel}</span>${secondaryHTML}</div>${articlesHTML}</div></div>`;
    }).join('');

    return `<div class="fs-factchecks"><div class="fs-factchecks-title">Claim analysis</div>${items}</div>`;
  }

  const V1_STATUS_PRESENTATION = {
    supported: { label: 'Supported', icon: '\u2714', color: '#059669' },
    contradicted: { label: 'Contradicted', icon: '\u2716', color: '#dc2626' },
    mixed: { label: 'Mixed evidence', icon: '\u26A0', color: '#d97706' },
    insufficient_evidence: { label: 'Insufficient evidence', icon: '\u2139', color: '#64748b' },
    processing: { label: 'Evidence processing', icon: '\u2026', color: '#4f46e5' },
    not_applicable: { label: 'Not applicable', icon: '\u2139', color: '#64748b' },
    no_indicators_detected: { label: 'No clear manipulation indicators', icon: '\u2714', color: '#059669' },
    possible_manipulation: { label: 'Possible editing or compositing', icon: '\u26A0', color: '#d97706' },
    likely_manipulated: { label: 'Edited or composited image detected', icon: '\u26A0', color: '#d97706' },
    likely_ai_generated: { label: 'Likely AI-generated', icon: '\u2716', color: '#dc2626' },
    uncertain: { label: 'Uncertain', icon: '?', color: '#64748b' },
    consistent: { label: 'Caption appears consistent', icon: '\u2714', color: '#059669' },
    inconsistent: { label: 'Caption appears inconsistent', icon: '\u2716', color: '#dc2626' },
    not_provided: { label: 'No caption provided', icon: '\u2139', color: '#64748b' },
    visible_source_indicator: { label: 'Visible source indicator', icon: '\u2714', color: '#059669' },
    no_visible_source_indicator: { label: 'No visible source indicator', icon: '\u2139', color: '#64748b' },
    unknown: { label: 'Unknown', icon: '?', color: '#64748b' },
  };

  function v1StatusPresentation(status) {
    return V1_STATUS_PRESENTATION[status] || V1_STATUS_PRESENTATION.unknown;
  }

  function formatV1Label(value) {
    const label = String(value || 'unknown').replace(/_/g, ' ');
    return label.charAt(0).toUpperCase() + label.slice(1);
  }

  function buildLimitationsHTML(limitations, title = 'Limitations', collapsible = false) {
    if (!Array.isArray(limitations) || limitations.length === 0) return '';
    const unique = [...new Set(limitations.filter(Boolean))];
    if (unique.length === 0) return '';
    const content = `<ul>${unique.map((item) => `<li>${item}</li>`).join('')}</ul>`;
    if (collapsible) {
      return `<details class="fs-limitations fs-limitations-compact"><summary class="fs-limitations-title">${title}</summary>${content}</details>`;
    }
    return `<div class="fs-limitations"><div class="fs-limitations-title">${title}</div>${content}</div>`;
  }

  function friendlyAssessmentLimitations(limitations) {
    const friendly = [];
    for (const raw of limitations || []) {
      const item = String(raw || '');
      const lowered = item.toLowerCase();
      if (lowered.includes('legacy score') && lowered.includes('probability')) {
        friendly.push("This assessment looks at the page's source, presentation, and available evidence. It does not guarantee that every claim is true.");
      } else if (!lowered.includes('at least one claim lacks enough evidence')) {
        friendly.push(item);
      }
    }
    return [...new Set(friendly.filter(Boolean))];
  }

  function buildV1SourcesHTML(sources, heading) {
    if (!Array.isArray(sources) || sources.length === 0) return '';
    const renderSource = (source) => {
      const title = source.title || source.publisher || 'Context source';
      const sourceMeta = [
        source.publisher,
        source.source_type === 'primary' ? 'Primary source' : '',
        source.independent === false ? 'Repeated or non-independent' : '',
        ['current', 'recent', 'older'].includes(source.recency) ? formatV1Label(source.recency) : '',
      ].filter(Boolean).join(' · ');
      const publisher = sourceMeta ? `<span class="fs-article-source">${sourceMeta}</span>` : '';
      const reviewedClaim = source.reviewed_claim
        ? `<span class="fs-reviewed-claim">Reviewed claim: ${source.reviewed_claim}</span>`
        : '';
      const repetition = Number(source.additional_reports || 0) > 0
        ? `<span class="fs-source-repetition">+${source.additional_reports} similar result${Number(source.additional_reports) === 1 ? '' : 's'} grouped</span>`
        : '';
      const link = source.url
        ? `<a class="fs-article-link" href="${source.url}" target="_blank" rel="noopener">${title}</a>`
        : `<span>${title}</span>`;
      return `<li>${link} ${publisher}${reviewedClaim}${repetition}</li>`;
    };
    const visible = sources.slice(0, 4).map(renderSource).join('');
    const remaining = sources.slice(4).map(renderSource).join('');
    const headingHTML = heading ? `<div class="fs-v1-source-heading">${heading}</div>` : '';
    const moreHTML = remaining
      ? `<details class="fs-more-sources"><summary>Show ${sources.length - 4} more source${sources.length - 4 === 1 ? '' : 's'}</summary><ul class="fs-related-articles">${remaining}</ul></details>`
      : '';
    return `<div class="fs-v1-source-group">${headingHTML}<ul class="fs-related-articles">${visible}</ul>${moreHTML}</div>`;
  }

  function buildEvidenceOverviewHTML(claims) {
    if (!Array.isArray(claims) || claims.length === 0) return '';
    const factualFindings = claims.filter((claim) =>
      ['supported', 'contradicted', 'mixed'].includes(claim.status)).length;
    const matchingCoverage = claims.filter((claim) =>
      (claim.related_sources || []).some((source) => source.evidence_level === 'matching_coverage')).length;
    const contextOnly = claims.filter((claim) =>
      !(claim.related_sources || []).some((source) => source.evidence_level === 'matching_coverage')
      && (claim.context_sources || []).length > 0).length;
    const openClaims = Math.max(0, claims.length - factualFindings - matchingCoverage - contextOnly);
    const items = [
      ['Claims checked', claims.length],
      ['Evidence findings', factualFindings],
      ['Matching coverage', matchingCoverage],
      ['Still open', openClaims + contextOnly],
    ];
    return `<div class="fs-evidence-overview" aria-label="Evidence overview">${items.map(([label, value]) =>
      `<div class="fs-overview-item"><strong>${value}</strong><span>${label}</span></div>`).join('')}</div>`;
  }

  function buildEvidenceMetaHTML(factual, result) {
    if (factual.status !== 'insufficient_evidence') {
      return `<div class="fs-assessment-meta" title="How strongly the displayed evidence supports this finding">Finding confidence: ${formatV1Label(factual.confidence || result.confidence || 'low')}</div>`;
    }
    const coverage = factual.coverage_breadth || 'none';
    const context = factual.context_breadth || 'none';
    let coverageLabel = 'No matching reporting found';
    if (coverage === 'broad') coverageLabel = 'Matching reporting found for most claims';
    else if (['partial', 'limited'].includes(coverage)) coverageLabel = 'Matching reporting found for some claims';
    else if (context !== 'none') coverageLabel = 'Background reporting found';
    return `<div class="fs-assessment-meta">${coverageLabel} <span aria-hidden="true">&middot;</span> No claim-level verdict yet</div>`;
  }

  function buildV1ClaimsHTML(claims, limitations = [], title = 'Claim evidence') {
    const safe = sanitizeForHTML({ claims: claims || [], limitations: limitations || [] });
    if (!Array.isArray(safe.claims) || safe.claims.length === 0) {
      const message = safe.limitations[0] || 'No checkable factual claims were identified in the extracted content.';
      return `<div class="fs-factchecks"><div class="fs-factchecks-title">${title}</div><div class="fs-body">${message}</div>${buildLimitationsHTML(safe.limitations.slice(1), 'More context', true)}</div>`;
    }
    let hasMatchingCoverage = false;
    let hasBroaderContext = false;
    let hiddenSourceCount = 0;
    const items = safe.claims.map((claim, claimIndex) => {
      const presentation = v1StatusPresentation(claim.status);
      const statusClass = V1_STATUS_PRESENTATION[claim.status] ? claim.status.replace(/_/g, '-') : 'unknown';
      let contextualPresentation = presentation;
      const reportingSupport = (claim.supporting_sources || []).some((source) => source.stance === 'corroborating');
      const reportingContradiction = (claim.contradicting_sources || []).some((source) => source.stance === 'contradicting');
      const matchingSources = (claim.related_sources || []).filter((source) =>
        source.evidence_level === 'matching_coverage'
        || (!source.evidence_level && source.stance === 'unavailable'));
      const relatedContext = (claim.related_sources || []).filter((source) => !matchingSources.includes(source));
      const broaderContext = claim.context_sources || [];
      const legacyHiddenCount = (claim.limitations || []).reduce((sum, item) => {
        const match = String(item || '').match(/^(\d+) candidate source\(s\) could not be shown/i);
        return sum + (match ? Number(match[1]) : 0);
      }, 0);
      hiddenSourceCount += Number(claim.hidden_source_count || 0) || legacyHiddenCount;
      hasMatchingCoverage = hasMatchingCoverage || matchingSources.length > 0;
      hasBroaderContext = hasBroaderContext || broaderContext.length > 0;
      if (claim.status === 'supported' && claim.confidence === 'medium' && reportingSupport) {
        contextualPresentation = { ...presentation, label: 'Corroborated by independent reporting' };
      } else if (claim.status === 'contradicted' && claim.confidence === 'medium' && reportingContradiction) {
        contextualPresentation = { ...presentation, label: 'Contradicted by independent reporting' };
      } else if (claim.status === 'insufficient_evidence' && matchingSources.length > 1) {
        contextualPresentation = { ...presentation, label: 'Multiple matching reports' };
      } else if (claim.status === 'insufficient_evidence' && matchingSources.length === 1) {
        contextualPresentation = { ...presentation, label: 'Matching coverage' };
      } else if (claim.status === 'insufficient_evidence' && relatedContext.length > 0) {
        contextualPresentation = { ...presentation, label: 'Related reporting found' };
      } else if (claim.status === 'insufficient_evidence' && broaderContext.length > 0) {
        contextualPresentation = { ...presentation, label: 'Broader context found' };
      } else if (claim.status === 'insufficient_evidence') {
        contextualPresentation = { ...presentation, label: 'No external coverage found' };
      }
      const confidenceHTML = claim.status === 'insufficient_evidence'
        ? ''
        : `<span class="fs-confidence">${formatV1Label(claim.confidence || 'low')} confidence</span>`;
      return `<div class="fs-factcheck-item fs-v1-claim-${statusClass}">
        <span class="fs-claim-number" aria-label="Claim ${claimIndex + 1}">${claimIndex + 1}</span>
        <div class="fs-claim-body">
          <span class="fs-claim-text">${claim.claim}</span>
          <div class="fs-claim-meta"><span class="fs-v1-status" style="color:${contextualPresentation.color}">${contextualPresentation.label}</span>${confidenceHTML}</div>
          ${buildV1SourcesHTML(claim.supporting_sources, 'Supporting sources')}
          ${buildV1SourcesHTML(claim.contradicting_sources, 'Contradicting sources')}
          ${buildV1SourcesHTML(matchingSources, '')}
          ${buildV1SourcesHTML(relatedContext, 'Related reporting')}
          ${buildV1SourcesHTML(
            broaderContext,
            contextualPresentation.label === 'Broader context found' ? '' : 'Broader context',
          )}
        </div>
      </div>`;
    }).join('');
    const guide = [];
    if (hasMatchingCoverage) {
      guide.push('Matching coverage reports on the same claim or event, but may not confirm every detail.');
    }
    if (hasBroaderContext) {
      guide.push('Broader context provides useful background but is not direct confirmation.');
    }
    if (hiddenSourceCount > 0) {
      guide.push(`${hiddenSourceCount} other result${hiddenSourceCount === 1 ? ' was' : 's were'} hidden because ${hiddenSourceCount === 1 ? 'it was' : 'they were'} repetitive, outdated, unrelated, or could not be checked.`);
    }
    return `<div class="fs-factchecks"><div class="fs-section-heading"><div class="fs-factchecks-title">${title}</div><span>${safe.claims.length} checked</span></div>${items}${buildLimitationsHTML(guide, 'About the coverage labels', true)}</div>`;
  }
  function buildV1ArticleSummaryHTML(result, view = 'all') {
    result = sanitizeForHTML(result || {});
    const factual = result.factual_evidence || {};
    const classification = result.content_classification || {};
    const coverage = factual.coverage_breadth || 'none';
    const contextBreadth = factual.context_breadth || 'none';
    let presentation = v1StatusPresentation(factual.status);
    if (factual.status === 'not_applicable') {
      const labels = {
        satire: 'Satire identified',
        opinion: 'Opinion and context assessment',
        prediction: 'Forward-looking claim',
        unsupported_page: 'Unable to assess this page',
      };
      presentation = { ...presentation, label: labels[classification.content_type] || 'Context-only assessment' };
    } else if (factual.status === 'insufficient_evidence' && coverage === 'broad') {
      presentation = { ...presentation, label: 'Matching coverage found' };
    } else if (factual.status === 'insufficient_evidence' && ['partial', 'limited'].includes(coverage)) {
      presentation = { ...presentation, label: 'Some matching coverage found' };
    } else if (factual.status === 'insufficient_evidence' && contextBreadth !== 'none') {
      presentation = { ...presentation, label: 'Context found; verification remains open' };
    } else if (factual.status === 'insufficient_evidence' && classification.content_type === 'breaking_news') {
      presentation = { ...presentation, label: 'Evidence still developing' };
    } else if (factual.status === 'insufficient_evidence') {
      presentation = { ...presentation, label: 'No corroborating evidence found' };
    } else if (factual.status === 'supported' && (result.claims || []).some((claim) =>
      (claim.supporting_sources || []).some((source) => source.stance === 'corroborating'))) {
      presentation = { ...presentation, label: 'Supported by independent reporting' };
    } else if (factual.status === 'contradicted' && (result.claims || []).some((claim) =>
      (claim.contradicting_sources || []).some((source) => source.stance === 'contradicting'))) {
      presentation = { ...presentation, label: 'Contradicted by independent reporting' };
    }
    const quality = result.source_quality || {};
    const classificationLabel = classification.content_type ? formatV1Label(classification.content_type) : '';
    const classificationDetails = classificationLabel
      ? `<details class="fs-details fs-secondary-assessment"><summary class="fs-details-summary">Why this was identified as ${classificationLabel}</summary><div class="fs-body">${classification.rationale || ''}</div><div class="fs-confidence">Classification confidence: ${formatV1Label(classification.confidence)} &middot; Checkability: ${formatV1Label(classification.checkability)}</div></details>`
      : '';
    const qualitySignals = (quality.signals || []).map((signal) => `<li>${signal.detail}</li>`).join('');
    const modelEvidence = (result.evidence || []).filter(Boolean).map((item) => `<li>${item}</li>`).join('');
    const modelAssessment = result.explanation || modelEvidence
      ? `<details class="fs-details fs-secondary-assessment"><summary class="fs-details-summary">Page and source context</summary><div class="fs-body">${result.explanation || ''}</div>${modelEvidence ? `<ul class="fs-details-list">${modelEvidence}</ul>` : ''}<div class="fs-caveat">This AI-assisted context review does not verify the claims above.</div></details>`
      : '';
    const qualityDetails = quality.summary || qualitySignals || (quality.limitations || []).length
      ? `<details class="fs-details fs-secondary-assessment"><summary class="fs-details-summary">Source and presentation signals</summary><div class="fs-body">${quality.summary || ''}</div>${qualitySignals ? `<ul class="fs-details-list">${qualitySignals}</ul>` : ''}${buildLimitationsHTML(quality.limitations, 'What these signals cannot tell you', true)}</details>`
      : '';
    const evidenceMeta = buildEvidenceMetaHTML(factual, result);
    const primaryHTML = `<div class="fs-assessment-card">
      <div class="fs-assessment-kicker">Evidence assessment</div>
      <div class="fs-assessment-status" style="color:${presentation.color}"><span>${presentation.icon}</span>${presentation.label}</div>
      ${evidenceMeta}
      <div class="fs-body">${result.overall_evidence_summary || factual.summary || 'No evidence summary is available.'}</div>
      ${buildEvidenceOverviewHTML(result.claims)}
    </div>`;
    const contextHTML = `${modelAssessment}${classificationDetails}${qualityDetails}${buildLimitationsHTML(friendlyAssessmentLimitations(result.limitations), 'About this assessment', true)}`;
    if (view === 'summary') return primaryHTML;
    if (view === 'context') return contextHTML;
    return `${primaryHTML}${contextHTML}`;
  }
  function buildV1ImageAssessmentHTML(result) {
    const assessment = result.assessment || {};
    const manipulation = assessment.manipulation || {};
    const caption = assessment.caption_consistency || {};
    const provenance = assessment.provenance || {};
    const manipulationView = v1StatusPresentation(manipulation.status);
    const captionView = v1StatusPresentation(caption.status);
    const provenanceView = v1StatusPresentation(provenance.status);
    const sectionLimitations = [
      ...(manipulation.limitations || []),
      ...(caption.limitations || []),
      ...(provenance.limitations || []),
    ];
    const remainingLimitations = (result.limitations || []).filter(
      (item) => !sectionLimitations.includes(item),
    );
    const editingCaveat = ['possible_manipulation', 'likely_manipulated'].includes(manipulation.status)
      ? '<div class="fs-caveat">Editing or compositing alone does not establish deceptive use.</div>'
      : '';
    const indicatorList = (items) => Array.isArray(items) && items.length
      ? `<ul class="fs-details-list">${items.map((item) => `<li>${item}</li>`).join('')}</ul>` : '';
    return `<div class="fs-assessment-card">
      <div class="fs-assessment-kicker">Visual manipulation assessment</div>
      <div class="fs-assessment-status" style="color:${manipulationView.color}"><span>${manipulationView.icon}</span>${manipulationView.label}</div>
      <div class="fs-assessment-meta" title="How strongly the available visual signals support this assessment">Visual finding confidence: ${formatV1Label(manipulation.confidence || 'low')}</div>
      <div class="fs-body">${manipulation.summary || 'No visual assessment is available.'}</div>
      ${indicatorList(manipulation.indicators)}${editingCaveat}${buildLimitationsHTML(manipulation.limitations, 'What could affect this result', true)}
    </div>
    <div class="fs-assessment-grid">
      <div class="fs-mini-assessment"><div class="fs-assessment-kicker">Caption consistency</div><div class="fs-mini-status" style="color:${captionView.color}">${captionView.icon} ${captionView.label}</div><div class="fs-body">${caption.summary || ''}</div>${buildLimitationsHTML(caption.limitations, 'What could affect this result', true)}</div>
      <div class="fs-mini-assessment"><div class="fs-assessment-kicker">Visible source clues</div><div class="fs-mini-status" style="color:${provenanceView.color}">${provenanceView.icon} ${provenanceView.label}</div><div class="fs-body">${provenance.summary || ''}</div>${indicatorList(provenance.indicators)}${buildLimitationsHTML(provenance.limitations, 'What could affect this result', true)}<div class="fs-caveat">Visible credits are clues, not proof of origin.</div></div>
    </div>
    <details class="fs-details fs-secondary-assessment"><summary class="fs-details-summary">Compatibility score (temporary)</summary><div class="fs-body">${Number.isFinite(result.legacy_score) ? result.legacy_score : result.authenticity_score || 0}/100. Use the separate visual, caption, and source-clue assessments above when interpreting this result.</div></details>
    ${buildLimitationsHTML(remainingLimitations, 'Other things to keep in mind', true)}`;
  }

  if (globalThis.__FACTSCOPE_SECURITY_TEST__) {
    Object.assign(globalThis.__FACTSCOPE_SECURITY__, {
      buildV1ClaimsHTML, buildV1ArticleSummaryHTML, buildV1ImageAssessmentHTML,
      classifyRecoveryState,
    });
  }

  /* ── Community section builders ──────────────────────────────────── */

  const FLAG_CATEGORIES = {
    false_info: 'False Information',
    misleading_headline: 'Misleading Headline',
    out_of_context: 'Out of Context',
    satire_as_real: 'Satire as Real',
    manipulated_media: 'Manipulated Media',
    other: 'Other',
  };

  const CATEGORY_COLORS = {
    false_info: '#ef4444',
    misleading_headline: '#f59e0b',
    out_of_context: '#8b5cf6',
    satire_as_real: '#06b6d4',
    manipulated_media: '#ec4899',
    other: '#64748b',
  };

  function buildVoteHTML(voteStats, fingerprint) {
    const likes = voteStats?.likes || 0;
    const dislikes = voteStats?.dislikes || 0;
    const total = likes + dislikes;
    const helpfulText = total > 0 ? `${likes} found this helpful` : '';
    return `<div class="fs-vote-row" data-fp="${fingerprint || ''}">
      <span class="fs-vote-label">Was this helpful?</span>
      <button class="fs-vote-btn fs-vote-up" data-vote="1" title="Yes">\u{1F44D}</button>
      <button class="fs-vote-btn fs-vote-down" data-vote="-1" title="No">\u{1F44E}</button>
      <span class="fs-vote-count">${helpfulText}</span>
    </div>`;
  }

  function buildNoteCardHTML(note) {
    note = sanitizeForHTML(note);
    const catLabel = FLAG_CATEGORIES[note.category] || note.category;
    const catColor = CATEGORY_COLORS[note.category] || '#64748b';
    let sourcesHTML = '';
    if (note.source_urls && note.source_urls.length > 0) {
      const links = note.source_urls.slice(0, 3).map((u) => {
        const domain = (() => { try { return new URL(u).hostname; } catch { return u; } })();
        return `<a class="fs-note-source" href="${u}" target="_blank" rel="noopener">${domain}</a>`;
      }).join('');
      sourcesHTML = `<div class="fs-note-sources">${links}</div>`;
    }
    return `<div class="fs-note-card">
      <span class="fs-category-badge" style="background:${catColor}">${catLabel}</span>
      <p class="fs-note-text">${note.justification}</p>
      ${sourcesHTML}
    </div>`;
  }

  function buildCommunitySection(result) {
    const notes = result.community_notes || [];
    const flagCount = result.community_flags || 0;
    const fp = result.fingerprint || '';

    let notesHTML;
    if (notes.length > 0) {
      notesHTML = notes.map(buildNoteCardHTML).join('');
    } else if (flagCount > 0) {
      notesHTML = `<p class="fs-no-notes">${flagCount} user report${flagCount !== 1 ? 's were' : ' was'} received; none has been approved as a community insight.</p>`;
    } else {
      notesHTML = '<p class="fs-no-notes">No crowd insights yet &mdash; be the first to weigh in</p>';
    }
    const countBadge = flagCount >= 3 ? ` <span class="fs-flag-count-badge">${flagCount}</span>` : '';

    return `<div class="fs-community-section">
      <div class="fs-community-header">
        <span class="fs-community-title">\uD83D\uDDE3 Crowd Insights${countBadge}</span>
      </div>
      ${notesHTML}
      <button class="fs-add-note-btn" data-fp="${fp}">\u270F Flag &amp; share your insight</button>
      <div class="fs-flag-form" data-fp="${fp}" style="display:none">
        <select class="fs-flag-category">
          <option value="">What's wrong with this content?</option>
          ${Object.entries(FLAG_CATEGORIES).map(([k, v]) => `<option value="${k}">${v}</option>`).join('')}
        </select>
        <div class="fs-textarea-wrap">
          <textarea class="fs-flag-justification" placeholder="Explain why (min 30 characters)" maxlength="500"></textarea>
          <span class="fs-char-counter">0/30</span>
        </div>
        <div class="fs-source-inputs">
          <input class="fs-source-url" type="url" placeholder="Link to a source (optional)">
          <button class="fs-add-source-btn" title="Add another source">+</button>
        </div>
        <button class="fs-submit-flag" disabled>Submit</button>
      </div>
    </div>`;
  }

  const TIER_CONFIG = {
    trusted:     { label: 'Trusted',     color: '#16a34a' },
    established: { label: 'Established', color: '#2563eb' },
    mixed:       { label: 'Mixed',       color: '#d97706' },
    low_trust:   { label: 'Low Trust',   color: '#dc2626' },
    new:         { label: 'New',         color: '#6b7280' },
  };

  function buildDomainProfileHTML(profile) {
    if (!profile || !profile.domain) return '';
    const tier = TIER_CONFIG[profile.reputation_tier] || TIER_CONFIG.new;
    const avgScore = Math.round(profile.avg_trust_score || 50);
    const barColor = avgScore >= 70 ? '#16a34a' : avgScore >= 45 ? '#d97706' : '#dc2626';

    const stats = [];
    if (profile.total_scans > 0) stats.push(`${profile.total_scans} scan${profile.total_scans !== 1 ? 's' : ''}`);
    if (profile.unique_users > 0) stats.push(`${profile.unique_users} user${profile.unique_users !== 1 ? 's' : ''}`);
    if (profile.total_scans > 0) stats.push(`avg ${avgScore}%`);
    const statsText = stats.length ? stats.join(' \u00b7 ') : 'First scan';

    const repTag = profile.is_reputable
      ? '<span class="fs-domain-rep-tag">\u2714 Known reputable source</span>'
      : '';

    const flagNote = profile.flag_count > 0
      ? `<span class="fs-domain-flags">\u26A0 ${profile.flag_count} flag${profile.flag_count !== 1 ? 's' : ''}</span>`
      : '';

    return `<div class="fs-domain-profile">
      <div class="fs-domain-header">
        <span class="fs-domain-name">${profile.domain}</span>
        <span class="fs-domain-badge" style="background:${tier.color}">${tier.label}</span>
      </div>
      <div class="fs-domain-stats">${statsText}</div>
      <div class="fs-domain-bar"><div class="fs-domain-bar-fill" style="width:${avgScore}%;background:${barColor}"></div></div>
      <div class="fs-domain-tags">${repTag}${flagNote}</div>
    </div>`;
  }

  function buildKBMatchHTML(kbMatches) {
    if (!kbMatches || kbMatches.length === 0) return '';
    const items = kbMatches.map((m) => {
      const conf = Math.round((m.confidence || 0) * 100);
      return `<div class="fs-kb-match"><span class="fs-kb-icon">\u{1F4DA}</span><span class="fs-kb-text">${m.counter_claim}</span><span class="fs-kb-conf">${conf}% confidence</span></div>`;
    }).join('');
    return `<div class="fs-kb-section"><div class="fs-kb-title">Previously flagged by the community</div>${items}</div>`;
  }

  function wireVoteButtons(panel, fingerprint) {
    panel.querySelectorAll('.fs-vote-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        const vote = parseInt(btn.dataset.vote, 10);
        panel.querySelectorAll('.fs-vote-btn').forEach((b) => b.classList.remove('fs-vote-active'));
        btn.classList.add('fs-vote-active');
        if (!chrome.runtime?.id) return;
        chrome.runtime.sendMessage({ type: 'vote', fingerprint, vote }, (resp) => {
          if (chrome.runtime.lastError) return;
          if (resp && resp.success) {
            const countEl = panel.querySelector('.fs-vote-count');
            if (countEl) countEl.textContent = `${resp.likes} found this helpful`;
          }
        });
      });
    });
  }

  function wireFlagForm(panel, fingerprint) {
    const addBtn = panel.querySelector('.fs-add-note-btn');
    const form = panel.querySelector('.fs-flag-form');
    if (!addBtn || !form) return;

    addBtn.addEventListener('click', () => {
      const isVisible = form.style.display !== 'none';
      form.style.display = isVisible ? 'none' : 'block';
      addBtn.textContent = isVisible ? '\u270F Flag & share your insight' : 'Cancel';
    });

    const textarea = form.querySelector('.fs-flag-justification');
    const counter = form.querySelector('.fs-char-counter');
    const submitBtn = form.querySelector('.fs-submit-flag');
    const categorySelect = form.querySelector('.fs-flag-category');

    const updateSubmitState = () => {
      const len = (textarea.value || '').length;
      const hasCat = !!categorySelect.value;
      counter.textContent = `${len}/30`;
      counter.classList.toggle('fs-char-ok', len >= 30);
      submitBtn.disabled = !hasCat || len < 30;
    };
    textarea.addEventListener('input', updateSubmitState);
    categorySelect.addEventListener('change', updateSubmitState);

    const addSourceBtn = form.querySelector('.fs-add-source-btn');
    const sourceInputs = form.querySelector('.fs-source-inputs');
    addSourceBtn.addEventListener('click', () => {
      const existing = sourceInputs.querySelectorAll('.fs-source-url');
      if (existing.length >= 3) return;
      const input = document.createElement('input');
      input.className = 'fs-source-url';
      input.type = 'url';
      input.placeholder = 'Link to another source';
      sourceInputs.insertBefore(input, addSourceBtn);
    });

    submitBtn.addEventListener('click', () => {
      if (submitBtn.disabled) return;
      submitBtn.disabled = true;
      submitBtn.textContent = 'Submitting\u2026';

      const sourceUrls = Array.from(sourceInputs.querySelectorAll('.fs-source-url'))
        .map((i) => i.value.trim())
        .filter((u) => u.length > 0);

      if (!chrome.runtime?.id) return;
      chrome.runtime.sendMessage({
        type: 'flag-content',
        fingerprint,
        category: categorySelect.value,
        justification: textarea.value.trim(),
        source_urls: sourceUrls.length > 0 ? sourceUrls : null,
      }, (resp) => {
        if (chrome.runtime.lastError) {
          submitBtn.textContent = 'Failed';
          submitBtn.disabled = false;
          return;
        }
        if (resp && resp.success && resp.note) {
          form.style.display = 'none';
          addBtn.textContent = '\u270F Flag & share your insight';
          const section = panel.querySelector('.fs-community-section');
          const noNotes = section.querySelector('.fs-no-notes');
          if (noNotes) noNotes.remove();
          const card = document.createElement('div');
          card.innerHTML = buildNoteCardHTML(resp.note);
          section.querySelector('.fs-community-header').after(card.firstElementChild);
        } else if (resp && resp.already_flagged) {
          submitBtn.textContent = 'Already submitted';
        } else if (resp && resp.rejection_reason) {
          submitBtn.textContent = 'Rejected';
          const hint = document.createElement('p');
          hint.className = 'fs-flag-rejection';
          hint.textContent = resp.rejection_reason;
          submitBtn.after(hint);
          submitBtn.disabled = false;
        } else {
          submitBtn.textContent = 'Failed \u2013 try again';
          submitBtn.disabled = false;
        }
      });
    });
  }

  function mergeCompletedClaimResult(baseResult, response) {
    const stale = /claim-level evidence is still being processed/i;
    const limitations = [
      ...(baseResult?.limitations || []).filter((item) => !stale.test(String(item))),
      ...(response?.limitations || []),
    ];
    return {
      ...baseResult,
      processing_state: 'complete',
      claims_pending: false,
      claims: response.claims || [],
      factual_evidence: response.factual_evidence || baseResult?.factual_evidence,
      overall_evidence_summary: response.overall_evidence_summary || '',
      confidence: response.confidence || baseResult?.confidence || 'low',
      limitations: [...new Set(limitations)],
    };
  }

  function pollForClaims(fingerprint, analysisId, attempts, baseResult) {
    if (attempts <= 0) {
      const slot = document.getElementById('fs-claims-slot');
      if (slot) slot.innerHTML = '<div class="fs-factchecks"><div class="fs-factchecks-title">Claim evidence</div><div class="fs-body">Claim evidence is taking longer than expected. The overall result remains limited until it is available.</div></div>';
      return;
    }
    if (!chrome.runtime?.id) return;
    chrome.runtime.sendMessage({ type: 'get-claims', fingerprint, analysisId }, (resp) => {
      if (chrome.runtime.lastError) return;
      const slot = document.getElementById('fs-claims-slot');
      if (resp?.processing_state === 'failed') {
        if (slot) slot.innerHTML = buildV1ClaimsHTML([], resp.limitations || ['Claim evidence could not be loaded.']);
      } else if (resp?.processing_state === 'complete' && Array.isArray(resp.claims)) {
        const completed = mergeCompletedClaimResult(baseResult, resp);
        if (slot) slot.innerHTML = buildV1ClaimsHTML(completed.claims, resp.limitations);
        const primarySlot = document.getElementById('fs-primary-assessment-slot');
        if (primarySlot && completed.factual_evidence) {
          primarySlot.innerHTML = buildV1ArticleSummaryHTML(completed, 'summary');
        }
        const secondarySlot = document.getElementById('fs-secondary-assessment-slot');
        if (secondarySlot && completed.factual_evidence) {
          secondarySlot.innerHTML = buildV1ArticleSummaryHTML(completed, 'context');
        }
      } else if (resp && !resp.pending && Array.isArray(resp.fact_checks)) {
        if (slot) slot.innerHTML = buildFactChecksHTML(resp.fact_checks);
      } else {
        setTimeout(() => pollForClaims(fingerprint, analysisId, attempts - 1, baseResult), 3000);
      }
    });
  }

  function wireShareButton(panel, sharePayload) {
    const btn = panel.querySelector('.fs-share-btn');
    if (!btn) return;
    const actionsWrap = btn.closest('.fs-header-actions');

    function buildShareText(url) {
      const v = (sharePayload.verdict || 'uncertain').replace(/_/g, ' ');
      const s = sharePayload.score || 0;
      const d = sharePayload.domain || '';
      const emoji = s >= 70 ? '\u2705' : s >= 40 ? '\u26A0\uFE0F' : '\uD83D\uDEA8';
      const source = d ? ` from ${d}` : '';
      return `${emoji} I just ran this${source} through FactScope \u2014 scored ${s}% (${v}). See the full breakdown:\n${url}`;
    }

    function showShareRow(url) {
      let row = panel.querySelector('.fs-share-row');
      if (row) { row.style.display = 'flex'; return; }
      row = document.createElement('div');
      row.className = 'fs-share-row';
      const text = encodeURIComponent(buildShareText(url));
      row.innerHTML =
        `<button class="fs-share-icon fs-share-copy" title="Copy link">\uD83D\uDD17</button>` +
        `<a class="fs-share-icon fs-share-whatsapp" href="https://api.whatsapp.com/send?text=${text}" target="_blank" rel="noopener" title="Share on WhatsApp">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/></svg>
        </a>`;
      row.querySelector('.fs-share-copy').addEventListener('click', async () => {
        const copyBtn = row.querySelector('.fs-share-copy');
        try { await navigator.clipboard.writeText(url); } catch {}
        copyBtn.textContent = '\u2714';
        setTimeout(() => { copyBtn.textContent = '\uD83D\uDD17'; }, 2000);
      });
      if (actionsWrap) {
        actionsWrap.after(row);
      } else {
        btn.after(row);
      }
    }

    function generateAndShow() {
      btn.disabled = true;
      btn.textContent = '\u231B Generating\u2026';
      if (!chrome.runtime?.id) {
        btn.textContent = 'Share unavailable';
        btn.disabled = false;
        return;
      }
      chrome.runtime.sendMessage({ type: 'share-result', payload: sharePayload }, async (resp) => {
        if (chrome.runtime.lastError || !resp || resp.error) {
          btn.textContent = '\u2718 Failed';
          btn.disabled = false;
          setTimeout(() => { btn.textContent = '\uD83D\uDD17 Share'; }, 1500);
          return;
        }
        btn.dataset.shareUrl = resp.share_url;
        btn.textContent = '\uD83D\uDD17 Share';
        btn.disabled = false;
        showShareRow(resp.share_url);
        try { await navigator.clipboard.writeText(resp.share_url); } catch {}
      });
    }

    btn.addEventListener('click', () => {
      if (btn.disabled) return;
      const existing = panel.querySelector('.fs-share-row');
      if (existing && existing.style.display !== 'none') {
        existing.style.display = 'none';
        return;
      }
      if (btn.dataset.shareUrl) {
        showShareRow(btn.dataset.shareUrl);
        return;
      }
      generateAndShow();
    });
  }

  function showResultPanel(result, retryAction = null) {
    result = sanitizeForHTML(result);
    if (showRecoveryPanel(result, 'page', retryAction)) return;
    if (result.verdict === 'rate_limited') {
      const rl = result.rate_limit || {};
      const panel = createPanel(`
        <div class="fs-header">
          <div class="fs-logo"><svg viewBox="0 0 100 100" width="28" height="28"><circle cx="50" cy="50" r="46" fill="#4F46E5"/><circle cx="50" cy="50" r="38" fill="#6366F1"/><circle cx="50" cy="50" r="30" fill="#4F46E5"/><polyline points="33,52 45,64 68,38" fill="none" stroke="#fff" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
          <div class="fs-header-text"><div class="fs-brand">FactScope</div></div>
          <div class="fs-header-actions"><button class="fs-close" aria-label="Close">&times;</button></div>
        </div>
        <div class="fs-body" style="text-align:center;padding:20px 0;">
          <div style="font-size:32px;margin-bottom:10px;">\u23F3</div>
          <div style="font-size:16px;font-weight:700;color:#ef4444;margin-bottom:8px;">Daily Scan Limit Reached</div>
          <div style="font-size:13px;color:#64748b;line-height:1.5;">
            You\u2019ve used <strong>${rl.used || '?'}/${rl.limit || '?'}</strong> scans today on the <strong>${rl.tier || 'free'}</strong> plan.<br/>
            Your limit resets at <strong>midnight UTC</strong>.
          </div>
          <div style="margin-top:14px;font-size:12px;color:#94a3b8;">FactScope is currently in free beta. Try again after the daily reset.</div>
        </div>
        <div class="fs-footer">Scanned by FactScope</div>
      `);
      panel.querySelector('.fs-close').addEventListener('click', removePanel);
      return;
    }

    const score = result.trust_score;
    const color = scoreColor(score);
    const label = verdictLabel(result.verdict);
    const icon = verdictIcon(result.verdict);
    const isV1 = result.schema_version === '1.0' && result.factual_evidence && result.source_quality;
    const primaryAssessmentHTML = isV1
      ? `<div id="fs-primary-assessment-slot">${buildV1ArticleSummaryHTML(result, 'summary')}</div>`
      : `<div class="fs-verdict-row"><span class="fs-verdict-icon">${icon}</span><span class="fs-verdict-label" style="color:${color}">${label}</span></div><div class="fs-scorebar"><div class="fs-scorebar-fill" style="width:${score}%;background:${color}"></div></div><div class="fs-score-text"><strong style="color:${color}">${score}%</strong> trust score</div>`;

    const evidenceItems = (result.evidence || [])
      .filter((e) => e && !e.includes('unstructured'))
      .map((e) => `<li>${e}</li>`)
      .join('');

    const secondaryAssessmentHTML = isV1
      ? `<div id="fs-secondary-assessment-slot">${buildV1ArticleSummaryHTML(result, 'context')}</div>`
      : '';

    const sourceInfo = result.source_info;
    const sourceHTML = sourceInfo
      ? `<div class="fs-source">${[sourceInfo.site_name, sourceInfo.author, sourceInfo.publish_date].filter(Boolean).join(' &middot; ')}</div>`
      : '';

    let claimsSlotHTML;
    if (isV1 && result.content_classification?.checkability === 'no_checkable_claims') {
      claimsSlotHTML = '<div id="fs-claims-slot"><div class="fs-factchecks fs-empty-state"><div class="fs-factchecks-title">No checkable factual claims found</div><div class="fs-body">This page may be opinion, commentary, navigation, or another format without specific claims that can be compared with external evidence.</div><div class="fs-state-hint">Try an article or post containing a concrete statement about a person, event, number, policy, or place.</div></div></div>';
    } else if (isV1 && result.content_classification?.content_type === 'satire') {
      claimsSlotHTML = '<div id="fs-claims-slot"><div class="fs-factchecks"><div class="fs-factchecks-title">Claim evidence</div><div class="fs-body">This page was identified as satire, so its statements were not evaluated as literal factual claims.</div></div></div>';
    } else if (result.claims_pending && result.fingerprint) {
      claimsSlotHTML = `<div id="fs-claims-slot"><div class="fs-factchecks"><div class="fs-factchecks-title">${isV1 ? 'Claim evidence' : 'Claim analysis'}</div><div class="fs-loader"><div class="fs-loader-bar"></div></div><div class="fs-body fs-scanning-text">Checking claims&hellip;</div></div></div>`;
    } else if (isV1) {
      claimsSlotHTML = `<div id="fs-claims-slot">${buildV1ClaimsHTML(result.claims)}</div>`;
    } else {
      claimsSlotHTML = `<div id="fs-claims-slot">${buildFactChecksHTML(result.fact_checks)}</div>`;
    }
    const notableSignals = (result.structural_signals || [])
      .map((s) => {
        const sIcon = s.delta > 0 ? '\u2714' : '\u26A0';
        return `<li>${sIcon} ${s.detail}</li>`;
      })
      .join('');

    const signalsHTML = !isV1 && notableSignals
      ? `<details class="fs-details"><summary class="fs-details-summary">Why this score?</summary><ul class="fs-details-list">${notableSignals}</ul></details>`
      : '';

    const scansHTML = result.community_scans
      ? `<div class="fs-scans-count">Verified by ${result.community_scans} user(s)</div>`
      : '';

    const pageDomain = (() => { try { return new URL(location.href).hostname; } catch { return ''; } })();

    const panel = createPanel(`
      <div class="fs-header">
        <div class="fs-logo"><svg viewBox="0 0 100 100" width="28" height="28"><circle cx="50" cy="50" r="46" fill="#4F46E5"/><circle cx="50" cy="50" r="38" fill="#6366F1"/><circle cx="50" cy="50" r="30" fill="#4F46E5"/><polyline points="33,52 45,64 68,38" fill="none" stroke="#fff" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
        <div class="fs-header-text">
          <div class="fs-brand">FactScope</div>
        </div>
        <div class="fs-header-actions">
          <button class="fs-share-btn">\uD83D\uDD17 Share</button>
          <button class="fs-close" aria-label="Close">&times;</button>
        </div>
      </div>
      ${primaryAssessmentHTML}
      ${sourceHTML}
      ${isV1 ? '' : buildDomainProfileHTML(result.domain_profile)}
      ${isV1 ? '' : scansHTML}
      ${isV1 ? '' : `<div class="fs-body">${result.explanation || 'No explanation available.'}</div>`}
      ${!isV1 && evidenceItems ? `<div class="fs-evidence"><div class="fs-evidence-title">Supporting evidence</div><ul>${evidenceItems}</ul></div>` : ''}
      ${claimsSlotHTML}
      ${signalsHTML}
      ${secondaryAssessmentHTML}
      <div class="fs-divider fs-secondary-divider"></div>
      ${buildVoteHTML(result.vote_stats, result.fingerprint)}
      ${buildKBMatchHTML(result.kb_matches)}
      ${buildCommunitySection(result)}
      <div class="fs-footer">Scanned by FactScope</div>
    `);
    panel.querySelector('.fs-close').addEventListener('click', removePanel);

    wireShareButton(panel, {
      result_type: 'page',
      score,
      verdict: result.verdict,
      explanation: result.explanation || '',
      evidence: (result.evidence || []).slice(0, 5),
      domain: pageDomain,
      source_info: sourceInfo ? { site_name: sourceInfo.site_name, author: sourceInfo.author, publish_date: sourceInfo.publish_date } : null,
      scanned_url: location.href,
      scanned_title: document.title || '',
      fingerprint: result.fingerprint || '',
      og_image: document.querySelector('meta[property="og:image"]')?.content || '',
    });

    if (result.fingerprint) {
      wireVoteButtons(panel, result.fingerprint);
      wireFlagForm(panel, result.fingerprint);
    }

    if (result.claims_pending && result.fingerprint) {
      pollForClaims(result.fingerprint, result.analysis_id || result.fingerprint, 10, result);
    }
  }

  /* ── Social media context extraction ─────────────────────────────── */

  function extractSocialContext(imageUrl) {
    const hostname = window.location.hostname;
    const ctx = { platform: null, username: null, post_text: null, timestamp: null };

    if (hostname.includes('x.com') || hostname.includes('twitter.com')) {
      ctx.platform = 'x/twitter';

      let tweetArticle = null;
      if (imageUrl) {
        const imgs = document.querySelectorAll('img');
        for (const img of imgs) {
          if (img.src === imageUrl || img.currentSrc === imageUrl) {
            tweetArticle = img.closest('article[data-testid="tweet"]');
            break;
          }
        }
      }

      if (tweetArticle) {
        const userLink = tweetArticle.querySelector('a[href*="/"] div[dir="ltr"] > span');
        if (userLink) ctx.username = userLink.textContent?.replace('@', '').trim();
        const tweetText = tweetArticle.querySelector('[data-testid="tweetText"]');
        if (tweetText) ctx.post_text = tweetText.textContent?.substring(0, 500);
        const time = tweetArticle.querySelector('time');
        if (time) ctx.timestamp = time.getAttribute('datetime');
      }
    } else if (hostname.includes('facebook.com') || hostname.includes('fb.com')) {
      ctx.platform = 'facebook';
      const postText = document.querySelector('[data-ad-preview="message"]')?.textContent;
      if (postText) ctx.post_text = postText.substring(0, 500);
    } else if (hostname.includes('instagram.com')) {
      ctx.platform = 'instagram';
      const caption = document.querySelector('h1')?.textContent;
      if (caption) ctx.post_text = caption.substring(0, 500);
    } else if (hostname.includes('reddit.com')) {
      ctx.platform = 'reddit';
      const title = document.querySelector('h1')?.textContent;
      if (title) ctx.post_text = title.substring(0, 500);
      const author = document.querySelector('a[href*="/user/"]')?.textContent;
      if (author) ctx.username = author.replace('u/', '').trim();
    }

    return ctx;
  }

  function extractPostPermalink(imageUrl) {
    const hostname = location.hostname;

    // Twitter/X: find the tweet article containing this image, get permalink from <time>'s parent <a>
    if (hostname.includes('x.com') || hostname.includes('twitter.com')) {
      const imgs = document.querySelectorAll('img');
      for (const img of imgs) {
        if (img.src === imageUrl || img.currentSrc === imageUrl) {
          const article = img.closest('article[data-testid="tweet"]');
          if (!article) break;
          const timeLink = article.querySelector('time')?.closest('a');
          if (timeLink?.href) return timeLink.href;
          break;
        }
      }
    }

    // Reddit: find post container, look for link containing /comments/
    if (hostname.includes('reddit.com')) {
      const imgs = document.querySelectorAll('img');
      for (const img of imgs) {
        if (img.src === imageUrl || img.currentSrc === imageUrl) {
          const post = img.closest('[data-testid="post-container"], shreddit-post, .Post');
          if (!post) break;
          const link = post.querySelector('a[href*="/comments/"]');
          if (link?.href) return link.href;
          break;
        }
      }
    }

    // Facebook: look for /posts/ or /photo/ or /permalink/ links near the image
    if (hostname.includes('facebook.com') || hostname.includes('fb.com')) {
      const imgs = document.querySelectorAll('img');
      for (const img of imgs) {
        if (img.src === imageUrl || img.currentSrc === imageUrl) {
          let el = img;
          for (let i = 0; i < 12 && el; i++) {
            el = el.parentElement;
            if (!el) break;
            const link = el.querySelector('a[href*="/posts/"], a[href*="/photo/"], a[href*="/permalink/"]');
            if (link?.href) return link.href;
          }
          break;
        }
      }
    }

    // Instagram: look for /p/ or /reel/ links
    if (hostname.includes('instagram.com')) {
      const imgs = document.querySelectorAll('img');
      for (const img of imgs) {
        if (img.src === imageUrl || img.currentSrc === imageUrl) {
          let el = img;
          for (let i = 0; i < 10 && el; i++) {
            el = el.parentElement;
            if (!el) break;
            const link = el.querySelector('a[href*="/p/"], a[href*="/reel/"]');
            if (link?.href) return link.href;
          }
          break;
        }
      }
    }

    // LinkedIn: look for /feed/update/ links
    if (hostname.includes('linkedin.com')) {
      const imgs = document.querySelectorAll('img');
      for (const img of imgs) {
        if (img.src === imageUrl || img.currentSrc === imageUrl) {
          let el = img;
          for (let i = 0; i < 10 && el; i++) {
            el = el.parentElement;
            if (!el) break;
            const link = el.querySelector('a[href*="/feed/update/"]');
            if (link?.href) return link.href;
          }
          break;
        }
      }
    }

    // General fallback: walk up from the image, find nearest <a> with a deep path
    try {
      const imgs = document.querySelectorAll('img');
      for (const img of imgs) {
        if (img.src === imageUrl || img.currentSrc === imageUrl) {
          let el = img;
          for (let i = 0; i < 8 && el; i++) {
            el = el.parentElement;
            if (!el) break;
            const anchors = el.querySelectorAll('a[href]');
            for (const a of anchors) {
              try {
                const u = new URL(a.href);
                if (u.origin === location.origin && u.pathname.length > 1 && u.pathname !== location.pathname) {
                  return a.href;
                }
              } catch {}
            }
          }
          break;
        }
      }
    } catch {}

    return location.href;
  }

  /* ── Image verification UI ─────────────────────────────────────── */

  const IMG_VERDICT_LABELS = {
    authentic: 'Likely Authentic',
    ai_generated: 'Likely AI-Generated',
    manipulated: 'Possibly Manipulated',
    out_of_context: 'Possibly Out of Context',
    uncertain: 'Uncertain',
    error: 'Analysis Error',
  };

  const IMG_VERDICT_ICONS = {
    authentic: '\u2714',
    ai_generated: '\u2699',
    manipulated: '\u26A0',
    out_of_context: '\u{1F504}',
    uncertain: '\u2753',
    error: '\u2716',
  };

  function imgScoreColor(s) { return s > 70 ? '#10b981' : s > 40 ? '#f59e0b' : '#ef4444'; }

  function showImageScanningIndicator() {
    createPanel(`
      <div class="fs-header">
        <div class="fs-logo"><svg viewBox="0 0 100 100" width="28" height="28"><circle cx="50" cy="50" r="46" fill="#4F46E5"/><circle cx="50" cy="50" r="38" fill="#6366F1"/><circle cx="50" cy="50" r="30" fill="#4F46E5"/><polyline points="33,52 45,64 68,38" fill="none" stroke="#fff" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
        <div class="fs-header-text">
          <div class="fs-brand">FactScope</div>
          <div class="fs-subtitle">Verifying image&hellip;</div>
        </div>
      </div>
      <div class="fs-loader"><div class="fs-loader-bar"></div></div>
      <div class="fs-body fs-scanning-text">Checking image for AI generation, manipulation, and misuse&hellip;</div>
    `);
  }

  function showImageResultPanel(result, resolvedPageUrl, retryAction = null) {
    result = sanitizeForHTML(result);
    if (showRecoveryPanel(result, 'image', retryAction)) return;
    if (result.verdict === 'rate_limited') {
      showResultPanel(result);
      return;
    }
    const score = result.authenticity_score;
    const color = imgScoreColor(score);
    const label = IMG_VERDICT_LABELS[result.verdict] || result.verdict;
    const icon = IMG_VERDICT_ICONS[result.verdict] || '';
    const isV1 = result.schema_version === '1.0' && result.assessment;
    const primaryAssessmentHTML = isV1
      ? buildV1ImageAssessmentHTML(result)
      : `<div class="fs-verdict-row"><span class="fs-verdict-icon">${icon}</span><span class="fs-verdict-label" style="color:${color}">${label}</span></div><div class="fs-scorebar"><div class="fs-scorebar-fill" style="width:${score}%;background:${color}"></div></div><div class="fs-score-text"><strong style="color:${color}">${score}%</strong> authenticity score</div>`;

    const evidenceItems = (result.evidence || [])
      .map((e) => `<li>${e}</li>`)
      .join('');

    const captionClaims = result.assessment?.caption_consistency?.claims || [];
    const claimHTML = isV1
      ? (captionClaims.length
        ? buildV1ClaimsHTML(captionClaims, [], 'Caption claim evidence')
        : '')
      : (result.claim_analysis ? buildFactChecksHTML(result.claim_analysis) : '');

    const imgDomain = (() => { try { return new URL(location.href).hostname; } catch { return ''; } })();

    const panel = createPanel(`
      <div class="fs-header">
        <div class="fs-logo"><svg viewBox="0 0 100 100" width="28" height="28"><circle cx="50" cy="50" r="46" fill="#4F46E5"/><circle cx="50" cy="50" r="38" fill="#6366F1"/><circle cx="50" cy="50" r="30" fill="#4F46E5"/><polyline points="33,52 45,64 68,38" fill="none" stroke="#fff" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
        <div class="fs-header-text">
          <div class="fs-brand">FactScope</div>
          <div class="fs-subtitle">Image Verification</div>
        </div>
        <div class="fs-header-actions">
          <button class="fs-share-btn">\uD83D\uDD17 Share</button>
          <button class="fs-close" aria-label="Close">&times;</button>
        </div>
      </div>
      ${primaryAssessmentHTML}
      ${isV1 ? '' : `<div class="fs-body">${result.explanation || 'No explanation available.'}</div>`}
      ${!isV1 && evidenceItems ? `<div class="fs-evidence"><div class="fs-evidence-title">What we found</div><ul>${evidenceItems}</ul></div>` : ''}
      ${claimHTML}
      <div class="fs-divider fs-secondary-divider"></div>
      ${buildVoteHTML(result.vote_stats, result.fingerprint)}
      ${buildCommunitySection(result)}
      <div class="fs-footer">Scanned by FactScope</div>
    `);
    panel.querySelector('.fs-close').addEventListener('click', removePanel);

    wireShareButton(panel, {
      result_type: 'image',
      score,
      verdict: result.verdict,
      explanation: result.explanation || '',
      evidence: (result.evidence || []).slice(0, 5),
      domain: imgDomain,
      scanned_url: resolvedPageUrl || location.href,
      scanned_title: document.title || '',
      fingerprint: result.fingerprint || '',
      og_image: document.querySelector('meta[property="og:image"]')?.content || '',
    });

    if (result.fingerprint) {
      wireVoteButtons(panel, result.fingerprint);
      wireFlagForm(panel, result.fingerprint);
    }
  }

  /* ── Image verification flow (triggered by context menu) ─────────── */

  async function verifyImage(imageUrl, pageUrl) {
    const consented = await ensureScanConsent('image');
    if (!consented) return;

    showImageScanningIndicator();

    const resolvedUrl = extractPostPermalink(imageUrl) || pageUrl;

    const socialContext = extractSocialContext(imageUrl);
    const pageText = socialContext.post_text
      || (socialContext.platform ? null : extractArticleBody().substring(0, 1000));

    const payload = {
      image_url: imageUrl,
      page_url: resolvedUrl,
      page_text: pageText || null,
      social_context: socialContext.platform ? socialContext : null,
    };

    const result = await new Promise((resolve) => {
      if (!chrome.runtime?.id) {
        resolve({
          authenticity_score: 0,
          verdict: 'error',
          explanation: 'Extension was reloaded. Please refresh this page and try again.',
          evidence: [],
        });
        return;
      }
      chrome.runtime.sendMessage({ type: 'verify-image', payload }, (response) => {
        if (chrome.runtime.lastError) {
          resolve({
            authenticity_score: 0,
            verdict: 'error',
            explanation: 'Lost connection to FactScope. Please refresh this page and try again.',
            evidence: [],
          });
          return;
        }
        resolve(response);
      });
    });

    if (result && result.authenticity_score !== undefined) {
      showImageResultPanel(result, resolvedUrl, () => verifyImage(imageUrl, pageUrl));
      if (!classifyRecoveryState(result, 'image') && result.verdict !== 'rate_limited' && chrome.runtime?.id) {
        chrome.runtime.sendMessage({ type: 'update-badge', score: result.authenticity_score });
      }
    } else {
      showImageResultPanel({
        authenticity_score: 50,
        verdict: 'uncertain',
        processing_state: 'failed',
        error_state: 'connection_problem',
        retryable: true,
        explanation: 'FactScope did not receive a usable image-analysis response.',
        evidence: [],
      }, resolvedUrl, () => verifyImage(imageUrl, pageUrl));
    }
  }

  /* ── Listen for messages from service worker ────────────────────── */

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'factscope-ping') {
      sendResponse({ ready: true });
      return false;
    }
    if (message.type === 'factscope-start-page-scan') {
      void scanPage();
      sendResponse({ started: true });
      return false;
    }
    if (message.type === 'factscope-verify-image-start') {
      void verifyImage(message.imageUrl, message.pageUrl);
      sendResponse({ started: true });
      return false;
    }
  });

  /* ── Scan orchestration ───────────────────────────────────────────── */

  async function scanPage() {
    const consented = await ensureScanConsent('page');
    if (!consented) return;

    showScanningIndicator();
    const payload = extractPageContent();
    const result = await analyzePayload(payload);

    if (result && result.trust_score !== undefined) {
      showResultPanel(result, scanPage);
      if (!classifyRecoveryState(result, 'page') && result.verdict !== 'rate_limited' && chrome.runtime?.id) {
        chrome.runtime.sendMessage({ type: 'update-badge', score: result.trust_score });
      }
    } else {
      showResultPanel({
        trust_score: 50,
        verdict: 'unknown',
        processing_state: 'failed',
        error_state: 'connection_problem',
        retryable: true,
        explanation: 'FactScope did not receive a usable page-analysis response.',
        evidence: [],
      }, scanPage);
    }
  }

  window.addEventListener(SCAN_EVENT, scanPage);
})();
