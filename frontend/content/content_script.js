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
    } else {
      notesHTML = '<p class="fs-no-notes">No crowd insights yet — be the first to weigh in</p>';
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

  function pollForClaims(fingerprint, attempts) {
    if (attempts <= 0) {
      const slot = document.getElementById('fs-claims-slot');
      if (slot) slot.innerHTML = '<div class="fs-factchecks"><div class="fs-factchecks-title">Claim analysis</div><div class="fs-body">Claims could not be loaded.</div></div>';
      return;
    }
    if (!chrome.runtime?.id) return;
    chrome.runtime.sendMessage({ type: 'get-claims', fingerprint }, (resp) => {
      if (chrome.runtime.lastError) return;
      if (resp && !resp.pending && resp.fact_checks) {
        const slot = document.getElementById('fs-claims-slot');
        if (slot) slot.innerHTML = buildFactChecksHTML(resp.fact_checks);
      } else {
        setTimeout(() => pollForClaims(fingerprint, attempts - 1), 3000);
      }
    });
  }

  function wireShareButton(panel, sharePayload) {
    const btn = panel.querySelector('.fs-share-btn');
    if (!btn) return;

    async function copyAndFlash(url) {
      try {
        await navigator.clipboard.writeText(url);
        btn.textContent = '\u2714 Link copied!';
        btn.classList.add('fs-share-copied');
      } catch {
        btn.textContent = '\u2714 Link ready';
        btn.classList.add('fs-share-copied');
      }
      btn.disabled = false;
      setTimeout(() => {
        btn.textContent = '\uD83D\uDD17 Share result';
        btn.classList.remove('fs-share-copied');
      }, 3000);
    }

    btn.addEventListener('click', () => {
      if (btn.disabled) return;
      btn.disabled = true;

      if (btn.dataset.shareUrl) {
        copyAndFlash(btn.dataset.shareUrl);
        return;
      }

      btn.textContent = '\u231B Generating link\u2026';

      if (!chrome.runtime?.id) {
        btn.textContent = 'Share unavailable';
        btn.disabled = false;
        return;
      }
      chrome.runtime.sendMessage({ type: 'share-result', payload: sharePayload }, (resp) => {
        if (chrome.runtime.lastError || !resp || resp.error) {
          btn.textContent = '\u2718 Failed';
          btn.disabled = false;
          setTimeout(() => { btn.textContent = '\uD83D\uDD17 Share result'; }, 1500);
          return;
        }
        btn.dataset.shareUrl = resp.share_url;
        copyAndFlash(resp.share_url);
      });
    });
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

    let claimsSlotHTML;
    if (result.claims_pending && result.fingerprint) {
      claimsSlotHTML = '<div id="fs-claims-slot"><div class="fs-factchecks"><div class="fs-factchecks-title">Claim analysis</div><div class="fs-loader"><div class="fs-loader-bar"></div></div><div class="fs-body fs-scanning-text">Checking claims&hellip;</div></div></div>';
    } else {
      claimsSlotHTML = `<div id="fs-claims-slot">${buildFactChecksHTML(result.fact_checks)}</div>`;
    }

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

    const scansHTML = result.community_scans
      ? `<div class="fs-scans-count">Verified by ${result.community_scans} user(s)</div>`
      : '';

    const pageDomain = (() => { try { return new URL(location.href).hostname; } catch { return ''; } })();

    const panel = createPanel(`
      <div class="fs-header">
        <div class="fs-logo">FS</div>
        <div class="fs-header-text">
          <div class="fs-brand">FactScope</div>
        </div>
        <div class="fs-header-actions">
          <button class="fs-share-btn">\uD83D\uDD17 Share result</button>
          <button class="fs-close" aria-label="Close">&times;</button>
        </div>
      </div>
      <div class="fs-verdict-row">
        <span class="fs-verdict-icon">${icon}</span>
        <span class="fs-verdict-label" style="color:${color}">${label}</span>
      </div>
      <div class="fs-scorebar"><div class="fs-scorebar-fill" style="width:${score}%;background:${color}"></div></div>
      <div class="fs-score-text"><strong style="color:${color}">${score}%</strong> trust score</div>
      ${sourceHTML}
      ${buildDomainProfileHTML(result.domain_profile)}
      ${scansHTML}
      ${buildVoteHTML(result.vote_stats, result.fingerprint)}
      ${buildKBMatchHTML(result.kb_matches)}
      ${buildCommunitySection(result)}
      <div class="fs-divider"></div>
      <div class="fs-body">${result.explanation || 'No explanation available.'}</div>
      ${evidenceItems ? `<div class="fs-evidence"><div class="fs-evidence-title">Supporting evidence</div><ul>${evidenceItems}</ul></div>` : ''}
      ${claimsSlotHTML}
      ${signalsHTML}
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
    });

    if (result.fingerprint) {
      wireVoteButtons(panel, result.fingerprint);
      wireFlagForm(panel, result.fingerprint);
    }

    if (result.claims_pending && result.fingerprint) {
      pollForClaims(result.fingerprint, 10);
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
        <div class="fs-logo">FS</div>
        <div class="fs-header-text">
          <div class="fs-brand">FactScope</div>
          <div class="fs-subtitle">Verifying image&hellip;</div>
        </div>
      </div>
      <div class="fs-loader"><div class="fs-loader-bar"></div></div>
      <div class="fs-body fs-scanning-text">Checking image for AI generation, manipulation, and misuse&hellip;</div>
    `);
  }

  function showImageResultPanel(result) {
    const score = result.authenticity_score;
    const color = imgScoreColor(score);
    const label = IMG_VERDICT_LABELS[result.verdict] || result.verdict;
    const icon = IMG_VERDICT_ICONS[result.verdict] || '';

    const evidenceItems = (result.evidence || [])
      .map((e) => `<li>${e}</li>`)
      .join('');

    const claimHTML = result.claim_analysis ? buildFactChecksHTML(result.claim_analysis) : '';

    const imgDomain = (() => { try { return new URL(location.href).hostname; } catch { return ''; } })();

    const panel = createPanel(`
      <div class="fs-header">
        <div class="fs-logo">FS</div>
        <div class="fs-header-text">
          <div class="fs-brand">FactScope</div>
          <div class="fs-subtitle">Image Verification</div>
        </div>
        <div class="fs-header-actions">
          <button class="fs-share-btn">\uD83D\uDD17 Share result</button>
          <button class="fs-close" aria-label="Close">&times;</button>
        </div>
      </div>
      <div class="fs-verdict-row">
        <span class="fs-verdict-icon">${icon}</span>
        <span class="fs-verdict-label" style="color:${color}">${label}</span>
      </div>
      <div class="fs-scorebar"><div class="fs-scorebar-fill" style="width:${score}%;background:${color}"></div></div>
      <div class="fs-score-text"><strong style="color:${color}">${score}%</strong> authenticity score</div>
      ${buildVoteHTML(result.vote_stats, result.fingerprint)}
      ${buildCommunitySection(result)}
      <div class="fs-divider"></div>
      <div class="fs-body">${result.explanation || 'No explanation available.'}</div>
      ${evidenceItems ? `<div class="fs-evidence"><div class="fs-evidence-title">What we found</div><ul>${evidenceItems}</ul></div>` : ''}
      ${claimHTML}
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
      scanned_url: location.href,
      scanned_title: document.title || '',
      fingerprint: result.fingerprint || '',
    });

    if (result.fingerprint) {
      wireVoteButtons(panel, result.fingerprint);
      wireFlagForm(panel, result.fingerprint);
    }
  }

  /* ── Image verification flow (triggered by context menu) ─────────── */

  async function verifyImage(imageUrl, pageUrl) {
    showImageScanningIndicator();

    const socialContext = extractSocialContext(imageUrl);
    const pageText = socialContext.post_text
      || (socialContext.platform ? null : extractArticleBody().substring(0, 1000));

    const payload = {
      image_url: imageUrl,
      page_url: pageUrl,
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
      showImageResultPanel(result);
      if (chrome.runtime?.id) {
        chrome.runtime.sendMessage({ type: 'update-badge', score: result.authenticity_score });
      }
    } else {
      showImageResultPanel({
        authenticity_score: 0,
        verdict: 'error',
        explanation: 'Could not verify this image. Make sure the FactScope backend is running.',
        evidence: [],
      });
    }
  }

  /* ── Listen for messages from service worker ────────────────────── */

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'factscope-verify-image-start') {
      verifyImage(message.imageUrl, message.pageUrl);
    }
  });

  /* ── Scan orchestration ───────────────────────────────────────────── */

  async function scanPage() {
    showScanningIndicator();
    const payload = extractPageContent();
    const result = await analyzePayload(payload);

    if (result && result.trust_score !== undefined) {
      showResultPanel(result);
      if (chrome.runtime?.id) {
        chrome.runtime.sendMessage({ type: 'update-badge', score: result.trust_score });
      }
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
