(() => {
  const SCAN_EVENT = 'factscope-scan';

  function analyzePayload(payload) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: 'analyze', payload }, (response) => {
        resolve(response);
      });
    });
  }

  function findCandidates() {
    const candidates = [];
    document.querySelectorAll('div').forEach(div => {
      const text = div.innerText && div.innerText.trim();
      const links = Array.from(div.querySelectorAll('a')).map(a => a.href);
      const imgs = Array.from(div.querySelectorAll('img')).map(i => i.src);
      if ((text && text.length > 20) || links.length || imgs.length) {
        candidates.push({ node: div, text, links, imgs });
      }
    });
    return candidates;
  }

  function attachBadge(node, result) {
    if (node.querySelector('.factscope-badge')) return;
    const badge = document.createElement('div');
    badge.className = 'factscope-badge';
    badge.textContent = `${result.trust_score}%`;
    badge.style.background = result.trust_score > 70 ? '#2ecc71' : result.trust_score > 40 ? '#f1c40f' : '#e74c3c';
    badge.title = 'Click for FactScope details';
    badge.addEventListener('click', (e) => {
      e.stopPropagation();
      showDetailPopup(node, result);
    });
    node.style.position = 'relative';
    node.appendChild(badge);
  }

  function showDetailPopup(node, result) {
    const existing = document.querySelector('.factscope-popup');
    if (existing) existing.remove();

    const evidenceItems = (result.evidence || []).length
      ? (result.evidence || []).map(e => `<li>${e}</li>`).join('')
      : '<li>No evidence provided for this snippet.</li>';

    const popup = document.createElement('div');
    popup.className = 'factscope-popup';
    popup.innerHTML = `
      <div class="tl-header">
        <div class="logo-dot">FS</div>
        <div class="tl-meta">
          <div class="tl-title">FactScope</div>
          <div class="tl-score">${result.trust_score}% confidence</div>
        </div>
        <button class="tl-close" aria-label="Close">×</button>
      </div>
      <div class="tl-body">${result.explanation}</div>
      <div class="tl-evidence">
        <strong>Evidence</strong>
        <ul>${evidenceItems}</ul>
      </div>
    `;
    popup.querySelector('.tl-close').addEventListener('click', ()=> popup.remove());
    document.body.appendChild(popup);
    const rect = node.getBoundingClientRect();
    popup.style.top = (rect.top + window.scrollY + 10) + 'px';
    popup.style.left = (rect.left + window.scrollX + 10) + 'px';
  }

  async function scanAndAnalyze() {
    const candidates = findCandidates();
    for (const c of candidates) {
      const payload = { text: c.text, links: c.links, sample_img: c.imgs[0] || null };
      const res = await analyzePayload(payload);
      if (res) attachBadge(c.node, res);
    }
  }

  window.addEventListener(SCAN_EVENT, scanAndAnalyze);

  const observer = new MutationObserver(()=> scanAndAnalyze());
  observer.observe(document.body, { childList: true, subtree: true });

  setTimeout(scanAndAnalyze, 2000);
})();
