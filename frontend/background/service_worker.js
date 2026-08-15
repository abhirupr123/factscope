// Developer-only evaluation helper. Uncomment locally when collecting an audit export.
// if (typeof importScripts === 'function') importScripts('evaluation_capture.js');

const API_BASE = 'https://factscope-api.onrender.com';

const SESSION_TOKEN_KEY = 'factscope_session_token';
const SESSION_EXPIRY_KEY = 'factscope_session_expires_at';
const TELEMETRY_ENABLED_KEY = 'factscope_telemetry_enabled';
const HISTORY_KEY = 'factscope_history';
const V1_API_ENABLED_KEY = 'factscope_use_v1_api';
/* Developer-only evaluation constants (disabled in production).
const EVALUATION_MODE_KEY = 'factscope_evaluation_mode';
const EVALUATION_CASES_KEY = 'factscope_evaluation_cases';
const EVALUATION_PENDING_KEY = 'factscope_evaluation_pending';
const MAX_EVALUATION_CASES = 100;
const MAX_PENDING_EVALUATIONS = 25;
const EVALUATION_PENDING_TTL_MS = 24 * 60 * 60 * 1000;
*/
const V1_FALLBACK_STATUSES = new Set([404, 405, 501]);
let _sessionPromise = null;

function storageGet(keys) {
  return new Promise((resolve) => {
    chrome.storage.local.get(keys, resolve);
  });
}

function storageSet(values) {
  return new Promise((resolve) => chrome.storage.local.set(values, resolve));
}

function storageRemove(keys) {
  return new Promise((resolve) => chrome.storage.local.remove(keys, resolve));
}

async function getSessionToken(forceRefresh = false) {
  if (!forceRefresh) {
    const stored = await storageGet([SESSION_TOKEN_KEY, SESSION_EXPIRY_KEY]);
    const expiresAt = Date.parse(stored[SESSION_EXPIRY_KEY] || '');
    if (stored[SESSION_TOKEN_KEY] && expiresAt > Date.now() + 5 * 60 * 1000) {
      return stored[SESSION_TOKEN_KEY];
    }
    if (_sessionPromise) return _sessionPromise;
  } else {
    await storageRemove([SESSION_TOKEN_KEY, SESSION_EXPIRY_KEY]);
  }

  _sessionPromise = (async () => {
    const response = await fetch(`${API_BASE}/v1/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!response.ok) throw new Error(`Session service returned ${response.status}`);
    const session = await response.json();
    if (!session.access_token || !session.expires_at) throw new Error('Invalid session response');
    await storageSet({
      [SESSION_TOKEN_KEY]: session.access_token,
      [SESSION_EXPIRY_KEY]: session.expires_at,
    });
    return session.access_token;
  })();

  try {
    return await _sessionPromise;
  } finally {
    _sessionPromise = null;
  }
}

async function apiFetch(path, options = {}, retryAuth = true) {
  const token = await getSessionToken();
  const headers = new Headers(options.headers || {});
  headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (response.status === 401 && retryAuth) {
    await getSessionToken(true);
    return apiFetch(path, options, false);
  }
  return response;
}

async function isV1ApiEnabled() {
  const stored = await storageGet([V1_API_ENABLED_KEY]);
  return stored[V1_API_ENABLED_KEY] !== false;
}

async function apiFetchVersioned(v1Path, legacyPath, options = {}) {
  if (!(await isV1ApiEnabled())) {
    return { response: await apiFetch(legacyPath, options), contract: 'legacy' };
  }

  const response = await apiFetch(v1Path, options);
  if (!V1_FALLBACK_STATUSES.has(response.status)) {
    return { response, contract: 'v1' };
  }

  // Only route-level failures are replayed. Provider errors, timeouts, quota
  // responses, and other 5xx statuses must never cause a duplicate analysis.
  console.warn(`FactScope v1 route unavailable (${response.status}); using legacy contract.`);
  return { response: await apiFetch(legacyPath, options), contract: 'legacy' };
}

function buildFailureResult(state, modality, details = {}) {
  const messages = {
    offline: 'You appear to be offline. Reconnect to the internet and try again.',
    cold_start: 'The FactScope service is waking up. Wait a moment, then try again.',
    timeout: 'The analysis took longer than expected. Try again when your connection is stable.',
    provider_failure: 'The analysis provider is temporarily unavailable. Try again later.',
    server_busy: 'FactScope is handling several scans right now. Wait a moment, then try again.',
    blocked_image: 'The selected image could not be accessed. It may block external access or be too large.',
    unsupported_page: 'This page cannot be scanned by a browser extension. Open a regular webpage and try again.',
    connection_problem: 'FactScope could not reach the analysis service. Check your connection and try again.',
    request_too_large: 'This page contains more content than FactScope can safely process. Try a shorter article or post.',
  };
  const retryable = !['unsupported_page', 'request_too_large'].includes(state);
  return {
    schema_version: '1.0',
    processing_state: 'failed',
    error_state: state,
    error_code: details.code || state,
    request_id: details.requestId || null,
    retryable,
    trust_score: 50,
    authenticity_score: 50,
    verdict: modality === 'image' ? 'uncertain' : 'unknown',
    explanation: messages[state] || messages.connection_problem,
    evidence: [],
  };
}

async function failureFromResponse(response, modality) {
  let payload = {};
  try { payload = await response.json(); } catch {}
  const code = String(payload.error || payload.code || '');
  let state = 'connection_problem';
  if (code === 'provider_timeout' || response.status === 504) state = 'timeout';
  else if (code === 'server_busy' || code === 'burst_limited' || code === 'cache_request_limited') state = 'server_busy';
  else if (code === 'budget_exhausted' || code === 'internal_error') state = 'provider_failure';
  else if (code === 'request_too_large' || response.status === 413) state = 'request_too_large';
  else if (response.status === 502 || (response.status === 503 && !code)) state = 'cold_start';
  else if (response.status >= 500) state = 'provider_failure';
  return buildFailureResult(state, modality, {
    code: code || `http_${response.status}`,
    requestId: payload.request_id,
  });
}

function failureFromException(error, modality) {
  const offline = globalThis.navigator?.onLine === false;
  const timedOut = error?.name === 'AbortError' || /timed?\s*out|timeout/i.test(String(error?.message || ''));
  return buildFailureResult(offline ? 'offline' : (timedOut ? 'timeout' : 'connection_problem'), modality, {
    code: offline ? 'offline' : (timedOut ? 'client_timeout' : 'network_error'),
  });
}
async function recordTelemetry(event) {
  const allowedEvents = new Set([
    'page_scan_completed',
    'image_scan_completed',
    'scan_failed',
    'history_cleared',
  ]);
  if (!allowedEvents.has(event)) return;
  const stored = await storageGet([TELEMETRY_ENABLED_KEY]);
  if (stored[TELEMETRY_ENABLED_KEY] !== true) return;
  try {
    await apiFetch('/v1/telemetry', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event }),
    });
  } catch {
    // Telemetry is best-effort and never affects product behavior.
  }
}

function sendTabMessage(tabId, message) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(response);
      }
    });
  });
}

async function ensureFactScopeInjected(tabId) {
  try {
    const response = await sendTabMessage(tabId, { type: 'factscope-ping' });
    if (response?.ready) return;
  } catch {
    // The page has not received the action-triggered script yet.
  }
  await chrome.scripting.insertCSS({ target: { tabId }, files: ['content/overlay.css'] });
  await chrome.scripting.executeScript({ target: { tabId }, files: ['content/content_script.js'] });
}

async function startPageScan(tabId) {
  await ensureFactScopeInjected(tabId);
  await sendTabMessage(tabId, { type: 'factscope-start-page-scan' });
}

/* ── Context menu for image verification ──────────────────────────── */

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'factscope-verify-image',
    title: 'Verify image with FactScope',
    contexts: ['image'],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'factscope-verify-image' && info.srcUrl) {
    try {
      await ensureFactScopeInjected(tab.id);
      await sendTabMessage(tab.id, {
        type: 'factscope-verify-image-start',
        imageUrl: info.srcUrl,
        pageUrl: info.pageUrl || tab.url,
      });
    } catch (error) {
      console.warn('FactScope cannot run on this page:', error.message);
    }
  }
});

/* ── Badge indicator ──────────────────────────────────────────────── */

function updateBadge(tabId, score) {
  const text = String(Math.round(score));
  const color = score >= 70 ? '#22c55e' : score >= 40 ? '#f59e0b' : '#ef4444';
  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeTextColor({ color: '#ffffff', tabId });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    chrome.action.setBadgeText({ text: '', tabId });
  }
});

/* ── Scan history helpers ────────────────────────────────────────── */

const MAX_HISTORY = 15;

function saveHistoryEntry(entry) {
  chrome.storage.local.get(HISTORY_KEY, (data) => {
    const history = data[HISTORY_KEY] || [];
    history.unshift(entry);
    if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
    chrome.storage.local.set({ [HISTORY_KEY]: history });
  });
}

/* ── Message routing ──────────────────────────────────────────────── */

/* Developer-only local evidence evaluation capture (disabled in production).
function evaluationPublisher(payload, sender) {
  const siteName = payload?.metadata?.site_name;
  if (siteName) return siteName;
  const rawUrl = payload?.url || payload?.page_url || sender?.tab?.url || '';
  try { return new URL(rawUrl).hostname; } catch { return 'Unknown public publisher'; }
}

async function evaluationModeEnabled() {
  const stored = await storageGet([EVALUATION_MODE_KEY]);
  return stored[EVALUATION_MODE_KEY] === true;
}

async function storeEvaluationCase(auditCase, analysisId, modality) {
  if (!auditCase) return false;
  const stored = await storageGet([EVALUATION_CASES_KEY]);
  const cases = Array.isArray(stored[EVALUATION_CASES_KEY]) ? stored[EVALUATION_CASES_KEY] : [];
  const record = {
    ...auditCase,
    _analysis_id: String(analysisId || ''),
    _modality: modality,
    _captured_at: new Date().toISOString(),
  };
  const existing = record._analysis_id
    ? cases.findIndex((item) => item?._analysis_id === record._analysis_id)
    : -1;
  if (existing >= 0) cases.splice(existing, 1);
  cases.unshift(record);
  if (cases.length > MAX_EVALUATION_CASES) cases.length = MAX_EVALUATION_CASES;
  await storageSet({ [EVALUATION_CASES_KEY]: cases });
  return true;
}

async function rememberPendingEvaluation(analysisId, claimOriginPublisher, modality) {
  if (!analysisId) return;
  const stored = await storageGet([EVALUATION_PENDING_KEY]);
  const pending = stored[EVALUATION_PENDING_KEY] && typeof stored[EVALUATION_PENDING_KEY] === 'object'
    ? stored[EVALUATION_PENDING_KEY] : {};
  pending[String(analysisId)] = {
    claim_origin_publisher: String(claimOriginPublisher || '').slice(0, 120),
    modality,
    created_at: Date.now(),
  };
  const cutoff = Date.now() - EVALUATION_PENDING_TTL_MS;
  const entries = Object.entries(pending)
    .filter(([, value]) => (value?.created_at || 0) >= cutoff)
    .sort((a, b) => (b[1]?.created_at || 0) - (a[1]?.created_at || 0))
    .slice(0, MAX_PENDING_EVALUATIONS);
  await storageSet({ [EVALUATION_PENDING_KEY]: Object.fromEntries(entries) });
}

async function captureEvaluationClaims({ claims, analysisId, claimOriginPublisher, modality }) {
  if (!(await evaluationModeEnabled()) || !globalThis.FactScopeEvaluation) return false;
  const auditCase = FactScopeEvaluation.buildAuditCase({
    auditCaseId: `eval-${crypto.randomUUID()}`,
    curatedOn: new Date().toISOString().slice(0, 10),
    claims,
    claimOriginPublisher,
  });
  return storeEvaluationCase(auditCase, analysisId, modality);
}

async function capturePageEvaluation(data, payload, sender) {
  if (!(await evaluationModeEnabled())) return;
  const claimOriginPublisher = evaluationPublisher(payload, sender);
  const captured = await captureEvaluationClaims({
    claims: data?.claims,
    analysisId: data?.analysis_id,
    claimOriginPublisher,
    modality: 'article',
  });
  if (!captured && data?.analysis_id && (data?.claims_pending || data?.processing_state === 'processing')) {
    await rememberPendingEvaluation(data.analysis_id, claimOriginPublisher, 'article');
  }
}

async function captureImageEvaluation(data, payload, sender) {
  await captureEvaluationClaims({
    claims: data?.assessment?.caption_consistency?.claims,
    analysisId: data?.analysis_id,
    claimOriginPublisher: evaluationPublisher(payload, sender),
    modality: 'image',
  });
}

async function completePendingEvaluation(analysisId, claimResponse) {
  if (!(await evaluationModeEnabled()) || !analysisId) return false;
  const stored = await storageGet([EVALUATION_PENDING_KEY]);
  const pending = stored[EVALUATION_PENDING_KEY] && typeof stored[EVALUATION_PENDING_KEY] === 'object'
    ? stored[EVALUATION_PENDING_KEY] : {};
  const item = pending[String(analysisId)];
  if (!item) return false;
  if (!FactScopeEvaluation.isCompletedClaimResponse(claimResponse)) return false;

  const captured = await captureEvaluationClaims({
    claims: claimResponse.claims,
    analysisId,
    claimOriginPublisher: item.claim_origin_publisher,
    modality: item.modality || 'article',
  });
  // A completed response cannot gain more claims. Remove it whether it had
  // exportable displayed evidence or completed legitimately without any.
  delete pending[String(analysisId)];
  await storageSet({ [EVALUATION_PENDING_KEY]: pending });
  return captured;
}

async function getEvaluationState() {
  const stored = await storageGet([EVALUATION_MODE_KEY, EVALUATION_CASES_KEY]);
  const cases = Array.isArray(stored[EVALUATION_CASES_KEY]) ? stored[EVALUATION_CASES_KEY] : [];
  return {
    enabled: stored[EVALUATION_MODE_KEY] === true,
    cases: cases.map((item) => ({
      audit_case_id: item.audit_case_id,
      modality: item._modality || 'article',
      captured_at: item._captured_at || '',
      publisher: item.claims?.[0]?.claim_origin_publisher || 'Unknown public publisher',
      claim_count: Array.isArray(item.claims) ? item.claims.length : 0,
      source_count: Array.isArray(item.claims)
        ? item.claims.reduce((sum, claim) => sum + (Array.isArray(claim.evidence) ? claim.evidence.length : 0), 0)
        : 0,
    })),
  };
}
*/
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'start-page-scan') {
    (async () => {
      try {
        await startPageScan(message.tabId);
        sendResponse({ success: true });
      } catch {
        sendResponse({
          success: false,
          error_state: 'unsupported_page',
          error: 'This browser page cannot be scanned. Open a regular http or https webpage and try again.',
        });
      }
    })();
    return true;
  }

  if (message.type === 'update-badge') {
    const tabId = sender.tab?.id;
    if (tabId && typeof message.score === 'number') {
      updateBadge(tabId, message.score);
    }
    return false;
  }

  if (message.type === 'analyze') {
    (async () => {
      const payload = { ...message.payload };
      try {
        const { response: r, contract } = await apiFetchVersioned('/v1/analyze', '/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (r.status === 429) {
          const rl = await r.json();
          sendResponse({
            trust_score: 0,
            verdict: 'rate_limited',
            explanation: `Daily scan limit reached (${rl.used}/${rl.limit}). Resets at midnight UTC.`,
            evidence: [],
            rate_limit: rl,
          });
          return;
        }
        if (!r.ok) {
          sendResponse(await failureFromResponse(r, 'page'));
          return;
        }
        const data = await r.json();
        data.api_contract = contract;
        if (data.verdict !== 'error' && data.processing_state !== 'failed') {
          const url = payload.url || sender.tab?.url || '';
          let domain = '';
          try { domain = new URL(url).hostname; } catch {}
          saveHistoryEntry({
            url,
            title: payload.title || sender.tab?.title || domain,
            domain,
            score: data.trust_score,
            verdict: data.verdict,
            evidence_status: data.factual_evidence?.status || null,
            confidence: data.factual_evidence?.confidence || null,
            api_contract: contract,
            type: 'page',
            timestamp: Date.now(),
          });
        }
        // Developer evaluation capture disabled: await capturePageEvaluation(data, payload, sender);
        sendResponse(data);
        void recordTelemetry(data.processing_state === 'failed' ? 'scan_failed' : 'page_scan_completed');
      } catch (err) {
        console.error('FactScope backend error:', err);
        void recordTelemetry('scan_failed');
        sendResponse(failureFromException(err, 'page'));

      }
    })();
    return true;
  }

  if (message.type === 'verify-image') {
    (async () => {
      const payload = { ...message.payload };
      try {
        const { response: r, contract } = await apiFetchVersioned(
          '/v1/analyze/verify-image',
          '/analyze/verify-image',
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          },
        );
        if (r.status === 429) {
          const rl = await r.json();
          sendResponse({
            authenticity_score: 0,
            verdict: 'rate_limited',
            explanation: `Daily scan limit reached (${rl.used}/${rl.limit}). Resets at midnight UTC.`,
            evidence: [],
            rate_limit: rl,
          });
          return;
        }
        if (!r.ok) {
          sendResponse(await failureFromResponse(r, 'image'));
          return;
        }
        const data = await r.json();
        data.api_contract = contract;
        if (data.verdict !== 'error' && data.processing_state !== 'failed') {
          const pageUrl = payload.page_url || sender.tab?.url || '';
          let domain = '';
          try { domain = new URL(pageUrl).hostname; } catch {}
          saveHistoryEntry({
            url: pageUrl,
            title: sender.tab?.title || domain,
            domain,
            score: data.authenticity_score,
            verdict: data.verdict,
            manipulation_status: data.assessment?.manipulation?.status || null,
            caption_status: data.assessment?.caption_consistency?.status || null,
            confidence: data.assessment?.manipulation?.confidence || null,
            api_contract: contract,
            type: 'image',
            timestamp: Date.now(),
          });
        }
        // Developer evaluation capture disabled: await captureImageEvaluation(data, payload, sender);
        sendResponse(data);
        void recordTelemetry(data.processing_state === 'failed' ? 'scan_failed' : 'image_scan_completed');
      } catch (err) {
        console.error('FactScope image verify error:', err);
        void recordTelemetry('scan_failed');
        sendResponse(failureFromException(err, 'image'));

      }
    })();
    return true;
  }

  if (message.type === 'get-claims') {
    (async () => {
      try {
        const analysisId = message.analysisId || message.fingerprint;
        const { response: r, contract } = await apiFetchVersioned(
          `/v1/analyses/${encodeURIComponent(analysisId)}/claims`,
          `/claims/${encodeURIComponent(message.fingerprint)}`,
        );
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        const data = await r.json();
        data.api_contract = contract;
        // Developer evaluation capture disabled: await completePendingEvaluation(analysisId, data);
        sendResponse(data);
      } catch (err) {
        sendResponse({ pending: true, processing_state: 'processing', fact_checks: null, claims: null });
      }
    })();
    return true;
  }

  if (message.type === 'flag-content') {
    (async () => {
      try {
        const r = await apiFetch('/flag', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            fingerprint: message.fingerprint,
            category: message.category,
            justification: message.justification,
            source_urls: message.source_urls || null,
          }),
        });
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        const data = await r.json();
        sendResponse(data);
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }

  if (message.type === 'vote') {
    (async () => {
      try {
        const r = await apiFetch('/vote', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            fingerprint: message.fingerprint,
            vote: message.vote,
          }),
        });
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        sendResponse(await r.json());
      } catch (err) {
        sendResponse({ success: false });
      }
    })();
    return true;
  }

  if (message.type === 'get-community-notes') {
    (async () => {
      try {
        const r = await apiFetch(`/community-notes/${encodeURIComponent(message.fingerprint)}`);
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        sendResponse(await r.json());
      } catch (err) {
        sendResponse({ notes: [], vote_stats: { likes: 0, dislikes: 0 }, flag_count: 0 });
      }
    })();
    return true;
  }

  if (message.type === 'get-usage') {
    (async () => {
      try {
        const r = await apiFetch('/user/usage');
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        sendResponse(await r.json());
      } catch (err) {
        sendResponse({ error: err.message });
      }
    })();
    return true;
  }


  if (message.type === 'share-result') {
    (async () => {
      try {
        const r = await apiFetch('/share', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(message.payload),
        });
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        sendResponse(await r.json());
      } catch (err) {
        sendResponse({ error: err.message });
      }
    })();
    return true;
  }

  /* Developer-only evaluation message routes (disabled in production).
  if (message.type === 'get-evaluation-state') {
    getEvaluationState().then(sendResponse);
    return true;
  }

  if (message.type === 'export-evaluation-cases') {
    (async () => {
      const stored = await storageGet([EVALUATION_CASES_KEY]);
      const cases = globalThis.FactScopeEvaluation
        ? FactScopeEvaluation.exportCases(stored[EVALUATION_CASES_KEY])
        : [];
      sendResponse({ success: true, cases });
    })();
    return true;
  }

  if (message.type === 'remove-evaluation-case') {
    (async () => {
      const stored = await storageGet([EVALUATION_CASES_KEY]);
      const cases = Array.isArray(stored[EVALUATION_CASES_KEY]) ? stored[EVALUATION_CASES_KEY] : [];
      const filtered = cases.filter((item) => item?.audit_case_id !== message.auditCaseId);
      await storageSet({ [EVALUATION_CASES_KEY]: filtered });
      sendResponse({ success: true });
    })();
    return true;
  }

  if (message.type === 'clear-evaluation-cases') {
    storageRemove([EVALUATION_CASES_KEY, EVALUATION_PENDING_KEY]).then(() => sendResponse({ success: true }));
    return true;
  }

  if (message.type === 'disable-evaluation-mode') {
    storageSet({ [EVALUATION_MODE_KEY]: false }).then(async () => {
      await storageRemove([EVALUATION_PENDING_KEY]);
      sendResponse({ success: true });
    });
    return true;
  }
  */
  if (message.type === 'record-telemetry') {
    void recordTelemetry(message.event);
    sendResponse({ success: true });
    return false;
  }

  if (message.type === 'delete-server-data') {
    (async () => {
      try {
        const response = await apiFetch('/v1/data', { method: 'DELETE' });
        const data = await response.json();
        if (!response.ok) {
          sendResponse({ success: false, error: data.message || 'Deletion failed.' });
          return;
        }
        await storageRemove([HISTORY_KEY]);
        sendResponse({ success: true, deleted: data.deleted || {} });
      } catch {
        sendResponse({ success: false, error: 'Could not delete server data. Please try again.' });
      }
    })();
    return true;
  }
});

if (globalThis.__FACTSCOPE_SESSION_TEST__) {
  globalThis.__FACTSCOPE_SESSION__ = {
    apiFetch, apiFetchVersioned, getSessionToken, isV1ApiEnabled,
    buildFailureResult, failureFromResponse, failureFromException,
  };
}
