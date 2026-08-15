const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const frontend = path.join(__dirname, '..');
const contentSource = fs.readFileSync(path.join(frontend, 'content', 'content_script.js'), 'utf8');
const workerSource = fs.readFileSync(path.join(frontend, 'background', 'service_worker.js'), 'utf8');
const overlayCSS = fs.readFileSync(path.join(frontend, 'content', 'overlay.css'), 'utf8');

const contentContext = {
  __FACTSCOPE_SECURITY_TEST__: true,
  chrome: { runtime: { id: 'test', onMessage: { addListener() {} } } },
  window: { addEventListener() {} },
  document: {},
  URL,
  console,
  setTimeout,
  clearTimeout,
};
contentContext.globalThis = contentContext;
vm.runInNewContext(contentSource, contentContext);
const classify = contentContext.__FACTSCOPE_SECURITY__.classifyRecoveryState;

assert.equal(classify({ error_state: 'offline', retryable: true }, 'page').title, 'You’re offline');
assert.equal(classify({
  processing_state: 'failed', retryable: false,
  explanation: 'Could not fetch the image. It may be protected or too large.',
}, 'image').state, 'blocked_image');
assert.equal(classify({
  processing_state: 'failed', retryable: true,
  explanation: 'The main analysis provider failed.',
}, 'page').state, 'provider_failure');
assert.equal(classify({
  content_classification: { content_type: 'unsupported_page' },
}, 'page').retryable, false);
assert.equal(classify({ processing_state: 'complete', verdict: 'unknown' }, 'page'), null);

assert.match(contentSource, /No checkable factual claims found/);
assert.match(contentSource, /showResultPanel\(result, scanPage\)/);
assert.match(contentSource, /showImageResultPanel\(result, resolvedUrl, \(\) => verifyImage/);
assert.match(contentSource, /result\.verdict !== 'rate_limited'/);
assert.match(overlayCSS, /\.fs-recovery-warning/);
assert.match(overlayCSS, /\.fs-retry-btn:disabled/);

const event = { addListener() {} };
const workerContext = {
  __FACTSCOPE_SESSION_TEST__: true,
  chrome: {
    storage: { local: {
      get(_keys, callback) { callback({}); },
      set(_values, callback) { if (callback) callback(); },
      remove(_keys, callback) { if (callback) callback(); },
    } },
    runtime: { onInstalled: event, onMessage: event },
    contextMenus: { create() {}, onClicked: event },
    tabs: { sendMessage() {}, onUpdated: event },
    action: { setBadgeText() {}, setBadgeBackgroundColor() {}, setBadgeTextColor() {} },
  },
  navigator: { onLine: false },
  fetch: async () => { throw new TypeError('Failed to fetch'); },
  AbortSignal,
  Headers,
  URL,
  Date,
  Promise,
  console,
};
workerContext.globalThis = workerContext;
vm.runInNewContext(workerSource, workerContext);
const failures = workerContext.__FACTSCOPE_SESSION__;

(async () => {
  const cold = await failures.failureFromResponse({
    status: 503,
    async json() { return {}; },
  }, 'page');
  assert.equal(cold.error_state, 'cold_start');
  assert.equal(cold.trust_score, 50);

  const timeout = await failures.failureFromResponse({
    status: 503,
    async json() { return { error: 'provider_timeout', request_id: 'request-123' }; },
  }, 'page');
  assert.equal(timeout.error_state, 'timeout');
  assert.equal(timeout.request_id, 'request-123');

  const blockedBySize = await failures.failureFromResponse({
    status: 413,
    async json() { return { error: 'request_too_large' }; },
  }, 'page');
  assert.equal(blockedBySize.retryable, false);

  const offline = failures.failureFromException(new TypeError('Failed to fetch'), 'image');
  assert.equal(offline.error_state, 'offline');
  assert.equal(offline.authenticity_score, 50);

  console.log('frontend recovery-state tests passed');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
