const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const workerPath = path.join(__dirname, '..', 'background', 'service_worker.js');
const source = fs.readFileSync(workerPath, 'utf8');
const stored = {};
const calls = [];
let sessionNumber = 0;
let analysisNumber = 0;

const response = (status, body = {}) => ({
  status,
  ok: status >= 200 && status < 300,
  async json() { return body; },
});

async function fetchMock(url, options = {}) {
  calls.push({ url, options });
  if (url.endsWith('/health')) return response(200, { status: 'ok' });
  if (url.endsWith('/v1/session')) {
    sessionNumber += 1;
    return response(200, {
      access_token: `token-${sessionNumber}`,
      expires_at: new Date(Date.now() + 86400000).toISOString(),
    });
  }
  if (url.endsWith('/analyze')) {
    analysisNumber += 1;
    return response(analysisNumber === 1 ? 401 : 200, { trust_score: 50 });
  }
  throw new Error(`Unexpected fetch: ${url}`);
}

const event = { addListener() {} };
const context = {
  __FACTSCOPE_SESSION_TEST__: true,
  chrome: {
    storage: {
      local: {
        get(keys, callback) {
          const result = {};
          for (const key of [].concat(keys)) result[key] = stored[key];
          callback(result);
        },
        set(values, callback) {
          Object.assign(stored, values);
          if (callback) callback();
        },
        remove(keys, callback) {
          for (const key of [].concat(keys)) delete stored[key];
          if (callback) callback();
        },
      },
    },
    runtime: { onInstalled: event, onMessage: event },
    contextMenus: { create() {}, onClicked: event },
    tabs: { sendMessage() {}, onUpdated: event },
    action: {
      setBadgeText() {}, setBadgeBackgroundColor() {}, setBadgeTextColor() {},
    },
  },
  fetch: fetchMock,
  AbortSignal,
  Headers,
  URL,
  Date,
  Promise,
  console,
};
context.globalThis = context;

vm.runInNewContext(source, context);
const session = context.__FACTSCOPE_SESSION__;
assert.ok(session, 'session helpers must be exposed in test mode');

(async () => {
  const result = await session.apiFetch('/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: 'claim' }),
  });
  assert.equal(result.status, 200);
  assert.equal(sessionNumber, 2, 'a 401 should mint exactly one replacement session');
  assert.equal(analysisNumber, 2, 'a 401 should retry the protected request once');
  const analysisCalls = calls.filter((call) => call.url.endsWith('/analyze'));
  assert.equal(analysisCalls[0].options.headers.get('Authorization'), 'Bearer token-1');
  assert.equal(analysisCalls[1].options.headers.get('Authorization'), 'Bearer token-2');
  assert.doesNotMatch(analysisCalls[1].options.body, /user_id/);
  console.log('frontend session tests passed');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
