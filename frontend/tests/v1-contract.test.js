const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const workerPath = path.join(__dirname, '..', 'background', 'service_worker.js');
const source = fs.readFileSync(workerPath, 'utf8');

const response = (status, body = {}) => ({
  status,
  ok: status >= 200 && status < 300,
  async json() { return body; },
});

function createHarness(routeStatuses, useV1) {
  const calls = [];
  const stored = {
    factscope_session_token: 'test-token',
    factscope_session_expires_at: new Date(Date.now() + 86400000).toISOString(),
  };
  if (useV1 !== undefined) stored.factscope_use_v1_api = useV1;

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
          set(values, callback) { Object.assign(stored, values); if (callback) callback(); },
          remove(keys, callback) {
            for (const key of [].concat(keys)) delete stored[key];
            if (callback) callback();
          },
        },
      },
      runtime: { onInstalled: event, onMessage: event },
      contextMenus: { create() {}, onClicked: event },
      tabs: { sendMessage() {}, onUpdated: event },
      action: { setBadgeText() {}, setBadgeBackgroundColor() {}, setBadgeTextColor() {} },
    },
    async fetch(url, options = {}) {
      const pathname = new URL(url).pathname;
      calls.push({ pathname, options });
      if (!(pathname in routeStatuses)) throw new Error(`Unexpected fetch: ${pathname}`);
      return response(routeStatuses[pathname]);
    },
    AbortSignal,
    Headers,
    URL,
    Date,
    Promise,
    console,
  };
  context.globalThis = context;
  vm.runInNewContext(source, context);
  return { session: context.__FACTSCOPE_SESSION__, calls };
}

assert.match(source, /apiFetchVersioned\('\/v1\/analyze', '\/analyze'/);
assert.match(source, /'\/v1\/analyze\/verify-image',[\s\S]*?'\/analyze\/verify-image'/);
assert.match(source, /`\/v1\/analyses\/\$\{encodeURIComponent\(analysisId\)\}\/claims`/);

(async () => {
  {
    const { session, calls } = createHarness({ '/v1/analyze': 200, '/analyze': 200 });
    const result = await session.apiFetchVersioned('/v1/analyze', '/analyze', { method: 'POST' });
    assert.equal(result.contract, 'v1');
    assert.deepEqual(calls.map((call) => call.pathname), ['/v1/analyze']);
  }

  {
    const { session, calls } = createHarness({ '/v1/analyze': 404, '/analyze': 200 });
    const result = await session.apiFetchVersioned('/v1/analyze', '/analyze', { method: 'POST' });
    assert.equal(result.contract, 'legacy');
    assert.deepEqual(calls.map((call) => call.pathname), ['/v1/analyze', '/analyze']);
  }

  {
    const { session, calls } = createHarness({ '/v1/analyze': 503, '/analyze': 200 });
    const result = await session.apiFetchVersioned('/v1/analyze', '/analyze', { method: 'POST' });
    assert.equal(result.contract, 'v1');
    assert.equal(result.response.status, 503);
    assert.deepEqual(calls.map((call) => call.pathname), ['/v1/analyze'], 'provider failures must not replay costly analysis');
  }

  {
    const { session, calls } = createHarness({ '/v1/analyze': 200, '/analyze': 200 }, false);
    const result = await session.apiFetchVersioned('/v1/analyze', '/analyze', { method: 'POST' });
    assert.equal(result.contract, 'legacy');
    assert.deepEqual(calls.map((call) => call.pathname), ['/analyze']);
  }

  console.log('frontend v1 contract tests passed');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});