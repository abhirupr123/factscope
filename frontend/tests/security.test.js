const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const contentScriptPath = path.join(__dirname, '..', 'content', 'content_script.js');
const source = fs.readFileSync(contentScriptPath, 'utf8');
const context = {
  __FACTSCOPE_SECURITY_TEST__: true,
  chrome: {
    runtime: {
      id: 'test-extension',
      onMessage: { addListener() {} },
    },
  },
  window: { addEventListener() {} },
  document: {},
  URL,
  console,
  setTimeout,
  clearTimeout,
};

vm.runInNewContext(source, context);
const security = context.__FACTSCOPE_SECURITY__;
assert.ok(security, 'security helpers must be exposed in test mode');

const sanitized = security.sanitizeForHTML({
  explanation: '<img src=x onerror=alert(1)>',
  source_url: 'javascript:alert(1)',
  related_articles: [{ title: '<script>bad()</script>', url: 'https://example.com/a' }],
});

assert.equal(sanitized.explanation, '&lt;img src=x onerror=alert(1)&gt;');
assert.equal(sanitized.source_url, '');
assert.equal(sanitized.related_articles[0].title, '&lt;script&gt;bad()&lt;/script&gt;');
assert.equal(sanitized.related_articles[0].url, 'https://example.com/a');
assert.match(source, /function showResultPanel\(result\) \{\s*result = sanitizeForHTML\(result\);/);
assert.match(source, /function buildNoteCardHTML\(note\) \{\s*note = sanitizeForHTML\(note\);/);
assert.match(source, /function buildFactChecksHTML\(factChecks\)[\s\S]*?factChecks = sanitizeForHTML\(factChecks\);/);

console.log('frontend security tests passed');
