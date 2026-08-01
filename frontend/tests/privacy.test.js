const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const frontend = path.join(__dirname, '..');
const manifest = JSON.parse(fs.readFileSync(path.join(frontend, 'manifest.json'), 'utf8'));
const worker = fs.readFileSync(path.join(frontend, 'background', 'service_worker.js'), 'utf8');
const content = fs.readFileSync(path.join(frontend, 'content', 'content_script.js'), 'utf8');
const popup = fs.readFileSync(path.join(frontend, 'popup', 'popup.js'), 'utf8');
const policy = fs.readFileSync(path.join(frontend, 'site', 'privacy.html'), 'utf8');

assert.equal(manifest.version, '1.2.0');
assert.equal(manifest.content_scripts, undefined, 'content scripts must not run on every page');
assert.deepEqual(manifest.host_permissions, [
  'http://localhost:8000/*',
  'https://factscope-api.onrender.com/*',
]);
assert.ok(manifest.permissions.includes('activeTab'));
assert.ok(manifest.permissions.includes('scripting'));

assert.match(worker, /ensureFactScopeInjected[\s\S]*chrome\.scripting\.insertCSS/);
assert.match(worker, /ensureFactScopeInjected[\s\S]*chrome\.scripting\.executeScript/);
assert.match(worker, /apiFetch\('\/v1\/data', \{ method: 'DELETE' \}\)/);
assert.match(worker, /body: JSON\.stringify\(\{ event \}\)/);

const pageScan = content.slice(content.indexOf('async function scanPage()'));
assert.ok(
  pageScan.indexOf("await ensureScanConsent('page')") < pageScan.indexOf('extractPageContent()'),
  'page consent must happen before extraction',
);
const imageScan = content.slice(
  content.indexOf('async function verifyImage'),
  content.indexOf('/* ── Listen for messages from service worker'),
);
assert.ok(
  imageScan.indexOf("await ensureScanConsent('image')") < imageScan.indexOf('extractSocialContext'),
  'image consent must happen before context extraction',
);
assert.match(content, /if \(!consented\) return;/);

assert.match(popup, /factscope_telemetry_enabled/);
assert.match(popup, /delete-server-data/);
assert.match(policy, /Raw page and image scan records/);
assert.match(policy, /automatically deleted after 30 days/);
assert.match(policy, /Optional telemetry is off by default/);
assert.match(policy, /Delete my server data/);

console.log('frontend privacy tests passed');
