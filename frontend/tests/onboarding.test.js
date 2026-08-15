const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const frontend = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(frontend, 'popup', 'popup.html'), 'utf8');
const script = fs.readFileSync(path.join(frontend, 'popup', 'popup.js'), 'utf8');
const styles = fs.readFileSync(path.join(frontend, 'popup', 'popup.css'), 'utf8');
const dependabot = fs.readFileSync(path.join(frontend, '..', '.github', 'dependabot.yml'), 'utf8');
const worker = fs.readFileSync(path.join(frontend, 'background', 'service_worker.js'), 'utf8');

assert.match(html, /id="onboarding"/);
assert.match(html, /Nothing is scanned automatically/);
assert.match(html, /explains what page or image information will be sent/);
assert.match(html, /assists verification\. It does not determine truth/);
assert.match(html, /Preview an example result/);
assert.match(html, /Matching coverage found/);
assert.match(html, /Free beta/);

assert.match(script, /factscope_onboarding_complete_v1/);
assert.match(script, /onboardingScanButton\.addEventListener/);
assert.match(script, /completeOnboarding\(startPageScan\)/);
assert.match(styles, /\.onboarding-steps/);
assert.match(styles, /\.beta-badge,[\s\S]*?\.tier-badge[\s\S]*?align-items:\s*center/);
assert.match(styles, /\.beta-badge[\s\S]*?white-space:\s*nowrap/);

assert.doesNotMatch(html, /license key/i);
assert.doesNotMatch(script, /redeem-key|redeemBtn|licenseInput/);
assert.doesNotMatch(worker, /redeem-key|\/redeem-key/);
assert.doesNotMatch(styles, /upgrade-section|upgrade-form|redeem-msg/);

assert.match(dependabot, /interval: monthly/);
assert.match(dependabot, /versioning-strategy: increase-if-necessary/);
assert.match(dependabot, /backend-dependencies/);
assert.match(dependabot, /github-actions/);
assert.match(dependabot, /version-update:semver-major/);

console.log('frontend onboarding tests passed');
