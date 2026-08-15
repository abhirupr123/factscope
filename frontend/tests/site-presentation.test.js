const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const site = path.join(__dirname, '..', 'site');
const pages = [
  'index.html', 'methodology.html', 'support.html',
  'changelog.html', 'status.html', 'privacy.html',
];

for (const page of pages) {
  const source = fs.readFileSync(path.join(site, page), 'utf8');
  assert.match(source, /<title>[^<]+<\/title>/, `${page} needs a title`);
  assert.match(source, /<meta name="description" content="[^"]+">/, `${page} needs a description`);
  assert.match(source, /href="styles\.css"/, `${page} needs shared styles`);
  assert.match(source, /src="site\.js"/, `${page} needs shared interactions`);
  assert.match(source, /class="nav-toggle"/, `${page} needs mobile navigation`);
  assert.doesNotMatch(source, /`[rn]/, `${page} contains an escaped line-ending artifact`);

  for (const match of source.matchAll(/href="([^"#][^"]*)"/g)) {
    const href = match[1];
    if (/^(?:https?:|mailto:)/.test(href) || href.startsWith('/')) continue;
    const target = href.split('#')[0];
    if (!target) continue;
    assert.ok(fs.existsSync(path.join(site, target)), `${page} links to missing ${target}`);
  }
}

const index = fs.readFileSync(path.join(site, 'index.html'), 'utf8');
assert.match(index, /verification assistant/i);
assert.match(index, /not a truth button/i);
assert.match(index, /data-demo-target="article-demo"/);
assert.match(index, /data-demo-target="image-demo"/);
assert.match(index, /data-demo-target="recovery-demo"/);
assert.doesNotMatch(index, /tells you if it(?:'|’)s trustworthy|misinformation detection/i);

const methodology = fs.readFileSync(path.join(site, 'methodology.html'), 'utf8');
for (const label of ['Supported', 'Contradicted', 'Mixed', 'Matching coverage', 'Broader context', 'Still open']) {
  assert.match(methodology, new RegExp(label));
}
assert.match(methodology, /It is not the probability that a claim is true/);

const status = fs.readFileSync(path.join(site, 'status.html'), 'utf8');
const script = fs.readFileSync(path.join(site, 'site.js'), 'utf8');
const styles = fs.readFileSync(path.join(site, 'styles.css'), 'utf8');
assert.match(status, /<body class="status-page">/);
assert.match(status, /data-status-check/);
assert.match(script, /factscope-api\.onrender\.com\/health/);
assert.match(script, /AbortController/);
assert.match(styles, /status-page \.page-hero > \.container/);
assert.match(styles, /status-page \[data-status-check\][\s\S]*?flex:\s*0 0 auto/);

const listingPath = path.join(site, 'chrome-web-store-listing.txt');
const changelog = fs.readFileSync(path.join(site, 'changelog.html'), 'utf8');
const manifest = JSON.parse(fs.readFileSync(path.join(site, '..', 'manifest.json'), 'utf8'));
assert.match(changelog, new RegExp(`Version ${manifest.version.replace(/\\./g, '\\\\.')}`));

// This Store submission copy is intentionally local-only. Validate it during
// local release checks when present without making CI depend on the private file.
if (fs.existsSync(listingPath)) {
  const listing = fs.readFileSync(listingPath, 'utf8');
  assert.match(listing, new RegExp(`Release notes \\u2014 version ${manifest.version.replace(/\\./g, '\\\\.')}`));
  const shortDescription = listing.match(/Short description\r?\n([^\r\n]+)/)?.[1] || '';
  assert.ok(shortDescription.length > 0 && shortDescription.length <= 132,
    `Store short description must be 1-132 characters; got ${shortDescription.length}`);
  assert.match(listing, /Single purpose/);
  assert.match(listing, /Permission justifications/);
  assert.match(listing, /FactScope is a verification assistant, not a truth detector/);
}

console.log('public site presentation tests passed');
