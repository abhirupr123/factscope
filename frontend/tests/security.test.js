const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const contentScriptPath = path.join(__dirname, '..', 'content', 'content_script.js');
const source = fs.readFileSync(contentScriptPath, 'utf8');
const overlayCSS = fs.readFileSync(path.join(__dirname, '..', 'content', 'overlay.css'), 'utf8');
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

assert.match(source, /function showImageResultPanel\(result, resolvedPageUrl\)[\s\S]*?result = sanitizeForHTML\(result\);/);

const v1ClaimHTML = security.buildV1ClaimsHTML([{
  claim: '<img src=x onerror=alert(1)>',
  status: 'supported',
  confidence: 'high',
  supporting_sources: [{ title: '<script>bad()</script>', url: 'javascript:alert(1)' }],
  contradicting_sources: [],
  limitations: ['<b>unsafe</b>'],
}]);
assert.match(v1ClaimHTML, /&lt;img src=x onerror=alert\(1\)&gt;/);
assert.match(v1ClaimHTML, /&lt;script&gt;bad\(\)&lt;\/script&gt;/);
assert.match(v1ClaimHTML, /&lt;b&gt;unsafe&lt;\/b&gt;/);
assert.doesNotMatch(v1ClaimHTML, /javascript:/);

const relatedClaimHTML = security.buildV1ClaimsHTML([{
  claim: 'A developing claim', status: 'insufficient_evidence', confidence: 'low',
  supporting_sources: [], contradicting_sources: [],
  related_sources: [
    { title: 'Report one', publisher: 'Outlet A', url: 'https://a.example/report' },
    { title: 'Report two', publisher: 'Outlet B', url: 'https://b.example/report' },
  ],
  limitations: ['Evidence is indirect.'],
}], ['Evidence is indirect.']);
assert.match(relatedClaimHTML, /Multiple related reports found/);
assert.match(relatedClaimHTML, /Related coverage — not verified as supporting evidence/);
assert.match(relatedClaimHTML, /https:\/\/a\.example\/report/);
assert.equal((relatedClaimHTML.match(/Evidence is indirect\./g) || []).length, 1);
assert.match(relatedClaimHTML, /Why these results\?/);
assert.doesNotMatch(relatedClaimHTML, /low evidence confidence/i);
assert.match(overlayCSS, /fs-limitations-compact > summary[\s\S]*?cursor:\s*pointer/);

const corroboratedClaimHTML = security.buildV1ClaimsHTML([{
  claim: 'The ministry issued the notification', status: 'supported', confidence: 'medium',
  supporting_sources: [{
    title: 'Official notification', publisher: 'Ministry', url: 'https://ministry.gov.in/notice',
    stance: 'corroborating', source_type: 'primary', recency: 'current',
  }],
  contradicting_sources: [], related_sources: [], limitations: [],
}]);
assert.match(corroboratedClaimHTML, /Corroborated by independent reporting/);
assert.match(corroboratedClaimHTML, /Ministry.*Primary source.*Current/);
assert.doesNotMatch(corroboratedClaimHTML, />Supported</);

const imageAssessmentHTML = security.buildV1ImageAssessmentHTML({
  authenticity_score: 35,
  legacy_score: 35,
  assessment: {
    manipulation: {
      status: 'likely_manipulated', confidence: 'medium', summary: 'A composite was detected.',
      indicators: ['Portrait composited onto background'], limitations: ['Low resolution'],
    },
    caption_consistency: {
      status: 'insufficient_evidence', confidence: 'low', summary: 'Not enough reporting.',
      claims: [], limitations: [],
    },
    provenance: {
      status: 'no_visible_source_indicator', confidence: 'low', summary: 'No credit visible.',
      indicators: [], limitations: ['Credits do not prove origin'],
    },
  },
  limitations: ['Low resolution', 'Credits do not prove origin', 'Technical result was partial'],
});
assert.match(imageAssessmentHTML, /Edited or composited image detected/);
assert.match(imageAssessmentHTML, /does not establish deceptive use/);
assert.equal((imageAssessmentHTML.match(/Low resolution/g) || []).length, 1);
assert.equal((imageAssessmentHTML.match(/Credits do not prove origin/g) || []).length, 1);
assert.match(imageAssessmentHTML, /Technical result was partial/);

const articleAssessmentHTML = security.buildV1ArticleSummaryHTML({
  factual_evidence: { status: 'insufficient_evidence', confidence: 'low', summary: 'Evidence is incomplete.' },
  overall_evidence_summary: 'Evidence is incomplete.',
  content_classification: {
    content_type: 'breaking_news', confidence: 'medium', checkability: 'checkable',
    rationale: 'Reporting is recent.',
  },
  source_quality: { level: 'high', score: 82, summary: 'Strong page signals.', signals: [], limitations: [] },
  explanation: 'Professional article presentation with a named author.',
  evidence: ['Published by a recognized outlet'],
  limitations: ['Evidence may change.'],
});
assert.match(articleAssessmentHTML, /Evidence still developing/);
assert.match(articleAssessmentHTML, /Evidence confidence: low/);
assert.match(articleAssessmentHTML, /Content and source assessment/);
assert.match(articleAssessmentHTML, /Professional article presentation/);
assert.match(articleAssessmentHTML, /does not verify individual factual claims/);
assert.match(articleAssessmentHTML, /About this assessment/);
assert.match(articleAssessmentHTML, /Classification confidence: Medium/);
assert.match(articleAssessmentHTML, /Checkability: Checkable/);
assert.doesNotMatch(articleAssessmentHTML, /checkable checkability/);
assert.match(source, /identified as satire, so its statements were not evaluated as literal factual claims/);

const corroboratedArticleHTML = security.buildV1ArticleSummaryHTML({
  factual_evidence: { status: 'supported', confidence: 'medium', summary: 'Independent reports corroborate the checked claim.' },
  overall_evidence_summary: 'Independent reports corroborate the checked claim.',
  claims: [{ supporting_sources: [{ stance: 'corroborating' }], contradicting_sources: [] }],
  content_classification: { content_type: 'standard_news', confidence: 'medium', checkability: 'checkable' },
  source_quality: {}, limitations: [],
});
assert.match(corroboratedArticleHTML, /Supported by independent reporting/);
assert.doesNotMatch(corroboratedArticleHTML, /Supported by direct evidence/);

console.log('frontend security tests passed');
