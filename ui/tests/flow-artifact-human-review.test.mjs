import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const service = readFileSync(new URL('../src/services/flowArtifactReviews.ts', import.meta.url), 'utf8');
const panel = readFileSync(new URL('../src/components/flows/FlowArtifactReviewPanel.tsx', import.meta.url), 'utf8');
const mounted = readFileSync(new URL('../src/pages/FlowOperations.tsx', import.meta.url), 'utf8');

test('senior-only signed artifact review uses one exact SHA+ROE/Flow-bound API request', () => {
  assert.match(service, /currentOperator\(\)/);
  assert.match(service, /identity\.role !== 'senior_operator'/);
  assert.match(service, /isSecureApiBase\(API_BASE\)/);
  assert.match(service, /isSecureBrowserOrigin\(\)/);
  assert.match(service, /authHeaders\(/);
  assert.match(service, /credentials: 'omit'/);
  assert.match(service, /cache: 'no-store'/);
  assert.match(service, /redirect: 'error'/);
  assert.match(service, /expected_sha256: boundary\.artifactSha256/);
  assert.match(service, /expected_authorization_version: boundary\.authorizationVersion/);
  assert.match(service, /expected_authorization_sha256: boundary\.authorizationSha256/);
  assert.match(service, /expected_authorization_id: boundary\.authorizationId/);
  assert.match(service, /receipt\.reviewer_sub === receipt\.uploader_sub/);
  assert.match(service, /receipt\.verified_review !== true/);
  assert.match(service, /if \(response\.status !== 201\)/);
  assert.match(service, /artifact-reviews\/candidates/);
  assert.match(service, /artifact-reviews\/\$\{encodeURIComponent\(boundary\.artifactId\)\}\/content/);
  assert.match(service, /expected_engagement_id: boundary\.engagementId/);
  assert.match(service, /reader\.read\(\)/);
  assert.match(service, /count > expectedBytes/);
  assert.match(service, /crypto\.subtle\.digest\('SHA-256', bytes\)/);
  assert.match(service, /receipt\.artifact_sha256 !== boundary\.artifactSha256/);
  assert.match(service, /receipt\.approved !== \(receipt\.decision === 'approve'\)/);
  assert.doesNotMatch(service, /localStorage|sessionStorage|document\.cookie/);
});

test('React panel requires verified file download, explicit inspection, reason, and separate senior decision', () => {
  assert.match(panel, /flowArtifactReviewsApi\.source\(signed, selected\.size_bytes\)/);
  assert.match(panel, /flowArtifactReviewsApi\.candidates\(/);
  assert.match(panel, /latestSignedBoundary\(selected\)/);
  assert.match(panel, /signed\.status !== 'active'/);
  assert.match(panel, /signed\.policy_sha256 !== previouslyChecked\.authorizationSha256/);
  assert.match(panel, /downloadedSha !== selected\.sha256/);
  assert.match(panel, /!hasInspected/);
  assert.match(panel, /!reviewChecked/);
  assert.match(panel, /flowArtifactReviewsApi\.inspect\(signed\)/);
  assert.match(panel, /flowArtifactReviewsApi\.decide\(signed, decision, reason\)/);
  assert.match(panel, /role !== 'senior_operator'/);
  assert.match(panel, /No approval action may be taken from metadata alone/);
  assert.match(panel, /not target verification/);
  assert.doesNotMatch(panel, /dangerouslySetInnerHTML/);
});

test('existing signed Flow operator view mounts human review separately from file vault and signed report release', () => {
  assert.match(mounted, /import \{ FlowArtifactReviewPanel \}/);
  assert.match(mounted, /<FlowArtifactReviewPanel/);
  assert.match(mounted, /authorizationId=\{selectedEngagement\?\.scope\.authorization_ref\}/);
  assert.match(mounted, /<FlowArtifactsPanel/);
  assert.match(mounted, /<SignedReportOperatorPanel/);
});
