# API acceptance activation

The installed review-maintain procedure was checked against REVIEW.md, config,
layers, and manifest. No real review corpus or former API-model quality baseline
exists yet. Selecting gpt-6-luna/low for this small synthetic sample is an initial
cost-bounded integration test, not an evaluated replacement for gpt-6-astra.

Verified evidence: runtime 43822775874, container 43824609484, protected publisher
and complete no-model controller 43827168365. Review quality and security-finding
quality remain needs_verification. Deployment layers remain pending_applicability.

Policy proposal: API only, same-repository PRs by NyongCho only, 60 seconds per
model stage, at most 15 stages and 3 repair rounds per run. Auto-fix is confined
to allowed source/new-test changes; sensitive paths and existing-test edits require
human intervention. AI remains observe-only; CI and scoped human checks stay required.

Execution order: run the fixed-prompt one-call smoke first; inspect token usage
before creating any billable review PR. Then test normal/bug/sensitive examples
sequentially, retain failed attempts, collect cases for human judgment, and compare
frozen cases separately. Total authorized API validation spend is US$5, including
smoke, failures, retries, and later evaluations. Provider hard limit and prior
project spend are unconfirmed because the user could not access Platform and
explicitly requested proceeding. Stop if usage cannot be determined.

No automatic merge or authentication fallback is enabled. This policy change
requires the repository's scoped human approval before activation.
