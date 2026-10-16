# Whole-project static-analysis cleanup

This separate branch addresses the owner's expanded cleanup request. It preserves the SLO fix as a smaller reviewable parent branch and does not represent an upstream submission.

## Behavior changes

- Use the canonical `/plugins/samlsso` route on GLPI 11 and 12, preserving subdirectory installations without duplicating the path.
- Pass raw user data to GLPI 11+ rather than applying deprecated HTML encoding before persistence. See the [official GLPI 11 migration guide](https://glpi-developer-documentation.readthedocs.io/en/master/upgradeguides/glpi-11.0.html).
- Reject duplicate authentication-state rows before hydration; retain request/inactivity expiration semantics and signature-before-state-change ordering.
- Split trace rendering from state management, escape diagnostic values and handle nested arrays safely.
- Reject DTD-bearing diagnostic XML and avoid external-resource/entity expansion. Real configuration-class regression tests cover this boundary.
- Validate the existing login-flow form's POST options instead of silently ignoring an extra constructor argument. This does not enable the unfinished legacy flow-configuration feature or create its schema.
- Split configuration, restoration, claim mapping, migration, GeoIP and user-provisioning helpers while preserving existing public interfaces and policies.
- Correct PHPDoc types, unused bindings and deprecated query-expression imports. Runtime PHP warnings can no longer be hidden by an otherwise successful test-suite exit code.

## Analyzer evidence

Validated on 2026-10-16 against upstream `8d4823b` and this branch's PHP sources:

| Tool | Configuration | Upstream baseline | Cleanup candidate |
| --- | --- | ---: | ---: |
| Intelephense 1.18.5 | PHP 8.3; GLPI 11.0.11 source/dependencies as include paths; production PHP, test doubles excluded from the shared symbol index | 82 diagnostics | 0 diagnostics across 31 production files |
| SonarLint Language Server 6.1.1.79808 / PHP analyzer 4.1.0.16998 | Standalone, no server quality profile; `**/tests/**` classified as tests | 89 diagnostics across 50 PHP files | 0 diagnostics across 53 PHP files |

Both language servers were actually executed using their LSP interfaces. The SonarLint distribution was the official VS Code extension 6.1.1. Initial scans that misclassified test doubles as production are not used as the baseline above. Intelephense's formatter was also applied to production files. No global rule-disable list was introduced.

### Explicit exceptions

Existing framework/API names are retained: GLPI hook functions, the public URL/version helpers, the hook registry, compatibility-layer properties, and validators dispatched by persisted database-column names. Narrow `NOSONAR` comments explain those naming contracts.

The method-count metric is waived at the existing LoginState, ConfigEntity and ClaimMapEntity public facade declarations. Their established APIs remain compatible while individual complex methods were split into focused helpers. The default-template length exception covers declarative data including multiline public example certificates, not a large algorithm. Existing upstream suppressions were not represented as newly fixed findings.

These are scoped analyzer results, not a claim that all possible defects or security issues have been eliminated. Test doubles are executed by the test runner rather than mixed into the production Intelephense index.

## Regression evidence

- `php tests/RunAllTests.php`: 19 independent suites passed, with runtime warnings treated as failure.
- PHP syntax: 53 files passed.
- Added coverage: duplicate state rejection, diagnostic XML isolation, trace escaping/nested values, POST option validation, restore field boundaries, raw user-update values, and canonical root/subdirectory URLs.
- GLPI 11.0.11 and 12.0.0 isolated copies: forced native plugin installation, activation and cache clearing passed.
- SLO-only parent candidate: both versions passed real authenticated browser acceptance.
- Expanded candidate: fresh browser acceptance remains pending. Temporary provider/application settings were restored and the isolated environment stopped after the browser-entry operation could not be completed.

## Suggested review order

Review the original SLO fix first, then the compatibility corrections and their tests, then the behavior-preserving helper extraction and diagnostic formatting. Keep this larger cleanup separate if maintainers prefer a narrow protocol fix. No release catalogue entry or upstream PR has been invented or submitted.
