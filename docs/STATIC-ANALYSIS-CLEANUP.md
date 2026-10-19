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
- Expanded candidate `b01b1a0f571b0caae89eb8a023f66b402be1bcac`: fresh browser acceptance completed on 2026-10-19 for GLPI 11.0.11 and 12.0.0. Both deployed trees matched all 216 tracked candidate files before acceptance.
- Both versions passed fresh SAML login with the expected account/profile, canonical configuration list/form rendering, claim-mapping and logging tabs, and trace popover rendering. A malformed signed-query logout returned HTTP 400 without clearing the login. A real signed IdP-initiated callback returned HTTP 302; the dedicated IdP session disappeared and the old GLPI central page reported session expiration. Unrelated IdP sessions and the production provider were preserved.
- GLPI 12 initially rejected a stale authentication state created three days earlier. Native local logout followed by a new request succeeded without changing timeout or signature validation.
- Temporary test-provider/application settings, plugin copies and web-server configuration were restored and verified; forwarding was stopped and isolated guests were shut down.

### Browser diagnostics and scope

Malformed XML in each negative logout test produced one server-side `DOMDocument::loadXML()` warning in the bundled toolkit before the request was rejected. This is a remaining diagnostic-noise issue; the zero static-analysis result does not claim a warning-free runtime for malformed input. No new PHP log errors were observed during the successful login/configuration paths. The GLPI 11 browser also reported a core FuzzySearch component `fuzzy is not defined` error; the tested plugin pages and trace popover remained usable. Its cause and presence on an unchanged core baseline were not established in this acceptance run. The trace popover was verified using keyboard activation.

This acceptance covers signed IdP-initiated top-level navigation. It does not establish SP-initiated LogoutResponse support, general cross-origin iframe compatibility, subdirectory browser coverage, or a new MFA challenge.

## Suggested review order

Review the original SLO fix first, then the compatibility corrections and their tests, then the behavior-preserving helper extraction and diagnostic formatting. Keep this larger cleanup separate if maintainers prefer a narrow protocol fix. No release catalogue entry or upstream PR has been invented or submitted.
