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
- Correct PHPDoc types, unused bindings and deprecated query-expression imports. The current runner fixes PHP diagnostic settings and requires normal suite completion; see the review correction below.

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

- Historical runner result: 19 suites reported success. The review below found that early `exit(0)` could hide unexecuted assertions; this count alone did not establish complete execution.
- PHP syntax: 53 files passed.
- Added coverage: duplicate state rejection, diagnostic XML isolation, trace escaping/nested values, POST option validation, restore field boundaries, raw user-update values, and canonical root/subdirectory URLs.
- GLPI 11.0.11 and 12.0.0 isolated copies: forced native plugin installation, activation and cache clearing passed.
- SLO-only parent candidate: both versions passed real authenticated browser acceptance.
- Expanded candidate `b01b1a0f571b0caae89eb8a023f66b402be1bcac`: fresh browser acceptance completed on 2026-10-19 for GLPI 11.0.11 and 12.0.0. Both deployed trees matched all 216 tracked candidate files before acceptance.
- Both versions passed fresh SAML login with the expected account/profile, canonical configuration list/form rendering, claim-mapping and logging tabs, and trace popover rendering. A malformed signed-query logout returned HTTP 400 without clearing the login. A real signed IdP-initiated callback returned HTTP 302; the dedicated IdP session disappeared and the old GLPI central page reported session expiration. Unrelated IdP sessions and the production provider were preserved.
- GLPI 12 initially rejected a stale authentication state created three days earlier. Native local logout followed by a new request succeeded without changing timeout or signature validation.
- Temporary test-provider/application settings, plugin copies and web-server configuration were restored and verified; forwarding was stopped and isolated guests were shut down.

### Browser diagnostics and scope

Follow-up fix validated on 2026-10-19: the SLO controller now confines libxml diagnostics to the request and restores the previous error mode in `finally`. Thirteen real-toolkit SLO cases covered malformed payload/truncated XML under both initial libxml modes, warning-free rejection, and unchanged signed-request validation. The old runner reported 19 passing suites, subject to the completion limitation identified below. Development-version recognition also accepts CRLF changelogs while strict release checks remain enforced. Intelephense and SonarLint were rerun with zero diagnostics for the controller fix.

Both versions passed fresh browser login (HTTP 200), malformed logout (400 with login preserved), and signed IdP logout (302 with both sessions expired); no new XML/PHP warnings occurred during these browser paths. GLPI 11's menu search successfully returned computer entries without a browser console error. The earlier FuzzySearch error was not reproduced; its cause remains unverified and no core patch was made. An initial GLPI 11 stale login timed out; a new native login request succeeded without relaxing validation. A test cache-clear CLI error predating the browser run is separate from these request paths; final cache clearing succeeded. Temporary settings and original plugin trees were restored, and test forwarding/guest were stopped.

This acceptance covers signed IdP-initiated top-level navigation. It does not establish SP-initiated LogoutResponse support, general cross-origin iframe compatibility, subdirectory browser coverage, or a new MFA challenge.

### Review corrections and current validation — 2026-10-19

The review found and corrected five functional boundaries: explicit rejection of SHA-1/unknown/missing logout signature algorithms; provider-controlled proxy handling with restoration of the toolkit setting; an inert local completion page for an already logged-out browser; restoration of the local collection variable required by GLPI's included rule list/form pages; and validation of malformed claim-map fields before typed helper arguments can coerce them or throw a TypeError.

The runner now uses the current PHP binary with `E_ALL` and plain diagnostic output, and requires a completion marker after each suite returns. This exposed premature `exit(0)` in ACS, claim-mapping and user-provisioning tests. Their fixtures now exercise expected failures through the existing test exception boundary, without weakening production validation. **All 20 suites complete and pass**, including the new `RulePageContractTest`. The SLO suite has **37 real-toolkit cases** covering state-before-cleanup ordering, untouched rejected sessions, returned response correlation and signature, proxy trust, algorithm restrictions, parser-state restoration and inert completion.

The final 20-suite rerun also passes after the chooser-text and ACS fixture corrections: all 85 tracked PHP files (including tooling) pass syntax checks, and normalized hashes match for 105 PHP/template files across the local tree, scratch tree and both deployed test copies. All 15 ACS cases pass normally; a no-op `init()` mutation exits with failure at the replay-handler assertion, proving the negative test no longer catches its own failed assertion as success.

Intelephense and SonarLint returned zero diagnostics for the revised 54-file PHP tree under the documented configurations; test doubles remain outside the production Intelephense symbol index. PHP_CodeSniffer 4 checked PSR-12 with zero diagnostics for **only** `SamlSsoController.php`, `LoginTraceRenderer.php`, `IdpSloTest.php` and `RulePageContractTest.php`. The standalone tests document narrow class/side-effect exceptions. This is not a whole-repository PSR-12 certification.

| Current review candidate | Browser result |
| --- | --- |
| GLPI 11.0.11 | Passed fresh login, rule list and existing rule form; bare and malformed logout returned 400 with the login preserved; the SP return rendered a 200 local completion page and GLPI access was expired; a separately scoped signed IdP logout expired the dedicated session while unrelated IdP sessions remained. |
| GLPI 12.0.0 | Passed the same fresh browser matrix: SAML login, rule list and existing rule form, bare/malformed logout rejection with the session preserved, 200 local-only SP completion with the old GLPI session expired, and separately scoped IdP logout with the target core session removed and unrelated sessions retained. |

The SP return page confirms **local GLPI logout only**. It does not validate or correlate LogoutResponse, and the tested Authentik core session remained active while the SAML application dependency was removed. The separate IdP-initiated test removed its scoped master session and preserved unrelated sessions. `PROXIED` coverage uses the real toolkit with forwarded-header fixtures; an actual reverse-proxy browser deployment has not been validated. General iframe behavior remains unverified.

The revised logout chooser was rendered in GLPI 12 and states that the identity provider determines whether other sessions end. The temporary provider configuration, original plugin trees, native settings and Apache configuration were restored and read back; both isolated guests and forwarding are stopped. An initial GLPI 11 cache ownership warning was confined to test preparation and the first completion-page load; correcting the test cache ownership allowed both native cache-clear commands to finish. No further PHP log entries appeared during the subsequent login, rule-page and logout matrix.

## Suggested review order

Split the contribution into standalone test infrastructure/release-policy changes, the protocol fix and its ADR, GLPI compatibility/rule-page/validation corrections, then behavior-preserving helper extraction. Obtain issue scope for the broader changes instead of treating the SLO preparation issue as covering every refactor. Revalidate each resulting PR head. No release catalogue entry or upstream PR has been invented or submitted.
