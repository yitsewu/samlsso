# IdP-initiated SLO: contribution preparation

Tracking: https://github.com/yitsewu/samlsso/issues/1

This fork branch is a review candidate, not a release. Base: upstream main `8d4823b`. Upstream already includes a GLPI 11/12 compatibility layer; this branch does not duplicate the earlier private compatibility changes.

## Included

- Protocol callbacks bypass the local logout chooser.
- Generated logout metadata includes the provider ID required by callback routing and strict destination checks.
- Fresh validated ACS sessions retain the minimum logout correlation context.
- Signed requests are checked before native session cleanup and a protocol response.
- Standalone cryptographic regression test using generated ephemeral keys and fictional identities.
- Test-harness SessionIndex support and a proposed ADR/Wiki update.

## Validation

The earlier prototype passed an isolated GLPI 12 / Authentik browser test: signed IdP request, callback redirect, IdP login screen, and denied access to the old application session. This is historical prototype evidence, not an end-to-end claim for this rebased branch.

The rebased candidate now passes all 18 suites using `php tests/RunAllTests.php` without an external GLPI bootstrap. The SLO suite uses the real bundled cryptographic library and local HTTP/GLPI boundary doubles. The missing HTML-escaping helper and developer-specific paths are resolved in test shims, without changing production escaping behavior.

Release-catalog checks now distinguish development from packaging. Every published entry is still checked for a valid version, duplicate entries and the expected upstream download path (including the historical plugin name). A newer development version must be explicitly listed in the changelog. Packaging sets `SAMLSSO_RELEASE_VALIDATION=1`, requiring the exact version entry; no fictitious download was added. Fixtures prove rejection of missing release entries, undeclared/older versions, empty catalogs, invalid URLs and duplicates.

On 2026-10-16, the full rebased plugin passed a fresh GLPI 12.0.0 / Authentik browser integration test after owner authentication. A malformed callback was rejected without clearing the application session. A real signed IdP-initiated logout returned to the IdP login page, removed the dedicated IdP session, and caused the old GLPI central page to report an expired session. The production provider and its existing session/dependencies remained unchanged. Temporary test-provider settings and application configuration were restored afterward.

This integration test caught a missing provider ID in the generated SLO endpoint that the controller-only doubles did not cover. ConfigIntegrityTest now exercises the real configuration builder with two provider IDs. The correction retains exact destination validation; it does not relax signature or identity/session checks.

## Expanded cleanup branch

The SLO-only candidate also passed a fresh GLPI 11.0.11 browser test on 2026-10-16: malformed signed-query rejection preserved the login, a real IdP-initiated logout removed the dedicated IdP session, and the GLPI session expired. The unrelated production session and provider remained unchanged.

The owner subsequently requested a separate whole-project warning cleanup. That work is on `chore/project-static-analysis`, based on `fix/idp-initiated-slo`. See [the analysis and regression report](STATIC-ANALYSIS-CLEANUP.md). Its 19 suites and both isolated GLPI installation/activation checks pass. The broader candidate `b01b1a0` passed its own fresh GLPI 11.0.11 and 12.0.0 browser acceptance on 2026-10-19, including login, configuration rendering, negative logout and signed IdP-initiated logout. See the analysis report for exact scope and remaining runtime/browser diagnostics. Earlier SLO-only results are not used as proof for this expanded candidate.

## Before an upstream PR

- Completed: standalone unit/regression suite is green (19/19); runtime PHP warnings now fail a suite.
- Completed: Intelephense and SonarLint checks, with explicit framework-contract exceptions documented in the analysis report.
- Completed: SLO-only GLPI 11 and GLPI 12 browser integration.
- Completed: fresh browser acceptance for expanded candidate `b01b1a0`, including canonical callbacks, configuration/claim/logging/trace rendering and both logout cases on GLPI 11.0.11 and 12.0.0.
- Follow-up completed: malformed XML warnings are contained and libxml state restored; 13 SLO cases and all 19 suites pass. Both versions passed fresh login/negative logout/signed logout browser checks without new XML warnings. GLPI 11 menu search worked without reproducing the earlier core FuzzySearch error; its original cause is unverified. See the analysis report.
- Review localization and the strict signed-request requirement with maintainers.
- Extend protocol coverage and agree on unsupported cases listed in ADR 0025; SP-initiated LogoutResponse and cross-browser iframe behavior are not claimed.
- The contribution guide references SECURITY.md, but that file is absent in this checkout. ADR 0017 and the architectural Wiki were reviewed; obtain the intended security policy before submission.

No upstream issue, PR, maintainer message or production deployment has been made by this preparation task. This is a review candidate, not a release or an unconditional production-upgrade recommendation.
