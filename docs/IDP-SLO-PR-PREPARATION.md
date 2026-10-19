# IdP-initiated SLO: contribution preparation

Tracking: https://github.com/yitsewu/samlsso/issues/1

This fork branch is a review candidate, not a release. Base: upstream main `8d4823b`. Upstream already includes a GLPI 11/12 compatibility layer; this branch does not duplicate the earlier private compatibility changes.

## Included

- Protocol callbacks bypass the local logout chooser.
- Generated logout metadata includes the provider ID required by callback routing and strict destination checks.
- Fresh validated ACS sessions retain the minimum logout correlation context.
- Signed requests are checked before native session cleanup and a protocol response.
- The callback explicitly allows RSA-SHA256/384/512, honors the provider's proxy setting and restores request-global parser/proxy state.
- An already logged-out browser can receive a local completion page; this does not validate an SP-initiated LogoutResponse or claim that other sessions ended.
- Standalone cryptographic regression test using generated ephemeral keys and fictional identities.
- Test-harness SessionIndex support and a proposed ADR/Wiki update.

## Validation

The earlier prototype passed an isolated GLPI 12 / Authentik browser test: signed IdP request, callback redirect, IdP login screen, and denied access to the old application session. This is historical prototype evidence, not an end-to-end claim for this rebased branch.

The earlier rebased candidate reported 18 passing suites using `php tests/RunAllTests.php` without an external GLPI bootstrap. A later review found that early `exit(0)` could conceal incomplete suites; the current completion-enforcing result is listed below. The SLO suite uses the real bundled cryptographic library and local HTTP/GLPI boundary doubles. The missing HTML-escaping helper and developer-specific paths are resolved in test shims, without changing production escaping behavior.

Release-catalog checks now distinguish development from packaging. Every published entry is still checked for a valid version, duplicate entries and the expected upstream download path (including the historical plugin name). A newer development version must be explicitly listed in the changelog. Packaging sets `SAMLSSO_RELEASE_VALIDATION=1`, requiring the exact version entry; no fictitious download was added. Fixtures prove rejection of missing release entries, undeclared/older versions, empty catalogs, invalid URLs and duplicates.

On 2026-10-16, the full rebased plugin passed a fresh GLPI 12.0.0 / Authentik browser integration test after owner authentication. A malformed callback was rejected without clearing the application session. A real signed IdP-initiated logout returned to the IdP login page, removed the dedicated IdP session, and caused the old GLPI central page to report an expired session. The production provider and its existing session/dependencies remained unchanged. Temporary test-provider settings and application configuration were restored afterward.

This integration test caught a missing provider ID in the generated SLO endpoint that the controller-only doubles did not cover. ConfigIntegrityTest now exercises the real configuration builder with two provider IDs. The correction retains exact destination validation; it does not relax signature or identity/session checks.

## Expanded cleanup branch

The SLO-only candidate also passed a fresh GLPI 11.0.11 browser test on 2026-10-16: malformed signed-query rejection preserved the login, a real IdP-initiated logout removed the dedicated IdP session, and the GLPI session expired. The unrelated production session and provider remained unchanged.

The owner subsequently requested a separate whole-project warning cleanup. That work is on `chore/project-static-analysis`, based on `fix/idp-initiated-slo`. See [the analysis and regression report](STATIC-ANALYSIS-CLEANUP.md). Its historical runner reported 19 passing suites, and both isolated GLPI installation/activation checks passed. The broader candidate `b01b1a0` passed its own fresh GLPI 11.0.11 and 12.0.0 browser acceptance on 2026-10-19, including login, configuration rendering, negative logout and signed IdP-initiated logout. See the analysis report for the later review corrections and current acceptance status. Earlier results are not used as proof for changed candidate code.

## Before an upstream PR

- Completed: all 20 standalone suites finish and pass under fixed PHP diagnostic settings and a completion marker; 37 real-toolkit SLO cases and a native rule-page contract suite are included. Early-exit false positives in the previous runner are corrected.
- Completed: Intelephense and SonarLint return zero diagnostics for the revised 54-file PHP tree. PSR-12 checks pass for the four explicitly scoped files listed in the analysis report, with narrow standalone-test exceptions.
- Historical: SLO-only and `b01b1a0` GLPI 11/12 browser integration passed; these results remain evidence only for those earlier versions.
- Current corrections: GLPI 11.0.11 passed fresh login, rule list/form, rejected bare/malformed logout with session preservation, a local-only SP completion page, and separately scoped IdP-initiated logout with session expiration.
- Current corrections: GLPI 12.0.0 passed the same fresh browser matrix: login, rule list/form, bare/malformed logout rejection with session preservation, local-only SP completion with expired GLPI access, and scoped IdP logout removing the target session while preserving unrelated sessions.
- Update translation catalogs for the new message IDs before upstream submission; they currently fall back to English. Review the strict signed-request requirements with maintainers. Actual reverse-proxy browser acceptance remains unverified; forwarded-header toolkit tests pass.
- Agree on unsupported cases listed in ADR 0025. The SP completion page neither correlates LogoutResponse nor confirms IdP-wide logout; general cross-origin iframe behavior is not claimed.
- Split test infrastructure/release policy, SLO, compatibility corrections and broad refactoring into reviewable changes with appropriate issue scopes; do not submit this whole branch as a purely mechanical cleanup.
- The contribution guide references SECURITY.md, but that file is absent in this checkout. ADR 0017 and the architectural Wiki were reviewed; obtain the intended security policy before submission.

No upstream issue, PR, maintainer message or production deployment has been made by this preparation task. This is a review candidate, not a release or an unconditional production-upgrade recommendation.
