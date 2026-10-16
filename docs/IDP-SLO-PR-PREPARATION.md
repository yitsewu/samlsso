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

## Before an upstream PR

- Completed: standalone unit/regression suite is green (18/18); release packaging remains intentionally strict.
- Run Intelephense and SonarLint (not available in this preparation environment).
- Review formatting, localization and the strict signed-request requirement with maintainers.
- Completed: full rebased GLPI 12 browser integration. GLPI 11 browser integration is not verified by this task and must not be claimed.
- Extend protocol coverage and agree on unsupported cases listed in ADR 0025.
- The contribution guide references SECURITY.md, but that file is absent in this checkout. ADR 0017 and the architectural Wiki were reviewed; obtain the intended security policy before submission.

No upstream issue, PR, maintainer message or production deployment has been made by this preparation task.
