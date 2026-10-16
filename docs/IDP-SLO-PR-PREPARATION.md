# IdP-initiated SLO: contribution preparation

Tracking: https://github.com/yitsewu/samlsso/issues/1

This fork branch is a review candidate, not a release. Base: upstream main `8d4823b`. Upstream already includes a GLPI 11/12 compatibility layer; this branch does not duplicate the earlier private compatibility changes.

## Included

- Protocol callbacks bypass the local logout chooser.
- Fresh validated ACS sessions retain the minimum logout correlation context.
- Signed requests are checked before native session cleanup and a protocol response.
- Standalone cryptographic regression test using generated ephemeral keys and fictional identities.
- Test-harness SessionIndex support and a proposed ADR/Wiki update.

## Validation

The earlier prototype passed an isolated GLPI 12 / Authentik browser test: signed IdP request, callback redirect, IdP login screen, and denied access to the old application session. This is historical prototype evidence, not an end-to-end claim for this rebased branch.

The rebased candidate now passes all 18 suites using `php tests/RunAllTests.php` without an external GLPI bootstrap. The SLO suite uses the real bundled cryptographic library and local HTTP/GLPI boundary doubles. The missing HTML-escaping helper and developer-specific paths are resolved in test shims, without changing production escaping behavior.

Release-catalog checks now distinguish development from packaging. Every published entry is still checked for a valid version, duplicate entries and the expected upstream download path (including the historical plugin name). A newer development version must be explicitly listed in the changelog. Packaging sets `SAMLSSO_RELEASE_VALIDATION=1`, requiring the exact version entry; no fictitious download was added. Fixtures prove rejection of missing release entries, undeclared/older versions, empty catalogs, invalid URLs and duplicates.

The full rebased plugin is installed and active on an isolated GLPI 12 test instance. Fresh browser authentication is awaiting the owner's password/MFA; end-to-end acceptance is not yet complete. No production application or shared identity flow was changed.

## Before an upstream PR

- Completed: standalone unit/regression suite is green (18/18); release packaging remains intentionally strict.
- Run Intelephense and SonarLint (not available in this preparation environment).
- Review formatting, localization and the strict signed-request requirement with maintainers.
- Re-run full browser integration on the rebased branch, including GLPI 11 and 12 where support is claimed.
- Extend protocol coverage and agree on unsupported cases listed in ADR 0025.
- The contribution guide references SECURITY.md, but that file is absent in this checkout. ADR 0017 and the architectural Wiki were reviewed; obtain the intended security policy before submission.

No upstream issue, PR, maintainer message or production deployment has been made by this preparation task.
