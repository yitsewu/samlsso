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

The rebased candidate passes IdpSloTest.php (valid request plus eight rejected variants) and PHP parsing. The complete upstream runner was executed on both the unmodified base and this candidate using the same isolated PHP runtime and HTTP Foundation dependency bootstrap. Candidate: 16/18 suites passed; base: 15/17. Both have the same two unresolved failures:

- AcsTest.php reaches a missing htmlescape() test-environment helper.
- VersionAndCopyrightTest.php expects a 1.3.2 entry absent from the base samlsso.xml.

The harness environment supplies HTTP Foundation, the ERROR constant and a test-only plugin root because upstream tests refer to a developer-specific installation path. No production application was used or changed. Test logs and environment-specific paths are intentionally not published.

## Before an upstream PR

- Resolve the baseline test environment and release-manifest checks; do not report the full suite as green.
- Run Intelephense and SonarLint (not available in this preparation environment).
- Review formatting, localization and the strict signed-request requirement with maintainers.
- Re-run full browser integration on the rebased branch, including GLPI 11 and 12 where support is claimed.
- Extend protocol coverage and agree on unsupported cases listed in ADR 0025.
- The contribution guide references SECURITY.md, but that file is absent in this checkout. ADR 0017 and the architectural Wiki were reviewed; obtain the intended security policy before submission.

No upstream issue, PR, maintainer message or production deployment has been made by this preparation task.
