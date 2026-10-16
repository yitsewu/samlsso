# ADR 0025: Signed IdP-initiated logout (fork candidate)

## Status

Proposed in https://github.com/yitsewu/samlsso/issues/1. Not an upstream decision or a production release.

## Context

The logout hook catches the protocol callback as a local logout action. The callback controller renders a page without consuming the IdP request. A user may finish an IdP logout while the application session remains usable.

## Candidate decision

Let the exact plugin callback route reach its controller. Capture NameID, SessionIndex and the provider identifier after the existing validated ACS login and native session initialization. Require a signed HTTP-Redirect LogoutRequest, strict XML/issuer/destination validation, a matching current login context and a five-minute issue time window. Preserve LoginState and move it to PHASE_LOGOFF before native session cleanup. Build the protocol response with the bundled OneLogin toolkit.

The callback clears only its current browser session. It does not find or destroy other users' sessions. A consumed login loses its context, so repeating the request cannot clear a later unrelated login. Old sessions require a fresh SAML login after deployment.

## Limits and alternatives

This candidate requires NameID and SessionIndex in the authenticated assertion. It deliberately rejects unsigned requests, missing context, and unsolicited LogoutResponse messages. A follow-up design is needed for SP-initiated response correlation, expired-session acknowledgements, encrypted NameID, full replay-cache semantics across reused IdP indexes and back-channel logout. A server-side session-index registry is an alternative but adds persistent schema and lifecycle concerns beyond this change.

Prefer top-level browser navigation for the isolated integration test; no general claim is made about iframe behavior on other origins. No core files, login replay rules, or configured production identity providers are changed.

## Documentation proposal

Add a Wiki section explaining signed IdP logout requirements, fresh-login migration, supported HTTP-Redirect direction, error behavior, and the above unsupported cases. Keep SP-initiated logout guidance separate. Preserve upstream licensing and attribution; no relicensing is proposed.
