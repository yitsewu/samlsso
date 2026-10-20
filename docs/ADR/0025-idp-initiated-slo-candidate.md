# ADR 0025: Signed IdP-initiated logout

## Status

Proposed. Related issue: https://github.com/yitsewu/samlsso/issues/1.

## Context

The logout hook catches the protocol callback as a local logout action. The callback controller renders a page without consuming the IdP request. A user may finish an IdP logout while the application session remains usable.

## Candidate decision

Let the exact plugin callback route reach its controller. Capture NameID, SessionIndex and the provider identifier after the existing validated ACS login and native session initialization. Require an RSA-SHA256/384/512 signed HTTP-Redirect LogoutRequest, strict XML/issuer/destination validation, a matching current login context and a five-minute issue time window. Reject SHA-1, missing and unknown algorithm identifiers explicitly. Preserve LoginState and move it to PHASE_LOGOFF before native session cleanup. Build the protocol response with the bundled OneLogin toolkit.

Honor forwarded origin headers only when the provider's existing Requests Proxied setting is enabled. Restore the toolkit's previous proxy setting and libxml error mode after success or rejection. This provider setting still depends on the deployment's trusted reverse-proxy configuration.

Sign outgoing responses with the same form URL encoding used by the bundled toolkit's redirect serializer. The local response settings override its inconsistent `lowercaseUrlencoding` signing option without changing persisted provider configuration. Incoming signatures are checked against the original query bytes. Tests independently verify the actual response query for both provider settings, including spaces, plus signs, tildes and Unicode RelayState values.

The callback clears only its current browser session. It does not find or destroy other users' sessions. A consumed login loses its context, so repeating the request cannot clear a later unrelated login. Old sessions require a fresh SAML login after deployment.

The protocol suite boots an installed, disposable GLPI framework and uses its actual database, users, sessions, plugin hooks and controller. Signed requests and response verification use the bundled OneLogin toolkit. CGI subprocesses exercise terminating response paths and contribute measured coverage. No GLPI core class or function is replaced. This follows ADR 0017 and the current development skill's no-core-mocking requirement; ADR 0003's earlier shim approach is not used by the validation gate.

## Limits and alternatives

This candidate requires NameID and SessionIndex in the authenticated assertion. It deliberately rejects unsigned requests and LogoutRequest messages without a matching login context. It does not process or correlate unsolicited LogoutResponse messages. An already logged-out browser making a GET without SAMLRequest may receive an inert local completion page, including on an SP return; that page does not mutate a session, validate a protocol response or confirm IdP/global logout. An authenticated browser does not receive that success page. A follow-up design is needed for SP-initiated response correlation, expired-session acknowledgements, encrypted NameID, full replay-cache semantics across reused IdP indexes and back-channel logout. A server-side session-index registry is an alternative but adds persistent schema and lifecycle concerns beyond this change.

The supported browser flow uses top-level navigation; cross-origin iframe behavior is not established. The design preserves core files, login replay rules and existing identity-provider configuration.

## Documentation proposal

Add a Wiki section explaining the allowed signature algorithms, signed IdP logout requirements, proxy trust setting, fresh-login migration, supported HTTP-Redirect direction, error behavior, and the above unsupported cases. Explain that the SP return page reports only local GLPI logout and that an IdP core session can remain active. Preserve upstream licensing and attribution; no relicensing is proposed.
