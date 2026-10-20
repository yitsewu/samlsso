# ADR 0027: Bound state and configuration validation

## Status

Proposed. A dedicated issue must be agreed before upstream submission; this local candidate does
not claim that an issue or this decision has been accepted.

## Context

Authentication-state lookup must identify one row. Ambiguous rows and malformed configuration
options cannot safely be treated as valid authentication context. Long state and form methods also
make it difficult to review persistence, timeout, diagnostic rendering and restoration separately.

## Candidate decision

Keep the existing public methods and database schema. Extract cohesive helpers for state loading,
phase evaluation, persistence, validated configuration restoration and escaped diagnostic rendering.
Reject ambiguous authentication rows and malformed options before consuming their values. Preserve
the original assertion correlation and replay checks, rule include variables and lifecycle ordering.

Exercise database round trips, timeout writes, replay rejection, native rule rendering and restore
operations in a disposable GLPI 11/12 environment. Map LoginFlow methods to executed test cases and
measure their execution with Xdebug; a list of test names alone is not evidence of coverage.

## Consequences and alternatives

The decomposition increases the number of private helpers while keeping changes reviewable and
the public API stable. Keeping the monolithic methods would retain the same review and regression
risks. Renaming public GLPI fields or introducing an unimplemented PluginContext API would break
existing contracts and is outside this candidate.

## Documentation proposal

Describe rejected ambiguous state and invalid configuration inputs in the troubleshooting Wiki.
Keep internal implementation details out of end-user error messages.
