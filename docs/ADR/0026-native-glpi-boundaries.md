# ADR 0026: Native GLPI routes and persistence

## Status

Proposed. Compatibility context: https://github.com/DonutsNL/samlsso/issues/167.

## Context

GLPI's canonical plugin URL already includes its installation prefix. Adding the prefix again
breaks installations below a subdirectory. GLPI 11 and 12 persistence APIs accept raw values;
legacy HTML sanitization before an update changes the stored username and other user fields.

## Candidate decision

Resolve plugin routes through the native version-specific API and add only the configured origin
when an absolute protocol URL is required. Pass validated raw user values to GLPI persistence and
leave output escaping to its renderer. Use GLPI's native database expression namespace.

Verify these contracts against both installed framework versions, including root and subdirectory
URLs and database round trips with apostrophes, ampersands, Unicode and HTML-looking text. No
replacement core sanitizer, database class or URL function is used in the acceptance suite.

## Consequences and alternatives

Existing configuration and public routes remain compatible. Encoding values before persistence
would preserve the former corruption; modifying GLPI core would couple this plugin to a local fork.
The plugin continues to depend on the deployment's correct canonical URL and proxy configuration.

## Documentation proposal

Clarify in the installation Wiki that protocol URLs use GLPI's configured origin and installation
prefix. Do not recommend manual duplication of the prefix or HTML encoding of user attributes.
