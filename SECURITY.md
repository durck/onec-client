# Security

## Reporting

For a suspected vulnerability, use the repository's **Security → Report a
vulnerability** entry if private reporting is enabled. If that entry is absent,
ask the maintainer for a private contact without posting exploit details,
credentials, captured authentication messages or business data in a public issue.

Include the revision, platform, affected operation and a minimal synthetic
reproduction where possible. Separate observed behavior from assumptions.

## Scope

This is an independent implementation of a bounded 1C protocol subset. It is
not a complete replacement for the official client. Use only systems and
accounts for which you have authorization.

CLI network operations preview by default. Secrets belong in hidden prompts,
explicit stdin or the documented credential provider, never command-line
password arguments or Git. EPF files can execute server-side opening handlers;
review the file before granting its opening confirmation.

Offline tests are the required development baseline. They do not establish
interoperability or security guarantees for every server build. See
[compatibility](go-onec/docs/COMPATIBILITY.md) and
[authentication boundaries](go-onec/docs/AUTH-ACCEPTANCE.md).
