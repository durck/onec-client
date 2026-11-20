# Changelog

## [Unreleased]

## [0.1.0] - 2026-11-20

### Added

- Pure Go anonymous NTLM transport on Linux, including checklist discovery,
  native role checks and administrator/database inventory. Added explicit
  anonymous library factory, platform-aware CLI defaults and Linux runtime
  verification against local synthetic peers. Windows session identity remains
  Windows-only; no new real-server compatibility claim is made.

- Host/list audit checklist for empty server and cluster credentials and empty
  passwords of discovered infobase users; JSON reports, console progress,
  bounded attempts and explicit incomplete-coverage results.
- SOCKS5 routing for native commands and all checklist stages, with remote
  target DNS, optional environment-backed authentication and no direct fallback.
- Guided console setup, grouped command help, text/JSON output and shell
  completion for PowerShell, Bash, Zsh and Fish.
- Native login/logout, prelogin user/settings discovery, database enumeration,
  port discovery and bounded supplied-credential checks.
- Native administration inventory and explicitly selected management operations;
  web publication inventory, application authentication and HTTP Basic checks.
- Supported EPF server calls, form workbench, module-image retrieval and
  offline traffic/lifecycle tools, with controlled fixtures and library APIs.
- Explicit experimental native27 transport policies. No new real-server
  acceptance is implied by selecting a policy or advertised version.

### Changed

- Put the audit workflow first in help and the wizard; unify English prompts,
  command examples, option groups and documentation navigation. Show readable
  durations and port ranges; keep caller-supplied report paths without adding a
  workstation prefix. Live checks require explicit execution.

### Fixed

- Keep proxy failures distinct from target connection refusals.
- Preserve synchronized framing and cleanup errors across cancellation and setup
  failures. Limit context-release recovery to the recognized credential-free
  refusal; never replay credential exchanges or application operations.
- Encode native HTTP continuation chunks correctly across the 16 KiB boundary.
- Redact native server exception payloads while retaining operation outcomes.

### Validation

- Offline synthetic peers and pinned fixtures cover protocol, authentication,
  cleanup, CLI, checklist and proxy behavior. Native live evidence is bounded to
  8.3.18.1208. See [compatibility](docs/COMPATIBILITY.md) for per-feature limits.
