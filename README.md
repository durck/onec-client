# onec-client

**Audit 1C endpoints from one command.** An independent Go client for native TCP
and web protocols, with a CLI, guided console and reusable library. No installed
1C client, vendor DLL, COM connector or Python runtime is required.

[Quick start](#quick-start) · [Audit checklist](go-onec/docs/CHECKLIST.md) ·
[Commands](go-onec/README.md) · [Documentation](docs/INDEX.md) ·
[Compatibility](go-onec/docs/COMPATIBILITY.md)

## What it does

| Task | Command |
| --- | --- |
| Check empty server/cluster credentials and discovered infobase passwords | `checklist` |
| Route native checks through SOCKS5 with remote target DNS | `--proxy socks5://HOST:PORT` |
| Discover ports, databases and prelogin users | `ports`, `infobases`, `users` |
| Inspect clusters, servers and sessions | `admin` |
| Check web publications and authentication | `web` |
| Inspect/call supported EPF functions and view forms | `epf` |
| Inspect saved protocol traffic offline | `inspect` |

The checklist tests **discovered objects only**. Hidden users, inaccessible
databases and unsupported protocols remain coverage gaps. A refused login is
not proof of a nonempty password. Reports preserve findings, errors and skipped
checks separately. See [report interpretation](go-onec/docs/CHECKLIST.md#read-the-report).

## Quick start

Build from a source checkout with Go 1.25.13 or a compatible newer toolchain:

```sh
cd go-onec
go build -trimpath -buildvcs=false -o bin/onec ./cmd/onec
./bin/onec --help
./bin/onec wizard
```

**Linux and Windows are supported.** On Windows build with `-o bin/onec.exe`
and invoke `./bin/onec.exe`. Anonymous native transport is pure Go on Linux;
current-session Windows authentication remains Windows-only. Explicit NTLMv2
and file-backed Kerberos have their own documented scope. See
[Linux setup and validation](go-onec/docs/LINUX.md).

The module path is `onec`; installation from source uses a checkout rather than
remote `go install`. Release executables need no Go toolchain. Download the Linux amd64 or Windows
amd64 archive from the repository's **Releases** page; each includes a quick start
and dependency licenses.

### Run an audit

Examples run from `go-onec`. Replace documentation targets with authorized hosts.

```sh
# Review the plan; no connection or report file is created.
./bin/onec checklist --target audit-host.example

# Run the checks and save a new JSON report.
./bin/onec checklist --target audit-host.example --execute --report-file audit.json

# One IP or domain per line, optionally through SOCKS5.
./bin/onec checklist --targets-file targets.txt --proxy socks5://127.0.0.1:1080 --execute

# Structured stdout and an exit code that also reflects findings.
./bin/onec --output json checklist --targets-file targets.txt --execute --fail-on-findings
```

Network commands **preview by default**. Add `--execute` to run them. The wizard
shows a reusable command and preview before execution. `--output`, `--color`
and `--verbose` are global options and go before the command. Command-specific
options, including `--proxy`, go after it.

The checklist makes authentication attempts and can affect lockout counters.
Live use requires a reachable, configured and licensed server. Audit reports
contain target/account inventory: keep them private and outside source control.

## Scope and evidence

Native live acceptance is bounded to **8.3.18.1208**; HTTP Basic has separate
8.3.18/8.3.27 acceptance. The checklist and SOCKS5 orchestration have local
synthetic regression coverage, without a new live end-to-end acceptance claim.
Synthetic cross-version tests do not establish support on every server.
This project implements a documented subset of 1C protocols and is unaffiliated
with the 1C vendor.

## Explore and contribute

- [Console, wizard and completion](go-onec/docs/INTERFACE.md)
- [SOCKS5 routing](go-onec/docs/PROXY.md)
- [Library API](go-onec/docs/API.md)
- [Development and verification](CONTRIBUTING.md)
- [Changelog](go-onec/CHANGELOG.md) and [security](SECURITY.md)

From the repository root, `sh tools/test.sh` (Linux) or
`./tools/Test-Project.ps1` (Windows) runs offline tests and vet, then builds
the CLI. Tests need no server credentials.

## License

[MIT](LICENSE). Original dependency notices are retained in
[third-party notices](THIRD_PARTY_NOTICES.md) and `licenses/`.
