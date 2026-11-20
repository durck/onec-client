# Contributing

Use Go 1.25.13 (the toolchain pinned in `go-onec/go.mod`) or a compatible newer
toolchain. On Linux, run `sh tools/test.sh`. On Windows, run from the repository root:

```powershell
./tools/Test-Project.ps1
```

This runs the offline tests and `go vet`, then builds the CLI. On other shells, run the equivalent
commands from `go-onec`:

```sh
go test ./...
go vet ./...
go build -trimpath -buildvcs=false -o bin/onec ./cmd/onec
```

Format Go changes with `gofmt`. Add focused behavior tests for parsers, protocol
logic and regressions. Use synthetic peers or sanitized fixtures for ordinary
tests; they must not require credentials, an installed 1C client or a live server.
Preserve the pinned control EPF bytes unless deliberately updating its validation.
The automated suite covers the checklist, SOCKS5, anonymous transport and CLI;
EPF examples support manual flows and are not needed by `go test`.

Keep protocol, authentication, application execution and cleanup outcomes
distinct. A synthetic test or a recognized interface does not establish live
compatibility. Describe the exact evidence and limitations in pull requests.

Keep changes focused and use descriptive commit subjects. Include the problem,
result and validation in the pull request. Do not add real accounts, credential
containers, tokens, captures, build products or local reports to Git.

The repository uses the local Go module path `onec`; build from a checkout.
