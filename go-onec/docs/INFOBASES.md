# Listing infobases through a working process

`onec infobases` lists names, UUIDs and descriptions without selecting or logging
into an infobase. It implements the observed working-process administration RPC
directly in Go. The product does not load `comcntr.dll`, use COM, or launch a
vendor client. Anonymous transport runs on Linux and Windows; current-session transport uses
Windows SSPI.

## CLI

Select the current `rphost` endpoint. The command does not scan ports, discover a
worker through the manager, or assume that port 1560 is always a worker.

```powershell
# Preview only: no connection or credential acquisition.
.\bin\onec.exe infobases --worker 127.0.0.1:1563

# Explicit anonymous NTLM; no fallback to the Windows account.
.\bin\onec.exe infobases --worker 127.0.0.1:1563 --transport anonymous --apply

# Explicitly use current-session Windows transport credentials instead.
.\bin\onec.exe infobases --worker 127.0.0.1:1563 --transport windows --apply
```

The endpoint above is a dated lab example. Recheck ownership after a restart.
Ports 1540 (agent), 1541 (manager), and 1545 (RAS) are different interfaces.
There is no `--base`, application `--auth`, password, or credential-file argument
for this command. `--timeout` bounds the CLI operation; cleanup has a separate
timeout of at most five seconds. Changing `--client-version` changes the
advertised version only and does not establish compatibility with that build.

`--transport-policy` / `InfobaseListConfig.TransportPolicy` separately selects
record processing. The default remains `plain`; explicit experimental
`native27-n` and `native27-c` have synthetic coverage but no real build-27 server
acceptance. See [policy scope](COMPATIBILITY.md#experimental-native-27-policy).

JSON output includes `success`, `infobases` and `stats`. Each entry contains
`name`, `id`, and `description`; an empty successful list is `[]`. The default
transport is `anonymous`. Its completed mechanism is reported as
`NTLM-anonymous`. `stats.authenticated` refers to application login and remains
false. Transport negotiation still takes place.

The anonymous provider creates a fresh explicit empty NTLM identity. Before
sending the final token it requires empty user/domain/NT-response fields, a
single zero LM byte, and no local-call optimization. On Windows it additionally checks the SSPI `NULL_SESSION` result; on Linux a
pure Go provider constructs the null-session exchange. It never retries with
default account credentials. Only the current-session `windows` mode requires
Windows. Anonymous completion is not server identity or infobase-login proof.

`success: false` or a nonzero exit code can accompany an already retrieved list
when cleanup fails. Inspect `context_released`, `security_closed` and `closed`
separately. A confirmed client release does not prove that every internal server
resource has been reclaimed. An incomplete exchange leaves release unconfirmed;
the client closes the socket without sending another RPC into an unsynchronized
stream. Cancellation after a fully consumed response frame preserves framing for
cleanup, while the canceled operation still returns an error.

## Library

```go
ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
defer cancel()
result, err := onec.ListInfobases(ctx, onec.InfobaseListConfig{
    Worker: "127.0.0.1:1563",
    Transport: "anonymous",
})
// Check err even if result.Infobases is populated: cleanup may have failed.
```

This is a one-shot API with automatic cleanup. `ValidateInfobaseListConfig`
validates options without network or credential access. The library's `Timeout`
is per exchange; use a caller context for an overall deadline. Advanced callers
can inject `SecurityFactory` and `DialContext`, as with the application client.
An injected provider is responsible for its own identity semantics.

## Protocol and evidence boundary

The client creates the administrative context
`a2c6af52-7d8b-46ef-9a69-cb1fa650e4f5` with selector
`##AdminProcess##:##AdminProcess##` and application label `COMConsole`. It queries
interface `7607aa1f-f87e-47a2-8a6b-701c7105ca63`, requires the observed query result
15, sends one list request, validates the typed collection, and releases the
context. Names/descriptions arrive in the collection; no additional remote
property getter is required for each entry.

The parser accepts the verified count followed by name/UUID/description triples,
with a one-MiB record limit and a maximum of 4096 entries. It rejects malformed or
unsupported replies without returning a partial list. Known native exceptions
are reported without server message text or private stack strings.

Live acceptance is bounded to a Windows server on **8.3.18.1208**, with anonymous
SSPI and confirmed context release.
Remote deployments, newer server builds and arbitrary multi-server visibility
remain unverified. This method does not grant access to database contents.
