# Port scanning and endpoint checks

`onec ports scan` checks one host and a bounded TCP port set. `onec ports check`
uses the same detector for one port. Neither needs an infobase name. The CLI
previews options without DNS, process inspection or network I/O until `--apply`.

Both commands support [SOCKS5 routing](PROXY.md) with
`--proxy socks5://127.0.0.1:1080`. In that mode, banners and role probes use the
same proxy, target DNS is remote, and local process inspection is disabled.
Domain targets have no locally pinned/resolved IP. Proxy failures are errors,
not closed target ports; error/timeout/canceled results make proxied runs fail.

From the `go-onec` directory:

```powershell
# Default pool includes the usual agent/manager ports and the worker range.
./bin/onec.exe ports scan --host 127.0.0.1 --apply

# A particular range or a comma-separated combination.
./bin/onec.exe ports scan --host server.example --ports 1540,1541,1560-1591 --apply

# Check a single endpoint.
./bin/onec.exe ports check --host 127.0.0.1 --port 1563 --apply

# Structured output, also usable to select worker candidates.
./bin/onec.exe ports scan --host server.example --ports 1560-1591 --json --apply

# Greeting only: no anonymous authentication or RPC interface queries.
./bin/onec.exe ports check --port 1563 --roles=false --local-process=false --apply
```

## What is identified

The table separates independent evidence:

| Column | Meaning |
| --- | --- |
| STATE | `open`: TCP connected; `closed`: connection refused; `timeout`: connect timed out; `error`: another connection failure; `canceled`: not completed because the overall operation stopped |
| PROTOCOL | `onec-native`: exact observed five-byte 1C greeting; `ssh`: SSH greeting prefix; `unknown`: no recognized greeting |
| LOCAL PROCESS (PID) | Windows listener snapshot for the selected loopback address; independent of protocol recognition |
| RPC ROLE | A successfully queried known interface; `unknown` means no interface was confirmed |
| DETAIL | Missing/unrecognized greeting, unconfirmed roles or cleanup |

An open silent service stays `open / unknown`. Nothing is sent to a port unless
it first provides the exact 1C greeting. No role is inferred from a port number.
A greeting or a successful interface query is a peer-provided protocol claim,
not cryptographic verification of an executable or a complete service audit.

On Windows loopback, the detector also reads the local TCP listener table and
process names. This can identify `ragent.exe`, `rmngr.exe`, `rphost.exe`,
`dbda.exe` or other processes, even when no known greeting arrives. It uses
Windows APIs directly, without PowerShell, COM, vendor DLLs or administrator
elevation. PID/name snapshots can race with process exits or listener changes;
they are not a permanent port assignment. Names can be unavailable while PIDs
remain visible. No local ownership lookup is applied to a remote address.

## Anonymous role checks

After recognizing a 1C greeting, the default detector makes at most two fresh
connections to the same pinned address, in this order:

1. `working-process-administration`: opens `AdminProcessContext` and queries
   `InfobaseListInterface`, requiring the observed query result `15`.
2. `cluster-manager-selection`: opens `ManagerContext` and queries
   `SelectInterface`, requiring query result `1`.

Both use explicit anonymous NTLM: SSPI on Windows, pure Go on Linux. No
current-account fallback, credentials, database selection, `GetInfoBases`,
application login or business operation is used. A successfully opened context
is released when the stream remains synchronized, then its socket/security
objects are closed. JSON separates `context_opened`, `context_released` and
`closed`; interface recognition survives a cleanup failure, which stays visible.

`context_unavailable` is deliberately inconclusive: it can reflect an unsupported
context, rejected transport, incompatible build, or failed exchange. It does not
establish a specific access-control rule. A role query can be rejected even on
the expected process. Unrecognized RAS, repository, debugger, Data Accelerator,
HTTP, TLS or database protocols are not identified remotely by port-number guesses.

Greeting detection and anonymous role checks run on Linux and Windows. Local
process ownership inspection requires Windows. Use `--roles=false` to avoid
anonymous handshakes, and `--local-process=false` to omit process inspection.

## Bounds and results

- Defaults: host `127.0.0.1`, scan ports `1540-1591`, four concurrent ports,
  five seconds per port, two minutes overall. Check mode requires `--port`.
- `--ports` accepts inclusive ranges and deduplicates/sorts ports. Limits:
  1..65535, at most 1024 unique ports, `--concurrency` 1..16.
- `--timeout` is positive and at most one minute. Initial greeting wait is at
  most 500 ms. Each opened role context may add up to 500 ms for cleanup after
  the operation deadline (at most one second per port).
- Without a proxy, hostnames resolve once to IPv4; the first usable address is pinned for all
  checks and printed as `resolved_ip`. Other addresses are not scanned.
- Ctrl+C / `--total-timeout` returns ordered partial results and a nonzero exit.
  Closed ports, unknown services and rejected role probes are normal findings;
  they do not make the scan fail. JSON `success` means the scan completed.
- The scan examines TCP only. It neither reads the configured cluster port pool
  nor discovers every cluster host. Supply a custom `--ports` range when needed.
- `--client-version` changes the advertised build, not the measured server version.

After a confirmed worker-role result, use its address explicitly:

```powershell
./bin/onec.exe infobases --worker 127.0.0.1:1563 --apply
```

`infobases` itself still requires `--worker`; scanning is a separate operation.

## Library

```go
report, err := onec.ProbePorts(ctx, onec.PortProbeConfig{
    Host: "server.example",
    Ports: []int{1540, 1541, 1560, 1561, 1562, 1563},
    Timeout: 5 * time.Second,
    Concurrency: 4,
})
```

`ValidatePortProbeConfig` performs no I/O. `ProbePorts` returns the ordered report
and a context error on cancellation. Inspect the results independently of the
operation error. The caller context should bound the complete scan.

## Compatibility

Live role identification is bounded to **8.3.18.1208**. Greetings and interface
queries identify supported endpoint roles; they do not prove authentication to an
infobase or compatibility with arbitrary newer builds. See [compatibility](COMPATIBILITY.md).

Local process ownership is Windows-only and uses Microsoft's
[GetExtendedTcpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable)
and [MIB_TCPROW_OWNER_PID](https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_pid)
contracts. Linux still supports network discovery and anonymous role queries.
