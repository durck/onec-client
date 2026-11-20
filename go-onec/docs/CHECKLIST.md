# Empty-password audit checklist

`onec checklist` runs the native administrative and infobase checks for a host
or a UTF-8 host list. It writes a JSON report and prints each result to the
console. It uses the existing native client; it needs no installed 1C client
or COM connector. The default anonymous transport runs on Linux and Windows. Current-session
`--transport windows` remains Windows-only. See [compatibility](COMPATIBILITY.md) for the evidence boundary.

## Run

```powershell
# Preview: no DNS/network requests and no report file creation.
./bin/onec.exe checklist --target 192.0.2.10

# Execute against one IP or DNS name; a leading positional host also works.
./bin/onec.exe checklist audit-host.example --execute --report-file audit.json

# Execute against a file, with findings reflected in the exit code.
./bin/onec.exe checklist --targets-file targets.txt --execute --report-file audit-batch.json --fail-on-findings

# Customize nonstandard ports and bounds.
./bin/onec.exe checklist --target 192.0.2.10 --agent-port 2540 --manager-port 2541 --worker-ports 2560-2591 --max-attempts 500 --interval 2s --execute

# Machine-readable final report on stdout; progress remains on stderr.
./bin/onec.exe --output json checklist --targets-file targets.txt --execute

# Route every native stage through SOCKS5, including discovery and role probes.
./bin/onec.exe checklist --targets-file targets.txt --proxy socks5://127.0.0.1:1080 --execute
```

Example `targets.txt` (replace the documentation addresses with audit targets):

```text
# One IPv4 address or DNS name per line
192.0.2.10
audit-host.example
```

Blank lines, full-line `#` comments and a UTF-8 BOM are accepted. Input is bounded
to 1 MiB and 4096 distinct hosts. DNS names use ASCII/punycode. URLs, CIDRs,
embedded ports and IPv6 are rejected. Names are normalized and deduplicated;
without a proxy,
each is resolved once to one IPv4 address. Aliases resolving to an already
processed IP are recorded without repeating checks. This is not enumeration of
every address in a DNS record set.

With `--proxy`, domains are resolved by SOCKS5 for each connection. The client
does not know the selected IP and cannot deduplicate aliases by IP; literal IP
targets retain address pinning. Proxy failure never triggers a direct target
connection. See [SOCKS5 routing](PROXY.md) for optional authentication and scope.

The default report name is `onec-checklist-<UTC timestamp>.json` in the current
directory. `--report-file` must name a new file in an existing writable directory.
The file is opened before any network request, and existing files are never
overwritten. Ctrl+C and the total timeout preserve partial results after bounded
cleanup. A forced process kill or disk-write failure cannot guarantee a report.

## Checks and discovery

1. Read the central server administrator list on the agent port (default 1540).
   Explicitly test empty username/empty password, then one empty password for
   each discovered administrator with password authentication enabled.
2. Enumerate clusters and repeat the default/named administrator checks for
   each cluster. Read its database inventory using accessible permissions.
3. Probe additional worker ports (default 1560-1591) and enumerate databases on
   confirmed working-process administration interfaces. This can discover
   databases even when administrative inventory is unavailable.
4. For each discovered database, request the prelogin user selection list.
   Test exactly one empty password candidate for each distinct returned name,
   using a fresh connection and the selected password method. Close the context
   and log out after successful authentication.

Listing an object is recorded separately from successful authentication. Empty
administrative credentials that succeeded are reused for subsequent inventory
reads; those reads require additional authentication exchanges. No administrative
mutation, session termination, EPF execution, password change or account change is
part of this command. Authentication attempts can still generate audit events
and affect configured account lockout counters.

Agent, advertised manager and manager-selected worker connections remain on the
resolved target IP, or the supplied name when using proxy DNS. Returned hostnames
do not expand the target list. The first
advertised manager port is used, falling back to `--manager-port` (1541) when no
endpoint is advertised. Database IDs are deduplicated per IP; cluster routes
take precedence over duplicate worker routes. An unavailable selected route is
reported as a gap; it is not silently retried through another route. Distributed
deployments may therefore require additional explicit targets.

`--worker-ports none` disables additional worker discovery, but does not disable
manager-to-worker selection for known databases. Role detection uses anonymous
plain transport; it cannot qualify all protected or experimental-policy endpoints.
Unconfirmed 1C worker interfaces, failed probes and failed cleanup remain visible.

## Bounds and identity

| Option | Default | Meaning |
| --- | --- | --- |
| `--transport` | `anonymous` | Explicit outer identity; `windows` uses the current OS session |
| `--auth` | `legacy` | Exactly one password method: `legacy`, `v1`, `v2`, `v3` |
| `--client-version` | `8.3.18.1208` | Advertised build, not version detection |
| `--transport-policy` | `plain` | Explicit policy; native27 selectors remain experimental |
| `--timeout` | `20s` | Each operation, at most 5m; cleanup has a separate bounded timeout |
| `--total-timeout` | `30m` | Whole run, at most 24h |
| `--interval` | `1s` | Minimum interval between credential checks, 0..1m |
| `--max-attempts` | `1000` | Global scheduled credential-check limit, 1..100000 |

Credential checks are sequential. Worker port discovery uses four workers and
up to five seconds per port. There are no password dictionaries, method fallback,
automatic credential retries or context recovery. After a policy, operational or
cleanup failure during a database login, the remaining users in that database
are recorded as unattempted; unrelated databases may continue. The global limit
or cancellation stops remaining work.

The check limit includes default and named administrative checks and infobase
checks, including candidates whose connection failed before login. It does not
count the repeated successful administrative authentication needed for inventory.
`authentication_requested` means the authentication operation was requested,
not proof that a credential-bearing packet reached the peer.

## Read the report

The JSON contains `schema_version`, UTC start/end timestamps, options, coverage,
summary counters and individual results. Rows identify the target/IP, endpoint,
cluster, database, username, check, status and cleanup uncertainty where applicable.
Summary counters describe processed input targets, discovered clusters/databases
and distinct database usernames; `skipped` counts result rows, not accounts.
The full configured target list remains in `options.targets` after early termination.

| Status | Interpretation |
| --- | --- |
| `finding` | Explicit empty administrative credentials or an empty infobase password were accepted |
| `not_accepted` | The administrative RPC or login was refused; this does not prove a nonempty password |
| `error` | Network, protocol, policy, operation or cleanup failure prevented a reliable result |
| `skipped` | A required check could not run; the reason and remaining count are reported when known |
| `info` | Discovery, alias deduplication or a non-password administrator record |

A finding survives a later read/logout/cleanup error. `cleanup_failed: true`
adds to the error count without erasing that finding. Raw server errors, secret
tokens and credential values are excluded from reports; usernames and deployment
identifiers remain audit data.

`completed: true` means the scheduled checks finished without errors/skips. It
never means all real accounts were enumerated or that the target is secure.
`coverage` is always `discovered_objects_only`: hidden users, inaccessible
databases, other worker ranges and unlisted hosts are outside that inventory.
An empty user list is a coverage gap, not a clean bill of health. A refused login
can reflect a password, account state, policy, licensing or protocol compatibility.

Exit codes: **0** completed (findings allowed by default), **1** incomplete,
report/output failure, or findings with `--fail-on-findings`; **2** invalid CLI
input. Consult the JSON to distinguish findings from incomplete coverage.

## Validation boundary

Checklist orchestration, input validation, reporting, cancellation, limits and
failure handling have offline regression tests. This command has not received
a new live end-to-end acceptance run. Existing native live evidence is bounded
to build 8.3.18.1208; SecPswd V1/V3 have synthetic evidence, V2 has schema/synthetic
evidence, and native27 policies remain experimental. Selecting another advertised
build does not establish compatibility. See [authentication acceptance](AUTH-ACCEPTANCE.md).
