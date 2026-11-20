# Native server and cluster administration

`onec admin` connects to the server agent, normally TCP **1540**, using the Go
native protocol implementation. It does not use COM, an installed 1C client,
RAS, or an infobase application login. The manager's usual port 1541 and an
allocated working-process port are different endpoints.

Every CLI request is a preview until `--apply` is supplied. Preview validates
options and explicit targets without reading environment passwords, prompting
for passwords, acquiring a security context, or contacting the server. Library
operations execute immediately.

`--transport-policy` / `AdminConfig.TransportPolicy` separately selects record
processing. The default remains `plain`; explicit experimental `native27-n` and
`native27-c` have synthetic coverage but no real build-27 server acceptance.
See [policy scope](COMPATIBILITY.md#experimental-native-27-policy).

## Commands and explicit targets

Run examples from `go-onec` after building `bin/onec.exe`:

```powershell
./bin/onec.exe admin --help
./bin/onec.exe admin clusters
./bin/onec.exe admin clusters --agent 127.0.0.1:1540 --apply
./bin/onec.exe admin sessions --cluster 11111111-2222-3333-4444-555555555555
```

The UUIDs in this guide are placeholders. Use the exact IDs returned for the
intended cluster and session. No command selects the first cluster, a default
cluster, all sessions, or a wildcard target.

| Command | Required target | Result or action |
| --- | --- | --- |
| `clusters` | Agent endpoint | Cluster descriptors |
| `agent-admins` | Agent endpoint | Central-server administrator records |
| `cluster-admins` | `--cluster UUID` | Administrator records for that cluster |
| `servers` | `--cluster UUID` | Working-server descriptors |
| `processes` | `--cluster UUID` | Working-process descriptors |
| `bases` | `--cluster UUID` | Short infobase descriptors |
| `sessions` | `--cluster UUID` | Session descriptors |
| `terminate-session` | `--cluster UUID --session UUID` | Terminate exactly that session; optional `--message TEXT` |
| `set` | `--cluster UUID --setting NAME --value NUMBER` | Change one supported cluster setting |

`--session` takes the internal **session UUID** from the session descriptor,
not its numeric display ID. Administrator-list results never contain passwords.
Termination first lists sessions in the selected cluster, resolves the matching
infobase UUID, and sends one termination call. A missing or duplicate session
prevents submission. No working-process endpoint is followed.
The `bases` operation is distinct from the existing `onec infobases --worker`
command and its working-process authorization boundary.

Mutation examples deliberately remain previews:

```powershell
./bin/onec.exe admin terminate-session --cluster 11111111-2222-3333-4444-555555555555 --session aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee --message "Planned maintenance"
./bin/onec.exe admin set --cluster 11111111-2222-3333-4444-555555555555 --setting security-level --value 1
```

Review the target and add `--apply` to execute. There is no retry or automatic
replay after an uncertain result. Termination affects a running session;
settings affect cluster behavior. A connection or cleanup failure after a
mutation does not imply that the server rolled the change back.

Supported setting names and accepted decimal values:

| Setting | Value range |
| --- | --- |
| `security-level` | `0..2` |
| `kill-problem-processes` | `0..1` |
| `kill-by-memory-with-dump` | `0..1` |
| `load-balancing-mode` | `0..1` |
| `recycle-lifetime` | `0..2147483647` |
| `recycle-expiration` | `0..2147483647` |
| `fault-tolerance` | `0..2147483647` |

`recycle-lifetime` changes the cluster descriptor's `LifeTimeLimit` field;
it does not implement a separate restart schedule or an error-count threshold.
`recycle-expiration` maps to `ExpirationTimeout`, `fault-tolerance` to
`FaultToleranceLevel`, and `load-balancing-mode` to `LoadBalancingMode`.
The supported kill flags map to `KillProblemProcesses` and
`KillByMemoryWithDump`. There is no supported `recycle-errors` setting.
The lifetime, expiration, load-balancing and kill options read the current
descriptor and submit the supported settings group with one value changed.
That sequence is not atomic: concurrent administrative changes to the same
group can be overwritten. Security level and fault tolerance use separate
native setters.

The native settings retain their platform semantics. This command does not
create or delete administrators, clusters, servers, or infobases, and does not
change OS accounts, services, licenses, or platform installations.

## Transport and two authentication scopes

Transport defaults to `windows` on Windows and `anonymous` on Linux.
`--transport windows` uses the current Windows security context;
`--transport anonymous` selects a null-session exchange without account credentials. Neither
mode falls back to the other. These built-in transports require Windows SSPI;
successful transport authentication does not establish administrative authority.

Agent credentials and cluster credentials have independent options:

| Scope | Mode | Username | Password source |
| --- | --- | --- | --- |
| Central server | `--agent-auth none\|default\|password` | `--agent-user NAME` | `--agent-password-env VARIABLE_NAME` or hidden prompt |
| Selected cluster | `--cluster-auth none\|default\|password` | `--cluster-user NAME` | `--cluster-password-env VARIABLE_NAME` or hidden prompt |

Both modes default to `none`, which sends **no administrator-authentication
call**. `default` explicitly submits empty name/password credentials. Success
does not prove that no administrators exist. The native COM connector can retry
empty credentials with an internal OS-authentication marker; this client does
not perform that implicit retry. A separate OS-administrator selection mode is
not implemented. `password` requires a nonempty username
and reads that scope's password only after `--apply`. A named administrator
with an empty password remains a named password authentication attempt.

Cluster authentication options are available only on commands that require a
cluster UUID. Agent authentication may accompany any supported command; it
never substitutes for cluster authentication. Credentials are attempted once
per requested scope, and failure stops the requested operation.

For a hidden cluster-password prompt:

```powershell
./bin/onec.exe admin sessions --cluster 11111111-2222-3333-4444-555555555555 --cluster-auth password --cluster-user operator --apply
```

For automation, arrange for the process environment to contain the password
through your existing secret-management mechanism, then pass its **variable
name**, never its value:

```powershell
./bin/onec.exe admin agent-admins --agent-auth password --agent-user operator --agent-password-env ONEC_AGENT_ADMIN_PASSWORD --apply
```

There is no password-value command-line flag. A missing environment variable
fails before connection; an existing empty variable supplies an empty password.
Passwords are UTF-8, at most 4096 bytes, and may not contain NUL. The CLI omits
credential inputs and termination-message text from its reports and redacts
submitted password values from returned diagnostics and JSON string fields.
Keep any administrative result reports private according to their contents.
The recovered administrator protocol serializes the supplied password as a
generic string. This client does not add TLS or SSPI message sealing to these
RPC records; the SSPI bootstrap alone is not payload encryption.

## Available data

Results project verified fields rather than returning native persistence arrays:

| Object | Exposed fields |
| --- | --- |
| Cluster | UUID, name, advertised endpoints, `settings_available`, mapped settings and newer recycling schedule |
| Administrator | Name, description, OS account name, password/OS authentication flags |
| Working server | UUID, name, host, main port, configured port ranges |
| Working process | UUID, host, port, enabled/running, PID, connection count, memory/selection sizes, raw start date |
| Infobase | UUID, name, description |
| Session | Internal UUID, numeric display ID, infobase UUID/name/description, host, user, application, raw start/last-active dates |

The `*_at_raw` date fields preserve the platform's unsigned integer values;
they are not Unix timestamps. Calendar/time-zone conversion is not implemented.
Optional session statistics and license fields are structurally validated and
omitted. One older session-statistics representation has unresolved list
boundaries and is explicitly rejected. Such a response fails the operation and
prevents termination; it is never reported as an empty session list.
The legacy12-field cluster projection has `settings_available=false`; its
default numeric settings are not observations. Validated legacy recycling fields
are retained privately for preserving grouped writes. Unknown newer session or
license extensions also fail explicitly.

## Go API

`RunAdmin(ctx, config, request)` executes one request with scoped credentials
and returns final cleanup statistics even if a completed connection's interface
query fails. To reuse one context, use `DialAdmin`, `AuthenticateAgent`,
`AuthenticateCluster`, `Clusters`, `Sessions`, `SetClusterSetting`,
`TerminateSession`, and `Execute` for the other list commands. Always `Close`
the client; there is no reconnect or credential fallback.

```go
client, err := onec.DialAdmin(ctx, onec.AdminConfig{Agent: "127.0.0.1:1540"})
if err != nil { return err }
defer client.Close()
if err := client.AuthenticateCluster(ctx, clusterID, credentials); err != nil {
    return err
}
sessions, err := client.Sessions(ctx, clusterID)
```

Library calls execute immediately. Empty `AdminCredentials{}` means an explicit
default-authentication attempt; a nil request credential pointer sends no such
call. `errors.As(err, &mutationError)` with `*onec.AdminMutationError` distinguishes
a native rejection from `OutcomeUnknown`. A valid acknowledgment can coexist
with a later cleanup error. Mutation statistics describe the last validated
`Execute` request, including failures before submission; locally invalid requests
leave the preceding client state unchanged.

## Bounds and output

The default endpoint is `127.0.0.1:1540`; override it with `--agent host:port`.
The default `--timeout` is `20s`; it must be positive and at most `5m`. It bounds
the operation after credentials are read. Cleanup has a separate bounded
deadline, including after cancellation. Ctrl+C cancels the operation.
In the library, `AdminConfig.Timeout` bounds each exchange; supply a context
deadline to `RunAdmin` or `DialAdmin` to bound the whole operation.

Apply output is JSON with `mode`, `operation`, `agent`, authentication modes,
explicit target fields, `success`, `data`, and `stats`. `success` is false when
either the operation or cleanup fails. Partial `data` is preserved on cleanup
failure, and the command exits unsuccessfully. Use the separate mutation and
cleanup statistics to distinguish execution confirmation from release of the
remote context. A successful listing does not imply permission for a mutation.
An interface-query failure after connection also retains its final cleanup
statistics. Earlier bootstrap failures return their operation and cleanup errors;
they do not provide a completed administrative-context snapshot.

## Compatibility and evidence

`--client-version` accepts a syntactically valid advertised build. It does not
select the administration decoder or identify the remote binary. The actual
interface query selects known method-count profiles68/79/80/89/96; strict
collection layouts must agree with that profile. Stats report
`advertised_client_version` and `interface_methods` separately.

| Interface profile | Inspected client sources | Contract and limits |
| --- | --- | --- |
| 68 | 8.3.12.1529 |12-field cluster; eight-argument recycling preserves legacy memory/duration/error fields. No memory-dump flag. Termination uses three UUIDs and rejects a nonempty message. Working-server layout remains unconfirmed. |
| 79 | 8.3.17.1549,18.1208,19.1522 |10-field cluster; six-argument recycling and four-argument termination.19 has a working-server trailing string; full optional session acceptance remains separately limited. |
| 80 | 8.3.22.1709 |10-field cluster and later working-server trailing fields; unchanged selected management signatures. |
| 89 | 8.3.27.1859,27.2130 |15-field cluster. Recycling's second argument is a schedule string, preserved for partial settings; numeric `recycle-lifetime` is unavailable. |
| 96 | 8.3.27.2342 |Selected static signatures match the newer schedule profile; native-consumer synthetic bootstrap remains unresolved, so full runtime compatibility is not established. |

Unknown profiles/layouts are rejected. The IID and method IDs alone are not
compatibility proof: argument types changed even where arity stayed constant.
All mutation targets and any required fresh session route remain validated;
unsupported operations are rejected before a management write. Optional session
statistics/license formats are not all covered, especially newer27 extensions.
See [the complete module matrix](COMPATIBILITY.md).

Live administrative reads are bounded to **8.3.18.1208**. Settings changes and
session termination have static/synthetic evidence, without a live mutation
acceptance claim. Optional-field variants and newer server builds are not all
live-confirmed. The implemented command set covers only the interfaces described here.
