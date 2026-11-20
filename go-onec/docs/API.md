# API and session lifecycle

## Quick start

The local module path is `onec`. From another Go module, add
`require onec v0.0.0` and a `replace onec => /path/to/onec-client/go-onec` entry
to `go.mod`. Replace the path with your checkout; remote module installation
is not configured. Library calls execute immediately, without a CLI preview.

```go
package main

import (
    "context"
    "errors"
    "fmt"
    "time"

    "onec"
)

func login() (err error) {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    client, err := onec.Dial(ctx, onec.Config{
        Worker: "127.0.0.1:1560", Infobase: "demo",
    })
    if err != nil { return err }
    defer func() { err = errors.Join(err, client.Close()) }()
    return client.Login(ctx, onec.Credentials{Method: onec.WindowsAuth})
}

func main() {
    if err := login(); err != nil { fmt.Println(err) }
}
```

This uses current-session Windows SSPI. See [authentication](AUTHENTICATION.md)
for other providers and [compatibility](COMPATIBILITY.md) for supported scope.

## Port checks

`ProbePorts(ctx, PortProbeConfig)` checks an explicit port set on one pinned IPv4
host, with bounded concurrency and anonymous role probes. Results separate TCP
state, greeting signature, local Windows process ownership and RPC interfaces.
`ValidatePortProbeConfig` performs no I/O. Cancellation preserves ordered partial
results. See [port checks](PORTS.md) for defaults, cleanup and compatibility limits.

`PortProbeConfig.DialContext` supplies a custom dialer for both banner and role
connections and disables local process inspection. With `RemoteDNS: true`, it
receives the supplied hostname without local DNS or IP pinning; a custom dialer
is required. `PortProbeReport.DNSResolution` then reports `remote` and
`ResolvedIP` is empty for domain targets. These options are additive; ordinary
calls retain direct TCP and pinned local IPv4 resolution.

## Infobase enumeration

`ListInfobases(ctx, InfobaseListConfig)` is a separate one-shot administrative
operation. It requires a current worker endpoint, no infobase name, and owns
context/socket/security cleanup. Its default is explicit anonymous NTLM;
`Transport: "windows"` selects current-session credentials without fallback.
`ValidateInfobaseListConfig` performs validation only. Results contain names,
UUIDs, descriptions and cleanup statistics, including when a later cleanup
failure produces an error. See [infobase enumeration](INFOBASES.md).

## Connections

`Dial(ctx, Config)` opens and negotiates a native context. It does not log into
the infobase. `ValidateConfig` validates without opening any connection.

`Config.Worker` selects a known worker directly. Otherwise `Config.Server`
defaults to `127.0.0.1:1541` and the client obtains a worker port from the manager,
releases the manager context and closes that socket before opening the worker.
`Infobase` is required. Default `Profile` is `8.3.18.1208 / 1CV8C`.
`ServerName` controls the identity in 1C request headers and defaults to the
configured endpoint host; it does not change the TCP destination.

`TransportPolicy` on `Config`, `AdminConfig` and `InfobaseListConfig` selects
record processing separately from `Profile.Version`/`Version` and authentication.
The empty value or `TransportPlain` keeps existing behavior. Explicit
`TransportNative27N` requests n with minimum n and may accept c;
`TransportNative27C` requests and requires c. These are experimental exact-build
27 policy paths with offline synthetic coverage and no real build-27 server
acceptance. See [policy scope](COMPATIBILITY.md#experimental-native-27-policy).
Each connection owns fresh policy state; malformed/incomplete exchanges retire
that state, with no fallback or retry. No native client library is loaded.

The connection owns fresh outer security credentials. Application HTTP security
can require a second, independently owned context. Both use current-process
Windows credentials by default, including when the infobase uses password login.
`SecurityFactory: onec.NewAnonymousSecurity` explicitly selects the portable
anonymous provider, including on Linux. The library default is unchanged;
CLI platform defaults are separate. `SecurityFactory` is an extension point
for a compatible provider, not a switch
that bypasses the server's security negotiation. Each factory call must return
a newly owned context. `DialContext` permits a custom dialer.

`Config.Kerberos = &ticketauth.Options{File: path, SPN: exactSPN, KDC: optionalKDC}`
selects direct file-backed Kerberos instead. It requires a direct `Worker` and
`WindowsAuth` login, excludes `SecurityFactory`, and does not import credentials
into the OS cache. Validation performs no file I/O. See
[file-backed Kerberos](AUTHENTICATION.md#file-backed-kerberos) for format,
same-realm and live compatibility constraints.
Providers can optionally implement `StepContext` for cancellation and
`Mechanism() (string, error)` for `Stats.SecurityContexts` diagnostics.

`Config.NTLM` selects caller-owned `*ntlmauth.Credentials`, constructed with
`NewPassword(Identity, UTF8Bytes)` or `NewHash(Identity, SixteenBinaryBytes)`.
It excludes `Config.Kerberos` and `SecurityFactory`, requires `WindowsAuth` login,
and uses neither OS credentials nor a ticket cache. Contexts receive independent
response-key copies. Call `Client.Close` before `Credentials.Close`; the client
owns contexts, not the reusable credential owner. See
[explicit NTLMv2](AUTHENTICATION.md#explicit-ntlmv2) for input and validation
limits. NTLM completion is not mutual server authentication.

`Config.Timeout` defaults to 20 seconds per wire exchange. A method's context
can impose a shorter deadline on the whole operation. Cancellation interrupts
blocked socket I/O. An incomplete exchange makes the connection unusable: close
it and create another client. Calls on one client are serialized by a mutex;
this is not a pool of concurrent sessions.

If cancellation wins after one complete response frame has been consumed,
the operation still returns cancellation, but framing and any successfully
decoded transport policy remain synchronized for
cleanup. The client does not drain an incomplete response or replay an uncertain
request. A canceled operation may already have executed on the server.

## Prelogin and login

| Method | Result and constraints |
| --- | --- |
| `Users(ctx)` | Optional selection list, before a login attempt; does not enumerate all accounts |
| `AuthenticationSettings(ctx)` | Decoded settings response bytes, before login; may contain environment-specific data |
| `Login(ctx, Credentials)` | One explicit login attempt; success requires the observed application document/proof |
| `Stats()` | Cumulative counters and observed outcomes, without session tokens |
| `Close()` | Logout if a session was obtained, release if synchronized, then close security handles/socket |
| `CloseContext(ctx)` | Same cleanup with a caller-specified deadline |

`Credentials.Method` is required. Supported values are `WindowsAuth`,
`LegacyAuth`, `PasswordV1`, `PasswordV2`, `PasswordV3`. Windows mode rejects
explicit username/password fields. Other modes use `Username` and `Password`.
There is no automatic downgrade or alternate password retry. Server policy,
enabled account mechanisms, application profile and platform build determine
whether the chosen mode is accepted.

`Login` can replace a refused worker context once, only when its initial
credential-free Windows/legacy request receives the complete, recognized
`infobase_context_releasing` native exception. The rejected context must first
complete cleanup. The replacement uses the same resolved worker, profile,
identity and transport policy, with fresh security state and request IDs.
`Config.DisableContextRecovery` disables this behavior. Cancellation, incomplete
frames, cleanup failure, unknown exceptions, inner-security exchanges, SecPswd,
previous credential sends and application requests do not enter recovery.
No credential-bearing attempt or uncertain application operation is replayed.
Live acceptance is specific to the build and provider recorded in
[authentication acceptance](AUTH-ACCEPTANCE.md).

After a failed login, close the client unless explicitly using the bounded
[legacy retry API](LOGIN-BATCH.md#connection-reuse-boundary).
If a final reply supplied a valid session but its application document or proof
was rejected, that session is retained privately for cleanup. HTTP 200 alone is
not considered authentication success. If cancellation prevents the final login
response from being parsed, its session is not adopted: `LogoutConfirmed` stays
false even if native context release later succeeds. That release does not prove
the unadopted application session has been reclaimed.

Always check the error from cleanup. `Close()` is idempotent and uses a separate
ten-second context, so canceling a business operation does not automatically
cancel cleanup. If framing is no longer synchronized, logout/release are skipped
and reported as errors; local socket/security cleanup still runs. A failed
logout does not prevent a synchronized release attempt.

`Stats.Authenticated` means this client **ever completed** login; it remains
true after logout. `LogoutConfirmed`, `ContextReleased`, `SecurityClosed`, and
`Closed` record distinct outcomes. `SecurityClosed` is not inferred from logout
success. Counters include manager, retired worker and replacement traffic,
including failed replacement bootstrap. `ContextRecoveryAttempts` counts entry
into recovery; `ContextRecoveries` counts successfully reopened and queried
contexts, not authenticated logins. `RetiredContextReleased`,
`RetiredSecurityClosed` and `RetiredConnectionClosed` describe the rejected
context; the last flag requires all its cleanup to succeed. The ordinary cleanup
flags describe the current connection. Neither context release nor a locally
closed socket proves that the server session object has been removed.
A discovery failure returns an error from `Dial`.

## External processing

`SnapshotForm(ctx, form, FormSnapshotOptions{Language: "ru"})` retrieves an
initial read-only managed-form snapshot using validated response schemas. It returns ordered
controls, flat scalar attributes and explicit unsupported reasons; it excludes
private form/session identifiers and raw server HTML. The three metadata GETs
do not invoke a method or advance the POST synchronization counter. Form
creation itself can already have executed server creation handlers.

The snapshot is detached and does not synchronize later changes. Client BSL,
ordinary forms, tables and nested-object editing are not implemented.
The advertised build no longer selects this API's decoder. Live acceptance
remains bounded to 8.3.18.1208; see [compatibility](COMPATIBILITY.md) and the
[CLI workbench](EPF-WORKBENCH.md).

`InspectFormLifecycle(elementsJSON)` inspects an already available, strict JSON
elements object offline. It returns `FormLifecyclePlan` with event UUIDs,
candidate lifecycle names, source-ordered handler groups, `Before`/`After`/
`Override` phases and explicit inherited-chain links. It does not resolve module
availability or execute handlers. Input must omit the server `response` wrapper;
bare `undefined`, redacted IDs, missing phases, duplicate event IDs and ambiguous
overrides are rejected. Input is bounded to 512 KiB, 1024 events and 4096 groups
plus handlers. Empty events do not imply that a form may close unconditionally.

`FormSnapshot.Lifecycle` includes this advisory plan without additional GETs.
It is omitted with a warning for unsupported metadata, and omitted together
with the element tree when unapplied structural changes make that tree stale.
The three candidate event names are inferred from exact 18/27/85 shipped
callers; they do not enable later-build network support or general event dispatch.
Use `onec epf lifecycle --elements elements.json` for offline CLI inspection.
The [synthetic lifecycle example](examples/form-lifecycle/elements.json) is
available from the module directory as `docs/examples/form-lifecycle/elements.json`.

`PrepareFormContext(ctx, form, options)` opts into bounded flat String, Number,
Boolean and full Date state under the validated `scalar-tracked-v1` contract.
`CallWithContext(ctx, form, method, revision, changes, args...)` validates the
local revision and edits, invokes an exported server function, and returns a
`FormContextResult` containing current `State`, typed `Value`, returned
`Arguments`, `Submitted`, and `Recovered`. At most 32 scalar arguments are
accepted, matching the discovered method parameter count. Local validation
errors preserve usable state; recognized application errors trigger a separate
state synchronization, not a method retry. Unconfirmed or unsupported outcomes
retire the context. Always inspect the returned state even on error. See the
[interactive API, wire behavior and limits](EPF-INTERACTIVE.md).

`FormValueCodec` preserves primitive type tags and exact decimal text. Its
standalone codec also supports Undefined, Null and explicitly registered
reference types; those features do not imply context-edit or arbitrary-method
support. `FormCollectionCodec` decodes ordered row operations, sparse values and
totals; it is not a full collection synchronization engine or UI table editor.

`FormModuleImages(ctx, form)` reads schema-validated client module images through the
observed `getModule` metadata request. It does not execute the images or
provide a client BSL interpreter.

`BindDynamicList(ctx, form, tableName)` binds a supported flat list on a freshly
opened form with supported metadata. `ReadDynamicListWindow(ctx, list, options)` reads a forward
window with an optional owned `After` bookmark or structured field `Search`.
The live-verified row decoder supports the observed unsigned integer Number
and `[S,6,1]` String layout. Other compact layouts fail explicitly without
partial rows. `InProgress` is distinct from a successful empty result; no
automatic polling or retry occurs. Later structural changes require opening
a fresh form. This is not a general table editor or list synchronization engine.

```go
processing, err := client.UploadProcessing(ctx, epfBytes, "control.epf")
if err != nil { return err }
form, err := client.OpenForm(ctx, processing)
if err != nil { return err }
defer func() {
    cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    // In production, join this error into the enclosing function's return.
    _ = client.CloseForm(cleanup, form)
}()
result, err := client.CallNoContext(ctx, form, "ProtocolControl")
if err != nil { return err }
```

`ExecuteProcessing(ctx, epf, filename, method, args...)` combines these three
operations. It leaves the form and session open until session cleanup; it does
not expose the form handle. Prefer the explicit methods and `CloseForm` for
repeated operations in a long-lived session. The caller always owns session cleanup.
The returned `Processing` and `Form` handles are opaque and tied to their owning
client. They cannot be supplied to another client or restored from a JSON log.

`UploadProcessing` accepts 1..393216 bytes (384 KiB) and a simple ASCII `.epf`
filename. Its multipart request carries the session in the URL. The upload
response decoder selects URI-encoded or raw backspace tuples from their actual
delimiter. Mixed/invalid encodings fail independently of the advertised build.

`AttachProcessing(ctx, epf, filename)` is an explicit alternative using
`POST /e1cib/extmd/processing`, with a single multipart `file` part and the
session header. It requires 201 and exactly one relative `Location` describing
the attached component and its version. The location is parsed, never followed
as a redirect. There is no exact-build gate; live attachment proof remains on 8.3.18.1208.
There is no fallback to `openDocument`.
The same byte/filename bounds apply. Both methods accept `[]byte`; callers do
not need a local EPF file or a server filesystem path. Internal server storage
is outside this promise. Attachment does not invoke an arbitrary object export.

`OpenForm` opens `<processing reference>.form` with the observed empty parameter
and geometry envelope. It does not implement a visual form runtime. Field order
in form JSON is deliberately preserved; the lab rejected alphabetically sorted
fields with HTTP 400.
The query reply accepts only the narrow bare-`undefined` metadata
dialect already observed in snapshots. Normalization is counted in snapshot
warnings; quoted strings remain unchanged and arbitrary JavaScript is rejected.
Other responses, including authentication, retain strict JSON parsing.

`OpenFormWithOptions(ctx, processing, FormOptions)` selects a local form name
through `Name` and accepts up to 32 ordered `Parameters` (`FormParameter{Name,
Value}`). Empty `Name` means the default form. Names are bounded Unicode
identifiers, with case-insensitive duplicate parameter rejection. String and
BinaryData values use the same codecs as function arguments. The live fixture
accepted an opening parameter; no application-level consumption assertion was
made for that parameter. Client-side open handlers are not executed by Go.

`FormMethods(ctx, form)` returns module, method name, context (`server` or
`no-context`), kind (`procedure` or `function`), export flag and sparse
positional parameter metadata. The separate-table schema uses
`dataDescrWMethods` with the session's real assembly/role selectors; the embedded
schema uses `moduleIds[].methods` from the form query. Selection follows the
response schema. The embedded schema has source/synthetic evidence from build
27; live form acceptance remains on build 18.
`Parameters` is not an arity list: missing positions and absent `Direction`
mean the response did not supply that information. Parameter names, complete
types and defaults are not reconstructed. Context functions use the separate
`PrepareFormContext`/`CallWithContext` flow described above. Object exports and client methods
are not this catalogue, and enumeration does not establish authorization.

`CloseForm(ctx, form)` sends `processFormsClose` with the instance `fid`, not
the form definition `id`. Copies of a handle share release state. Once an
exchange is attempted, reuse is forbidden even if its acknowledgement fails.
Repeated closes return the first result without issuing another release.
Successful release means the route acknowledged it; it does not execute
client-side close handlers or establish component unloading/secure deletion.
Use a separate cleanup context when the business-operation context expired.

`CallNoContext` supports at most 32 arguments:

- `StringValue(string)`: up to 65536 Unicode code points, valid UTF-8.
- `BinaryValue([]byte)`: up to 65536 bytes, copied at construction and represented
  as Base64 in JSON.
- Number, Boolean, Date and Null use the bounded scalar codec.

No variadic arguments omits parameter fields; an explicit empty `[]Value{}...`
sends empty parameter arrays, matching the reference behavior. The total request
must also fit the HTTP bound. Method names are nonempty bounded text; the server
decides which server no-context functions exist and can be called. This method
does not require an `Export` metadata flag: a non-exported server form function
was successfully called in the controlled build-18 fixture. Export is not an
authorization boundary for server form methods. `CallWithContext` retains its
own narrower exported-function selection policy; that is a library constraint.

`Value` exposes the returned type UUID and JSON value. String returns are
validated as strings. Number, Boolean, Date and Null returns use the scalar
decoder. Binary returns retain their JSON Base64 representation; other return
types remain raw JSON values, not a general 1C object model. In particular, an
empty object payload tagged as Array is not proof of a general collection
return implementation.

The synchronous application counter starts at one for form requests and advances
once per logical operation. Security continuation legs reuse the same HTTP
request. Logout advances beyond the last application request, with a minimum
sequence of two.

## Low-level packages

`wire` exposes the observed framing tokens, UUID conversion, text and binary
ListStream subset, bootstrap/selection/query/release encoders and reply parsers,
and native-file HTTP framing. Binary decoding supports the observed Latin-1
and UTF-16LE string tags (23/24/25), with surrogate and size validation; the
generic binary packer still emits Latin-1 strings only. Unobserved tags return
errors. Embedded HTTP is bounded to 512 KiB, uses exact `Content-Length`, and
rejects transfer encoding.

`secpswd.NewClient(version, options)` creates a single-use credential exchange:
`Start(user, password)` returns C1; `Receive(serverCredential)` produces the next
credential or final result. Always call `Close`. `PasswordHash` and `PasswordKey`
expose the recovered derivations. Version numbers 1/2/3 correspond to native
selectors 0/1/2. Default randomness is `crypto/rand`; deterministic `Options`
belong to tests. The default exchange lifetime is 18 seconds.

V1 final success verifies the encrypted server marker; V2/V3 require the exact
`suc` result. Challenge/proof validation is performed before acceptance. Mutable
key buffers are cleared when completed, failed or closed. Go strings and copies
may remain in memory; this is not a guarantee of complete secret erasure.

## Error and output handling

Protocol errors avoid echoing response bodies, credentials or session values.
`StatusError` exposes the operation and HTTP status for `errors.As`. Credential,
client and remote-handle formatting is redacted, including `%#v`. Raw `wire`
messages and direct return values of credential builders are sensitive buffers;
do not log them. The library itself does not persist traffic or sessions.

The CLI writes reports to stdout (readable or JSON; see [output](INTERFACE.md#output)),
diagnostics to stderr and exits nonzero on an
operation, expectation or cleanup failure. The `users` command intentionally
prints selected names; `epf run` intentionally prints the method result. Handle
those outputs according to the data in the target infobase.

CLI examples are maintained in [external processing](EXTERNAL-PROCESSING.md).

## Evidence scope

See [compatibility](COMPATIBILITY.md) for the supported interfaces and the
distinction between synthetic validation and live server acceptance. Automated
tests focus on checklist orchestration, SOCKS5, anonymous transport and CLI
behavior; manual EPF examples have separate requirements.
