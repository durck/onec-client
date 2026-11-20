# Bounded infobase login checks

`onec login-batch` checks supplied infobase credentials against one configured
target. By default each combination gets a fresh client, one `Login` call and
independent cleanup. Optional workers and conditional connection reuse are
described below. It performs no EPF or application-data operations and never changes
accounts or passwords. Login itself can run platform/application session setup.

The command supports three explicit mappings:

| Mode | Mapping | Planned attempts |
| --- | --- | --- |
| `shared` | One supplied password for every user | U |
| `paired` | User line N with password line N | U, with equal file lengths |
| `matrix` | Every password for every user | U × P |

Matrix dispatch order is user 1/passwords 1..P, then user 2/passwords 1..P, and so on.
It continues after an accepted login, so all supplied combinations are checked
unless interrupted by an operational failure. Password records are not silently
deduplicated. User duplicates differing only in uppercase conversion are rejected.
Parallel completion order can differ from dispatch order; the stable `attempt`
number identifies the original combination. No combination is automatically
replayed, and there are no authentication fallbacks.

## Commands

Run from the Go project directory. The example paths are placeholders for
local files, not bundled credentials.

One shared password, with a hidden prompt only when `--apply` is added:

```powershell
.\bin\onec.exe login-batch --mode shared --users-file test-results/users.txt --auth legacy --worker 127.0.0.1:1560 --base test
```

Paired files:

```powershell
.\bin\onec.exe login-batch --mode paired --users-file test-results/users.txt --passwords-file test-results/passwords.txt --auth legacy --worker 127.0.0.1:1560 --base test
```

Every combination:

```powershell
.\bin\onec.exe login-batch --mode matrix --users-file test-results/users.txt --passwords-file test-results/passwords.txt --auth legacy --worker 127.0.0.1:1560 --base test
```

All examples preview counts without connecting or creating a report. File-based
preview **does read and validate the supplied files**, including password records.
It prints no password contents. Shared prompt/stdin input is not read in preview.

To execute a reviewed plan, add `--apply`. Add
`--report-file test-results/result-new.jsonl` to save the report to a new file instead
of stdout. An existing report is never overwritten. Use `--format csv` for CSV.
Shared mode also accepts a one-record `--passwords-file` or `--password-stdin`;
the latter is mutually exclusive with the file. No password-value command-line
flag or environment variable is provided.

Add `--workers 4` to allow at most four independent connections. Add
`--connection-mode reuse-refused` with `--auth legacy` to retain each worker's
connection after an eligible refusal:

```powershell
.\bin\onec.exe login-batch --mode paired --users-file test-results/users.txt --passwords-file test-results/passwords.txt --auth legacy --worker 127.0.0.1:1560 --base test --workers 4 --connection-mode reuse-refused --interval 1s
```

This also previews by default. To keep a single connection between eligible
refusals, use `--workers 1 --connection-mode reuse-refused`. A single connection
never carries concurrent attempts; workers own separate connections.

## Connection reuse boundary

`--connection-mode fresh` is the default. `reuse-refused` is explicitly limited
to legacy authentication. It retains TCP, the native context, RPC counters and
existing security contexts only after a complete final HTTP 401/402 refusal,
with no `vrs-session` or `Connection` header, completed HTTP security framing,
no established application session and a synchronized transport.

Each subsequent attempt still performs the legacy preliminary request and
credential request, with newly constructed credentials. Bootstrap and existing
transport negotiation are skipped. No password/challenge/proof is replayed
from a previous attempt.

An accepted login always receives logout and full connection cleanup; the next
combination starts with a new connection. A refusal in an ineligible state also
retires that connection. Operational/protocol/policy failures stop the batch.
If a server closes an apparently reusable connection, the next attempt reports
the failure and stops; it is not silently replayed on another connection.

Reuse with `v1/v2/v3` is rejected before input files are read. Those protocols
have multi-stage credential state and routing sessions whose same-connection
failure lifecycle is not yet proven. They support workers in `fresh` mode.
Switching methods on a retained connection is excluded.

Library callers can explicitly use `Client.CanRetryLogin()` and
`Client.RetryLogin(ctx, credentials)`. Ordinary `Login` permits only one
credential-bearing attempt. Its initial credential-free request may perform
one [context recovery](API.md#prelogin-and-login) before any credentials have
been sent. A retained connection that previously sent credentials is ineligible;
no batch combination is automatically repeated on another connection.

Live 8.3.18.1208 acceptance confirmed legacy refusal-to-success on one connection
and cleanup. Later parallel runs also exposed intermittent precredential
context-release errors; see [acceptance results](AUTH-ACCEPTANCE.md).
Same-connection method switching is excluded, and live 8.3.27/8.5 reuse remains
unproven.

`--auth` is mandatory: `legacy`, `v1`, `v2` or `v3`. This selects the infobase
credential protocol, not a Windows account. The outer/inner security exchanges use the selected transport: current-process
Windows SSPI on Windows by default, anonymous on Linux by default.
`--transport anonymous` selects the portable null-session exchange explicitly. Windows mode,
explicit NTLM, ticket files and the single-user `--user` flag are excluded from
this command. A list of names cannot switch the identity of the OS session.

## Input and execution bounds

- UTF-8, with an optional leading UTF-8 BOM; LF and CRLF are accepted.
  UTF-16 exports must be converted explicitly.
- One record per physical line. A final newline does not add a record.
  Blank user lines are errors. A blank password line is an explicit empty
  password; an empty file has no records and is rejected.
- Password case and surrounding spaces are preserved. User names are also
  preserved without trimming. NUL, backspace and embedded CR/LF are rejected;
  user control characters are rejected.
- At most 16 MiB and 10,000 records per file, 4096 bytes per password and
  256 Unicode code points per user.
- `--max-attempts` defaults to 1000; its hard ceiling is 100000. A larger
  Cartesian product fails before any network request.
- `--workers` defaults to 1 and accepts 1..16. The worker pool and completion
  channel are bounded; the Cartesian product is not materialized as a job queue.
- `--interval` defaults to one second and accepts 0..1h. With one worker it is
  a pause after each completed attempt. With multiple workers it is one shared
  minimum spacing between dispatches, not a separate allowance per worker.
  There are no catch-up bursts or adaptive retry/backoff.
- `--timeout` bounds each dial/login attempt, default 45 seconds. Cleanup has
  its own independent ten-second timeout.
- Ctrl+C stops dispatch, cancels active operations and closes all retained
  connections. The command waits for worker cleanup before returning.
  Already-started attempts can finish after cancellation; sent requests cannot
  be withdrawn. There is no automatic resume.

No account-lockout policy is inferred from these settings. The user is
responsible for choosing the supplied credentials and target scope.

## Reports and outcomes

JSONL contains a `plan`, individual `attempt` records, optional `connection`
cleanup records, then a `summary`.
Each attempt includes username, one-based user/password line numbers, status,
HTTP status when available, login confirmation and separate cleanup flags.
Additional fields are `worker`, `connection_id`, `connection_reused` and
`connection_retained`. Connection IDs equal the first dispatched attempt
number for that connection; they may have gaps. A retained attempt correctly
has false cleanup flags because the connection remains open at that moment.
Match its connection ID to a later attempt that closed it, or to the terminal
`connection` record emitted when an idle retained connection is closed.
Connection records have attempt/line numbers zero and an empty username;
they do not represent additional login attempts.
For a hidden/stdin shared password, password line 1 denotes the sole supplied
record rather than a physical file line.

CSV contains a header and the same attempt/connection rows, distinguished by
the appended `event` column; its JSON summary goes to stderr.
CSV usernames starting with a formula marker after spaces are prefixed with
an apostrophe. JSONL preserves exact names. Reports never contain password
fields, credential hashes, authentication tokens or raw server error bodies.
They do contain user names and should be handled as account inventory.

| Status | Meaning and continuation |
| --- | --- |
| `accepted` | Library confirmed application login; cleanup also succeeded |
| `not_accepted` | The final login or secure-login stage returned HTTP 401/402; continue with the next combination |
| `policy_or_limit` | HTTP 403/423/429; stop the entire batch |
| `connection_failed` | Dial/bootstrap did not complete; stop, without claiming a credential rejection |
| `timeout`, `cancelled`, `network_error` | Operational failure; stop |
| `unexpected_http_status`, `protocol_or_io_error`, `unconfirmed_login` | Result could not be established; stop |
| `cleanup_failed` | Cleanup was incomplete; stop even if login was confirmed |
| `closed` | Terminal connection cleanup record, not a login outcome |

`not_accepted` does **not** prove that a password was wrong: the response can
also reflect account state, allowed mechanisms or policy. Only a confirmed
application login establishes acceptance. SecPswd parsing/decryption/proof
errors are deliberately not converted into password failures; they stop the
batch. HTTP 200 alone is not success.

If the transport fails during `Dial`, its internal cleanup runs, but the library
does not return a client with observable cleanup statistics. The corresponding
false flags mean unconfirmed, not proof that cleanup was skipped.

Exit 0 means all planned attempts were recorded and the run completed, even
when some credentials were not accepted. Operational, input, report or cleanup
failure returns nonzero. Inspect `started`, `recorded`, `accepted`,
`not_accepted`, `errors`, `connections_opened`, `connections_closed`,
`cleanup_errors`, `completed` and `stopped_reason` in the summary.
Opened connections count successful `Dial` returns, not unobserved sockets
inside failed bootstrap. Outcome/cleanup counters include completed work even
if report writing has failed; `recorded` counts successfully written attempts.
A failure stops new dispatch before cleanup of the failing connection.
Other already-active workers are cancelled and joined; their final records
can follow the initial failure. All report writes run in the coordinator.
After a report write fails, no further attempt/connection writes are made.
Already recorded lines remain
available after interruption; a disk write failure can prevent a final summary.

Secrets exist in process memory while required. Byte buffers are cleared where
possible, but Go strings cannot provide guaranteed memory erasure. The command
does not create password copies on disk.

## Compatibility

Live legacy acceptance is bounded to **8.3.18.1208**, including two simultaneous
successful logins and refusal-to-success on one connection. Precredential context
failures can stop a batch without establishing a password rejection. Successful
bounded runs do not guarantee availability under repeated connections.

Native SecPswd login retains the limits in [compatibility](COMPATIBILITY.md).
A first-step HTTP 402 is not evidence about a supplied SecPswd password. Inspect
each attempt's phase, outcome and cleanup rather than treating every failure as
an incorrect password.
