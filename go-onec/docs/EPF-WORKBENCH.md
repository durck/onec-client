# EPF workbench

`onec epf ui` displays a managed form in a local browser through the native TCP
client. The default mode shows initial controls/scalar values and exported
server no-context functions. `--allow-edit` enables the supported scalar edits
and context calls. Live acceptance is bounded to **8.3.18.1208**; see
[compatibility](COMPATIBILITY.md) and [interactive state handling](EPF-INTERACTIVE.md).

## Start and stop

From `go-onec` after building the CLI:

```powershell
./bin/onec.exe epf ui --worker 127.0.0.1:1560 --database demo --file testdata/epf/graphical/NativeGraphicalProbe.epf --session-timeout 20m --execute
```

Without `--execute`, the command only previews. Execution logs in, uploads the
EPF, opens the form and prints a loopback URL. Open it in a browser. Shared
[EPF options](EXTERNAL-PROCESSING.md) select the upload route, form and String
opening parameters; shared [authentication options](AUTHENTICATION.md) select
credentials. The workbench does not support `--confirm-open`.

Use **Завершить сеанс**, Ctrl+C or the lifetime limit to finish; closing a browser
tab does not log out. Lifetime defaults to 20 minutes, with an 8-hour maximum.
The CLI drains calls, closes the form/session and reports each cleanup outcome.
`lifecycle_success` covers setup/cleanup, while `ui.calls_confirmed` covers calls.
A failed or unconfirmed call makes overall `success` false even if cleanup succeeds.

## Use the form

- **Form** shows supported fields. In edit mode, changed values are sent with
  the next context call; the pending-edit indicator counts them.
- **Server functions** accepts up to 32 ordered String, Number, Boolean or Date
  arguments. Numbers remain decimal text; dates use `YYYY-MM-DDTHH:mm:ss`.
- **JSON** accepts explicit argument arrays. Switching back preserves supported
  values. Invalid JSON or unsupported shapes stay in the editor without submission.
- Confirmed calls, validation errors, recovered application errors and uncertain
  outcomes have distinct labels. Uncertain outcomes disable further calls;
  no automatic retry occurs.

| Supported | Outside the workbench subset |
| --- | --- |
| Ordered groups, labels, scalar fields and inactive buttons | Original button commands, client BSL, ordinary forms and exact 1C layout |
| Initial flat String/Number/Boolean/Date values | Tables and nested-object editing |
| Exported no-context server functions | Arbitrary object exports |
| `--allow-edit`: flat scalar edits, exported context functions, supported deltas | References, mixed types, unknown structural changes |
| Existing-element titles, visibility and editability | Complete presentation/event runtime |

Calling a function is not equivalent to pressing an original form button, which
may run client validation, several calls or other handlers. Default snapshots
remain initial; interactive calls return current supported state. State recovery
after an exception does not undo server side effects or make the call successful.

## Local session boundary

The UI binds IPv4 loopback with a random URL capability. Treat that URL as access
to the running session; another local process with it can act as the local user.
Host/origin checks, POST-only mutations, a request marker and restrictive CSP
protect the embedded UI. It is not a remotely shareable service.

Server HTML and client module images are not executed; labels/results use text
nodes. Calls are bounded and concurrent submissions are rejected. Results are
application data displayed locally; final CLI reports record counters rather
than result contents. Oversized successful results are distinguished from
unconfirmed execution.

Loading an EPF can execute server creation handlers; calling a function uses the
authenticated user's permissions. Read-only display is not an execution sandbox.

## Compatibility

The included `testdata/epf/graphical/NativeGraphicalProbe.epf` example has live
acceptance on **8.3.18.1208** using current-session Windows authentication. Those
checks establish no additional acceptance for explicit NTLM, ticket files or
other password modes. Supported controls and limitations are listed above.

The workbench is part of `onec`; it needs a browser, without Node.js or Playwright.
See [compatibility](COMPATIBILITY.md) for server and transport boundaries.
