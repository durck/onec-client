# Interactive EPF forms: bounded Go implementation

The Go client can edit supported String, Number, Boolean and full Date attributes,
call exported `&AtServer` functions with form context and scalar arguments,
and apply returned values and supported presentation changes. Protocol support
is selected by validated metadata, independently of the advertised build. The
live baseline uses **8.3.18.1208** and the controlled
`testdata/epf/interactive/NativeInteractiveProbe.epf` fixture. It does not
implement the complete managed-form runtime. The expanded typed/presentation
fixture is `testdata/epf/research/NativeResearchProbe.epf`.

## Run

From the module directory:

```powershell
.\bin\onec.exe epf ui --allow-edit --worker 127.0.0.1:1560 --database demo --auth windows --file testdata/epf/interactive/NativeInteractiveProbe.epf --session-timeout 20m --execute
```

Open the loopback URL printed on stderr. Edit **Text**, select **ProcessText**,
and click **Выполнить один раз**. The returned value and **Server result** become
`server:<text>`; **Completed calls** increments. The original form button stays
disabled: the workbench's separate function panel performs the call.

**FailAfterChange** deliberately changes `ResultText` and raises an application
exception. The client retrieves the authoritative state before allowing another
call. The error is reported even if state recovery succeeds. A subsequent
**ProcessText** call can then continue from that recovered state.

Without `--allow-edit`, the read-only snapshot and no-context function
panel remain the default. Without `--execute`, both modes only print a plan.
Use **Завершить сеанс**, Ctrl+C, or the duration limit to release the form and
log out; closing the browser tab alone does not release the session.

## Library

```go
state, err := client.PrepareFormContext(ctx, form, onec.FormSnapshotOptions{
    Language: "ru",
})
if err != nil { return err }
result, callErr := client.CallWithContext(ctx, form, "ProcessText",
    state.Revision, []onec.FormParameter{
        {Name: "InputText", Value: onec.StringValue("hello")},
    })
// Inspect result.State even when callErr is non-nil.
// Recovered means the state was recovered, not that the function succeeded.
if callErr != nil { return callErr }
fmt.Println(result.Value.Value)
```

`FormContextState` contains a detached snapshot, editable field names, a local
revision, and `Usable`. The private implementation retains the remote form key,
metadata, parameter state, synchronization counters, and `dd` state. Those
private values are not exposed to the browser.

Supply the current revision on every call. A stale revision, unknown or
read-only field, duplicate field, wrong value type, excessive declared String
length, out-of-range Number, unsupported method or incorrect argument count is
rejected before sending. String length checks use UTF-16 code units as the inspected client
does. Go rejects overflow; the inspected client setter can truncate it. This
is a deliberate boundary, not complete setter/validation parity. Form opening
parameters and function arguments are separate concepts. Up to 32 scalar
arguments are accepted, matching the metadata's parameter count.

The research fixture's `ApplyValues` takes a Number multiplier and String suffix:

```go
multiplier, err := onec.NumberValue("2")
if err != nil { return err }
result, err := client.CallWithContext(ctx, form, "ApplyValues",
    state.Revision, changes, multiplier, onec.StringValue("-ok"))
// result.Arguments exposes returned parameter values without mutating inputs.
```

In the workbench, enter `[{"type":"number","value":"2"}, "-ok"]`.
Other explicit types are `boolean` with a JSON Boolean and `date` with a
full civil-date string such as `2026-10-20T12:34:56`. Number text avoids
binary-float coercion; malformed Unicode is rejected before submission.

The local revision is not a wire synchronization counter. Successful calls and
successful error-state recovery advance it. Validation failures leave it
unchanged. The browser preserves unsent edits when validation fails at the
same revision; a stale-revision response replaces them with authoritative state.

`Submitted` means the exchange was attempted. It does not establish execution.
`Recovered` means a confirmed application exception was followed by successful
state synchronization. A transport failure, malformed response or unsupported
state change retires the context: `Usable=false`. Open a new form to proceed;
the client never automatically repeats an uncertain function call.

## Observed wire sequence

1. Open the form using the existing EPF lifecycle. Retain its `queryForm` state.
2. Read `elements`, `dataDescrWMethods`, and `layouter`. Decode the bounded
   descriptor and retain untouched nested objects.
3. Validate edits and construct `pchs`. For a changed flat root, the inspected
   client sends all simple fields, including unchanged output/counter values.
   Field indexes are descriptor positions, not arbitrary metadata IDs.
4. POST `call` with the form identity, remote key, method descriptor, tracked
   proposal, parameter object, and dynamic-data object. This remains HTTP
   encapsulated in the existing native TCP transport.
5. Validate the response identity, method, proposal acknowledgements, supported
   field deltas, and dynamic state. Apply the values to a new detached snapshot.
6. For a recognized application exception, POST `synchException` using
   `{"root":{"key":remoteKey}}` and the next session synchronization value.
   Validate and adopt the recovered state. Do not repeat the failed method.
7. Explicitly close the form and authenticated session.

The wire JSON is ordered. Although JSON objects are conceptually unordered,
the observed platform's JSON-to-XML reader consumes relevant metadata in
serialization order. The implementation therefore uses explicit ordering:

- Proposal counters `sinDesc`, `sin`, `seq` precede `structure`.
- Parameter descriptors place `name` before nested `field`.
- String qualifiers such as `length` precede `__content`.

The native reader is sensitive to this ordering. A generic sorted-map JSON
encoder can produce an HTTP 400 XML conversion error for these structures.

Editing a String does not itself increment the tracked-object counters.
The implementation checks the server acknowledgement rather than inventing
counter increments. `dd` is replaced by returned authoritative state.
An application exception is not an automatic rollback: the fixture's
`CHANGED_BEFORE_ERROR` value remains visible after recovery.

Recovery can reorder the list of named structures: the fixture returned
`[root, root.Object]` where its original description used
`[root.Object, root]`. Comparison therefore matches unique structure names,
then requires identical structure bodies, including ordered field arrays,
identifiers and type qualifiers. Field ordering is never normalized because
the proposal refers to field positions.

## Supported boundary

| Area | Current support |
| --- | --- |
| Protocol | Validated `scalar-tracked-v1` metadata/state contract, independent of the advertised build |
| Root values | Flat monotype String, Number, Boolean and full Date attributes |
| Editing | Visible, enabled, writable supported scalar fields explicitly listed by the API |
| Method | Metadata-approved exported server function with matching scalar arguments |
| Results | Typed scalar return, returned arguments and supported flat field changes |
| Error recovery | Recognized application exception plus `synchException` |
| Other objects | Retained unchanged; nested edits are unsupported |
| Client behavior | No client BSL, commands, client validation, or event dispatch |
| Presentation changes | Supported existing-element title/visibility/enabled/read-only changes; structural or unknown changes retire context |
| Other data | No table/row editing, references, mixed types or restricted date qualifiers |
| Other builds | Eight-client source comparison and cross-version synthetic checks; additional live-server acceptance remains unconfirmed |

Read-only `SnapshotForm` still represents the initial form state; callers who
want current values must use the context result's snapshot. Server code may
have external side effects before throwing an exception. State recovery only
synchronizes the form; it cannot undo those effects.

## Evidence

The examples only change in-memory form values. Their XML/BSL source accompanies
each EPF. Live acceptance is bounded to **8.3.18.1208** with current-session
Windows authentication; it does not establish additional acceptance for explicit
NTLM, ticket files or other password protocols. See [compatibility](COMPATIBILITY.md).
