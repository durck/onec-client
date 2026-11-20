# Controlled interactive form fixture

`NativeInteractiveProbe.epf` is the compiled 8.3.18.1208 fixture for bounded
form-context calls. The adjacent XML/BSL files are its Designer source.

All three root data fields are Strings:

- `InputText`: editable, at most 100 UTF-16 code units.
- `ResultText`: read-only, initially `READY`.
- `CounterText`: read-only, initially `0`.

`ProcessText()` runs on the server with form context, sets
`ResultText = "server:" + InputText`, increments the String counter and returns
the result. `FailAfterChange()` sets `CHANGED_BEFORE_ERROR` and raises
`CONTROLLED_FORM_ERROR_20261020`. `ProtocolControl()` is a separate no-context
constant check.

The fixture does not read/write files, modify database data, change accounts,
or start background work. It is not a file-access or general code-execution
helper. Its client button is deliberately inactive in the Go UI; only the
workbench function panel is exercised.

See [the interactive guide](../../../docs/EPF-INTERACTIVE.md) for launch and
protocol limits. Manual validation requires a separately configured test server
and explicit authorization; the ordinary Go tests do not use this fixture.

To rebuild after editing the XML/BSL, use the installed Designer's
`/LoadExternalDataProcessorOrReportFromFiles` command with
`NativeInteractiveProbe.xml` as input and `NativeInteractiveProbe.epf` as output.
Designer is a fixture build tool, not a dependency of the Go runtime.
