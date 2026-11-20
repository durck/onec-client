# External processing

The client uploads an EPF, opens a managed form and invokes supported server
form functions in an authenticated native TCP session. Live acceptance is
bounded to **8.3.18.1208** and controlled fixtures; see
[compatibility](COMPATIBILITY.md). No web publication is required.

The 12 November 2026 build-18 check fixed HTTP file continuation encoding:
multi-chunk requests now omit separators inside the native file stream. The
reviewed 16,879-byte ServerFiles processing passed upload, named-form opening,
its `ExecuteJSON` control call, form close and confirmed session/context cleanup.
The existing 384 KiB EPF and 512 KiB embedded HTTP limits are unchanged.

## Discover and call functions

From `go-onec`, use a reviewed EPF and its actual form/function names:

```powershell
# Preview method discovery, then add --execute to perform it.
./bin/onec.exe epf methods --worker 127.0.0.1:1560 --database demo --file testdata/epf/forms/NativeFormProbe.epf --form SecondaryForm

# Call the fixture's no-context Echo function and check its result.
./bin/onec.exe epf run --worker 127.0.0.1:1560 --database demo --file testdata/epf/forms/NativeFormProbe.epf --form SecondaryForm --method Echo --arg hello --expect echo:hello --execute
```

Commands share the [native authentication options](AUTHENTICATION.md).
`epf methods` creates a form and can run its server creation handlers, even
though it does not invoke the listed functions. Calls execute with the
authenticated user's permissions. Upload and form creation are not a sandbox.

| Option | Meaning |
| --- | --- |
| `--file` | Compiled `.epf`, 1..393216 bytes (384 KiB); simple ASCII filename |
| `--form` | Local form name; omitted means default form |
| `--upload-mode open-document` | Default upload route |
| `--upload-mode extmd` | Explicit attachment route; no fallback to another route |
| `--param Name=value` | Repeatable String opening parameters |
| `--method` | Server no-context form function for `epf run` |
| `--arg value` | Repeatable String arguments |
| `--args-json` | String or typed Number/Boolean/Date arguments; excludes `--arg` |
| `--expect` | Expected String result; mismatch fails the command |

Example typed argument array: `[{"type":"number","value":"2"},"suffix"]`.
Number values retain decimal text. Each function must accept the supplied types;
sparse discovered parameter metadata is not a complete signature. The library
additionally supports the bounded BinaryData no-context path; see
[API types and lifecycle](API.md#external-processing).

## Opening confirmation and cleanup

On an opening warning, `epf methods`, `epf modules` and `epf run` return
`ProcessingSecurityError`. Add `--confirm-open` only to approve that reviewed
file: it permits one confirmation and repeat upload of the same bytes.
The platform retained the observed decision after logout; its full lifetime
and scope are unknown. The wizard and `epf ui` do not provide this approval.
See [acceptance evidence](AUTH-ACCEPTANCE.md).

Each CLI form operation closes its form before logging out and releasing the
native context. Check the final report and exit status: successful execution,
form closure, logout and local cleanup are separate outcomes. An uncertain call
is never automatically replayed. Form release does not run client close handlers
or prove component unloading or secure deletion.

Both upload routes send bytes and a simple filename, without requiring a
caller-selected server filesystem path. This does not promise memory-only
storage: inspected build-18 `extmd` code materializes an internal temporary file
on a fresh attachment/cache miss, including inputs below its 1 MiB buffer size.
The 384 KiB limit is a Go client bound, not a platform maximum.

## Workbench and offline inspection

- [Workbench](EPF-WORKBENCH.md): initial controls and scalar values, with a
  separate function panel. `--allow-edit` enables the supported context calls
  and scalar edits described in [interactive forms](EPF-INTERACTIVE.md).
- `epf modules`: retrieves compiled client images without executing them.
- `epf lifecycle --elements elements.json`: inspects saved form events offline.
  From the module directory, use `--elements docs/examples/form-lifecycle/elements.json`
  to inspect the included [synthetic example](examples/form-lifecycle/elements.json).

## Scope

| Supported surface | Boundary |
| --- | --- |
| Default/named managed forms and supported opening parameters | Server creation handlers may run; client open/close events do not |
| No-context server form functions | Object-module exports and form buttons are different entry points; `Export` is not a server authorization boundary |
| Exported context functions and scalar edits | Validated `scalar-tracked-v1` state only; uncertain/unsupported changes retire context |
| Initial form snapshots and module images | No client BSL execution, ordinary forms, UI table editing or exact 1C layout |
| Compiled EPF input | No EPF compiler/editor, generic BSL/query executor or arbitrary object dispatcher |
| Controlled synchronous EPF calls | No validated ERF/report generation, background jobs, scheduled jobs or BSP registration |

An EPF may depend on its configuration's metadata/common modules and need its
original client workflow. A successful function call does not establish that an
arbitrary EPF works headlessly. Temporary-storage addresses, component names,
form definitions and form instances are separate identities; they are not
interchangeable filenames or durable handles.

## Compatibility

Live native acceptance is bounded to **8.3.18.1208** and the documented control
files. Opening confirmation, workbench behavior and interactive form calls have
separate limits; see [known-account checks](AUTH-ACCEPTANCE.md),
[workbench compatibility](EPF-WORKBENCH.md#compatibility) and
[interactive forms](EPF-INTERACTIVE.md#evidence). Successful control examples do
not establish compatibility with arbitrary EPFs or newer server builds.
