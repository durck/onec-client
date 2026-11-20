# EPF examples

These reviewed EPFs and their XML/BSL source support the documented manual flows:

| Directory | Purpose |
| --- | --- |
| `epf/forms/` | Pinned `NativeFormProbe.epf` for optional `auth-check --control-epf` and function-call examples |
| `epf/graphical/` | Workbench display example |
| `epf/interactive/` | Scalar edits and context calls |
| `epf/research/` | Typed arguments and supported presentation changes |

The automated Go tests do not require these files. They are included so manual
examples can be reproduced with an explicitly selected test server. Opening an
EPF may execute its creation handlers; review its source before confirming it.

`auth-check` accepts only the pinned control EPF hash. `.gitattributes` preserves
these files' exact bytes; updating that control file requires updating its
validation deliberately. See [known-account checks](../docs/AUTH-ACCEPTANCE.md),
[workbench](../docs/EPF-WORKBENCH.md) and [interactive forms](../docs/EPF-INTERACTIVE.md).
