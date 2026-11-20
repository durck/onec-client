# Console workflow

Run examples from `go-onec` after the [build step](../../README.md#quick-start).
For the command list, see the [command guide](../README.md).

## Help and wizard

```powershell
./bin/onec.exe --help
./bin/onec.exe help login
./bin/onec.exe --verbose help login
./bin/onec.exe wizard
```

Help groups options by purpose; `--verbose` includes credential-provider and
advanced options. The English wizard starts with the audit checklist and also offers login,
user/database lists, port checks, EPF calls, clusters and web inventory:

1. Choose an action and enter its parameters.
2. Review the reusable command and offline preview.
3. Choose **1** to execute once, **2** to start again, or Enter/**0** to exit.
   Type **q** at any prompt to cancel.

On Linux the wizard offers password login; current-session Windows login is
available only on Windows. Native tasks offer an optional SOCKS5 URL and credential environment-variable
name. The checklist accepts one host or a file and an optional new report path.
No secret environment value is read during setup.

The wizard requires terminal stdin and never starts automatically in a pipe.
Passwords use a hidden prompt only after execution is selected and are absent
from the reusable command. It writes no settings or connection history.
EPF opening approval is a separate decision: the wizard does not grant it;
use a reviewed direct command with `--confirm-open` when needed.

## Output

Global options go **before** the command:

```powershell
./bin/onec.exe --output json infobases --worker 127.0.0.1:1560
./bin/onec.exe --color never --verbose help epf run
```

| Option | Behavior |
| --- | --- |
| `--output auto` | Readable terminal reports; existing JSON reports stay JSON when redirected |
| `--output text` | Readable sections even when redirected |
| `--output json` | Machine-readable reports |
| `--color auto` | Terminal accents; honors `NO_COLOR` and `TERM=dumb` |
| `--color always` / `never` | Force or disable accents |
| `--verbose` | All help options and complete report details/rows |

`ports`, `web enum` and `inspect` retain their default tables unless JSON is
requested. File reports and explicit JSONL/CSV batch streams keep their formats.
JSON has no ANSI decoration; diagnostics go to stderr. Syntax errors exit 2;
operation failures exit 1. Compact lists show 20 rows and report omissions;
use verbose or JSON output for all rows. Decimal/integer JSON values retain
precision, and untrusted strings are escaped for terminal display.

## Option aliases

| Preferred | Original alias | Meaning |
| --- | --- | --- |
| `--manager` | `--server` | Cluster manager host:port |
| `--database` | `--base` | Infobase name |
| `--file` | `--epf` | EPF path |
| `--upload-mode` | `--upload` | EPF upload route |
| `--allow-edit` | `--interactive` | Supported workbench field edits/context calls |
| `--session-timeout` | `--duration` | Browser session lifetime |
| `--execute` | `--apply` | Perform the network operation |

Use one spelling per option; mixing both is rejected. Boolean false uses
`--execute=false`, not `--execute false`. Network previews do not read EPFs,
request credentials or connect. `--timeout` bounds the operation;
`--session-timeout` separately bounds the browser session.

## Tab completion

Enable completion for the current PowerShell session:

```powershell
./bin/onec.exe completion powershell | Out-String | Invoke-Expression
```

For `onec` on PATH in other shells:

```sh
source <(onec completion bash)
# Zsh, after compinit:
source <(onec completion zsh)
# Fish:
onec completion fish | source
```

Completion uses offline command/flag definitions and common enum values. It
neither connects nor reads credentials or changes a shell profile.

## Workbench and verification

See [EPF workbench](EPF-WORKBENCH.md) for browser controls and supported forms.
`go test ./cmd/onec` checks wizard previews,
execution/cancellation, pipes, aliases, completion, output and redaction without
a live server. [Project verification](../../CONTRIBUTING.md) runs the full suite.
