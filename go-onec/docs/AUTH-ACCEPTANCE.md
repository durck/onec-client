# Known-account authentication checks

`auth-check` compares password methods for one known test account and records
login, optional EPF calls and cleanup separately. For the empty-password audit
across discovered users, use [checklist](CHECKLIST.md).

## Run

From `go-onec`, after building the CLI. On Windows use `./bin/onec.exe`:

```sh
# Preview the selected method without connecting or reading credentials.
./bin/onec auth-check --worker 127.0.0.1:1560 --database demo --methods legacy

# Execute and save a new JSONL report; credentials use the hidden prompt.
./bin/onec auth-check --worker 127.0.0.1:1560 --database demo --methods legacy --execute --report-file auth-check.jsonl

# Preview extended checks and the included control EPF.
./bin/onec auth-check --worker 127.0.0.1:1560 --database demo --methods legacy --extended --control-epf testdata/epf/forms/NativeFormProbe.epf
```

`--methods` selects a comma-separated set from `legacy,v1,v2,v3`; the default
compares all four. Selecting a method does not establish server support.
`--extended` adds legacy refusal-to-success and two parallel successful-login
cases after successful baselines. It makes additional authentication attempts.

`--control-epf` enables method discovery, a control call and form-close checks.
Only the shipped `NativeFormProbe.epf` hash is accepted. If the server requires an
opening decision, `--confirm-control-epf` explicitly permits one confirmation for
that file. The platform may retain the decision after logout; automatic revocation
is not promised. See [EPF opening behavior](EXTERNAL-PROCESSING.md#opening-confirmation-and-cleanup).

Execution requires `--execute` and a new `--report-file` path. Preview creates no
report. Native commands also support the documented [SOCKS5 options](PROXY.md).

## Read the results

Each case records login, method discovery, the expected control result, form
close and client cleanup separately. A completed report does not mean every
method succeeded. A failed authentication or preliminary request does not by
itself establish an incorrect password.

Operational, policy/limit or cleanup failures stop remaining serial work;
parallel work is cancelled and joined. Cleanup has an independent deadline.
Reports contain case outcomes and redacted statistics, without credentials or
authentication proofs. Go strings cannot guarantee erasure of secrets from memory.

## Compatibility

Native live acceptance is bounded to **8.3.18.1208**. Confirmed scenarios include
legacy login/logout, refusal-to-success, bounded parallel logins and control EPF
calls after legacy or current-Windows login. Intermittent precredential
context-release failures were also observed; parallel reliability is not guaranteed.

Native SecPswd V1/V2/V3 login has no completed live acceptance on that build.
Explicit NTLM, file-backed Kerberos, Linux-to-server interoperability and newer
native server builds retain their separate limits in [compatibility](COMPATIBILITY.md).
Recovery is restricted to the initial credential-free refusal described in the
[API](API.md#prelogin-and-login); credentials and application operations are not replayed.
