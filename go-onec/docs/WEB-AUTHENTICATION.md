# Web-publication authentication

`onec web login` performs one explicit username/password login to the web client,
validates the application response and credential proof where applicable, then
logs out. `onec web basic-check` separately checks an HTTP Basic challenge on a
known service-description route. These operations do not use the native TCP
client, SSPI, COM or installed 1C DLLs at runtime.

## Commands

From `go-onec`:

```powershell
# Preview only: no connection, credential read or user-name enumeration.
./bin/onec.exe web login --url https://example.invalid/demo/ru_RU/ --user TestUser

# One login with a hidden password prompt, followed by logout.
./bin/onec.exe web login --url https://example.invalid/demo/ru_RU/ --user TestUser --apply

# Service authentication; the URL is the publication root, without /ru_RU/.
./bin/onec.exe web basic-check --url https://example.invalid/demo/ --user TestUser --apply

# An explicit protocol when the publication's client contract is unavailable.
./bin/onec.exe web login --url https://example.invalid/demo/ru_RU/ --user TestUser --auth v3 --apply
```

`--password-stdin` reads UTF-8 input (maximum 4096 bytes) for automation. Only one
terminal CRLF/LF is stripped; spaces and an empty password are preserved. There
is no password command-line argument, environment lookup, saved-password lookup
or automatic use of the Windows account. Never put passwords or credential
containers in reports or Git. Go strings cannot guarantee zeroization of every
copy; explicit byte buffers and codec state are cleared where possible.

Both commands emit JSON to stdout and redacted errors to stderr. Exit codes are
0 for completed checks/preview/help, 1 for operational/authentication/cleanup
failure, and 2 for invalid arguments. HTTP status, safe reason codes and phase
are retained; response text, credential/proof strings, session identifiers,
cookies and sensitive request URLs are not reported. An invalid password is
not automatically retried, downgraded or tried under another mechanism.

HTTPS with ordinary certificate validation is the default outside literal
loopback IPs. `--allow-http` explicitly permits plaintext HTTP (including a
localhost hostname). `--insecure` explicitly bypasses certificate validation;
the report records that choice. These options do not change system trust.
Legacy query credentials require TLS against a remote server, and server/proxy
request logging should exclude the query: Base64 is not encryption.

`--timeout` bounds the CLI operation, including DNS, to at most 3 minutes
(default 45 seconds). Logout receives its own 15-second context even after
cancellation. All requests stay on the supplied origin and publication path;
DNS is resolved once, redirects are never followed, no environment proxy or OS
credentials are used, and HTTP response sizes are bounded. The initial entry
must contain the observed `var VERSION` bootstrap declaration.

## Supported password profiles

| `--auth` | Automatic selection | Wire behavior / verification |
| --- | --- | --- |
| `legacy` | Legacy login route and credential-query construction in the served loader | POST `e1cib/login`, empty body, query Base64 of UTF-8 `username + backspace + password`; application JSON and session required |
| `v1` | Login route and parsed-response `credAns4` access | Preliminary seance, POST settings with C1 and optional S2, JSON credential phases, encrypted final proof |
| `v3` | Login route and parsed-response `credAns6` access | Preliminary seance, versioned POST settings with C1 and optional S2, JSON credential phases, final proof |
| `auto` | Default | Downloads `scripts/mod_main_loader.js?sysver=...` before credentials and recognizes one supported source contract; no build-number allowlist |

The web asset build is propagated as a request/cache selector; it does not
select the credential codec or independently identify the backend worker build.
The loader is read with the existing size, timeout and origin limits and is
never executed. These are narrow source signatures, not a general JavaScript
interpreter or proof of server compatibility. An unavailable, unknown or mixed
contract stops automatic login before credentials. Explicit `legacy`, `v1` or
`v3` skips contract discovery; failed authentication never tries another method.
V2 has no confirmed caller in the inspected browser
builds and is not exposed as a web-login mode. Older browser legacy code has
Unicode edge cases; this implementation sends canonical UTF-8 and unfolded
Base64, rather than reproducing historical browser encoding defects.

Modern login first requires a structured HTTP-402 challenge with a valid,
nonzero application seance ID. Cookies are retained in a fresh in-memory jar.
Ordinary requests use the complete `vrs-session` token; login's `sid` is the
UUID or the UUID prefix decoded from an opaque token. Credential phases use
fresh randomness from the existing `secpswd` package. A malformed/early proof,
ambiguous document or missing session fails the operation. The server's
application response must contain the observed `user` and `config` fields;
their specific value types are not assumed. A 200 HTML page is not a login.

Reports distinguish `credentials_submitted`, `authenticated`,
`application_ready` and `session_present`. A preliminary anonymous acceptance
does not prove the supplied password, so `credentials_submitted` stays false.
`application_ready` means login/password policy permits further application
startup, not that forms or configuration startup have already executed.

Password-policy statuses 2/4/6 produce `password_change_required` after
authentication; the CLI still cleans up the session and changes no password.
Unknown policy statuses fail closed. Standard 2FA and external-factor requests
are recognized as explicit `second_factor_required` or
`external_second_factor_required` outcomes; this release does not submit a
second factor, resend a code or approve an external challenge. OIDC/OpenID,
QR/email authentication, saved-login tokens, HTTP NTLM/Kerberos and password
change workflows are not implemented. A publication requiring those mechanisms
returns an explicit failure instead of being reported as authenticated.

## HTTP Basic is a separate check

The default resource is `odata/standard.odata/$metadata`; `--resource` also
accepts the OData root, `hs/`, `ws/` or `ws/<name>?wsdl`. Arbitrary application
methods, entity queries and SOAP operations are not invoked.

The command first requests the resource anonymously. Only an HTTP401 offering
Basic permits one credentialed retry to that exact URL. Cookies from the
anonymous response are not reused, so a cookie cannot mask the password check.
An initially public 2xx response yields `authentication_not_required=true` and
does not validate the supplied password. A 2xx after the challenge records
`challenge_satisfied=true`; no web-client application session is established.
403/404 after credentials remain inconclusive for password validity and fail
the check. Basic here does not supply a second, separately configured IIS
credential layer for `web login`.

1C may request Basic itself after IIS accepts anonymous access. This is a
standard platform behavior, distinct from enabling the IIS Basic module.
See [official 1C setup/authentication documentation](https://1c-dn.com/anticrisis/tools-and-technologies/embedded-web-client/setting-up/).

## Library lifecycle

`webauth.New(ctx, Config)` discovers the entry build; `Login(ctx, Credentials)`
attempts authentication once. A successful client retains an in-memory session
for `About(ctx)` and future supported application operations. `About` returns
private JSON to the caller without logging it. There is no token-export/import
API, captured-token replay or session persistence on disk.

Call `Logout` on every exit path if `SessionPresent()` is true, including failed
credential-proof validation and password-policy requirements. A non-200/201/204
or exception reply is an unconfirmed cleanup. `Close` releases local transport,
cookies and session references; it does not claim remote logout. Methods are
serialized and a second login attempt requires a new client.

```go
client, err := webauth.New(ctx, webauth.Config{URL: publicationURL})
if err != nil { return err }
defer client.Close()
result, loginErr := client.Login(ctx, webauth.Credentials{
    Username: knownUser, Password: suppliedPassword, Method: "auto",
})
// Use result to distinguish authentication from application policy.
_ = result
cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
defer cancel()
return errors.Join(loginErr, client.Logout(cleanupCtx))
```

## Compatibility

Live legacy web login/logout is confirmed on **8.3.18.1208**. HTTP Basic service
authentication has separate acceptance on **8.3.18.1208** and **8.3.27.2342**.
V1/V3 application exchanges have synthetic validation; the build-27 V3 live
exchange ended with a license-unavailable response, without final login proof.

Static loader comparison across eight client builds does not establish support
for every server or publication setting. HTTP Basic success remains separate
from application login. See [compatibility](COMPATIBILITY.md) for the full matrix.
