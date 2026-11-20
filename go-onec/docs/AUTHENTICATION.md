# Authentication

Transport authentication, infobase login and application execution are separate
layers. The client does not silently switch accounts or methods. Run the examples
from `go-onec`; they preview without credentials or a connection. Add `--execute`
to perform login and cleanup. Use `--verbose help login` for every option.

## Current Windows session

```powershell
./bin/onec.exe login --worker 127.0.0.1:1560 --database demo --auth windows
```

On Windows, the default provider uses current-process Windows SSPI. On Linux,
ordinary native commands default to anonymous transport and legacy infobase
password authentication; see [Linux setup](LINUX.md). `--manager HOST:PORT`
discovers a worker; `--worker` selects it directly. Password login below still
uses the platform default transport unless `--transport anonymous|windows` or
an explicit credential provider is selected. `--transport auto` is the default.
`users` and `settings` retrieve prelogin selection/settings data, not proof of an
authenticated infobase session or a complete account list.

## Infobase password

```powershell
./bin/onec.exe login --worker 127.0.0.1:1560 --database demo --auth legacy --user example
```

Execution prompts for a hidden password; `--password-stdin` reads one password
from stdin and requires `--user`. There is no password argument. Legacy mode
can offer the prelogin selection list when `--user` is omitted.

| Mode | Scope |
| --- | --- |
| `legacy` | Live login and refusal-to-success acceptance on 8.3.18.1208; reversible Base64 credentials, not password hashing |
| `v1`, `v3` | Shipped-JavaScript synthetic oracles; no live native SecPswd login proof |
| `v2` | Schema/synthetic evidence only; defaults to the `MobileClient` application profile |

Other modes default to `1CV8C`. Selecting a mode or advertised client version
does not enable it on the server. Password modes suppress Windows fallback and
ordinary `Login` allows one attempt. Explicit legacy refusal reuse is described
in [batch checks](LOGIN-BATCH.md#connection-reuse-boundary). See
[acceptance](AUTH-ACCEPTANCE.md) for the build-18 ingress mismatch and intermittent
precredential context-release failures. Transport negotiation does not establish
encryption of every subsequent application message.

## Explicit NTLMv2

```powershell
./bin/onec.exe login --worker 127.0.0.1:1560 --database demo --auth windows --ntlm password --ntlm-domain EXAMPLE --ntlm-user alice
```

Use `--ntlm hash` for an NT hash. Both domain and unqualified account name are
required; this identity is separate from infobase `--user`. Input is hidden,
or explicitly read with `--ntlm-secret-stdin` (hash input is 32 hexadecimal
characters). The provider uses fresh NTLMv2 exchanges and no OS credential cache.
It excludes ticket files. NTLM completion is not mutual server authentication.

## File-backed Kerberos

```powershell
./bin/onec.exe login --worker 127.0.0.1:1560 --database demo --auth windows --ticket-file credentials/service.kirbi --kerberos-spn service/server.example
```

Supply the exact service/host SPN and a direct worker. A TGT additionally needs
`--kdc HOST:PORT`; an exact service ticket may not need a KDC. The provider uses
same-realm `.kirbi`/ccache credentials, fresh authenticators and server-proof
validation. It neither imports tickets into the OS cache nor replays captured
tokens. The identity still needs a matching OS-authenticated infobase user.
Keep credential containers outside the repository.

Explicit NTLMv2 and ticket-file Kerberos are pure Go with synthetic coverage;
live domain/1C compatibility remains unproven. A successful Linux build is not
live authentication evidence. Default current-session SSPI requires Windows.

## Other interfaces and evidence

- `infobases` uses [transport selection](INFOBASES.md): `anonymous` or `windows`.
- [Administration](ADMINISTRATION.md) separates transport, agent and cluster credentials.
- [Web authentication](WEB-AUTHENTICATION.md) separates application login from HTTP Basic.
- [Compatibility](COMPATIBILITY.md) records operation/build evidence; OpenID,
  OpenID Connect and SAML login flows are not implemented.

Provider behavior is covered by the shipped synthetic tests. See
[compatibility](COMPATIBILITY.md) for separate live acceptance boundaries.
