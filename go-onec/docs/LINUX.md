# Linux setup

The CLI builds and runs on Linux without Wine, vendor DLLs, COM or a Windows
credential cache. The default audit checklist, port-role probes, administration
and database enumeration use anonymous native transport. Common native commands
default to `--auth legacy --transport auto`; on Linux, auto selects anonymous.

## Build and run

With Go 1.25.13 or a compatible newer toolchain, from `go-onec`:

```sh
go build -trimpath -buildvcs=false -o bin/onec ./cmd/onec
./bin/onec checklist --target audit-host.example
./bin/onec checklist --targets-file targets.txt --execute --report-file audit.json
./bin/onec checklist --targets-file targets.txt --proxy socks5://127.0.0.1:1080 --execute
./bin/onec users --worker audit-host.example:1560 --database demo --execute
./bin/onec login --worker audit-host.example:1560 --database demo --auth legacy --user auditor --execute
```

Use authorized targets. The login command prompts for the password; do not place
it in shell arguments. A release executable needs no Go installation.

## Transport and identity

| Mode | Linux | Windows |
| --- | --- | --- |
| Anonymous native NTLM | Pure Go null-session provider | Explicit anonymous SSPI |
| Current Windows session | Unavailable | SSPI |
| Explicit NTLMv2 / ticket-file Kerberos | Pure Go, documented constraints | Same providers |
| SOCKS5 for native commands | Supported | Supported |
| Local listener process ownership | Unavailable | Windows listener snapshot |
| Web commands and offline tools | Supported | Supported |

Anonymous transport sends empty NTLM identity/proof fields and a single zero
LM response. It does not use account credentials, provide mutual authentication
or protect application payloads. No sign/seal/key-exchange capability is offered;
the protocol's mandatory ALWAYS_SIGN marker does not change that boundary.
The native 1C bootstrap still supplies a client computer name as protocol metadata.
No transport failure falls back to a different identity.

The library keeps its existing default provider. To select anonymous transport
explicitly, set `Config.SecurityFactory = onec.NewAnonymousSecurity` and use an
explicit infobase password method. Provider selection is separate from infobase
authentication; an accepted anonymous transport is not a successful database login.

## Verification and limits

From the repository root, run `sh tools/test.sh`. CI checks Linux and Windows.
The Linux runtime was exercised in an isolated Linux amd64 container with local
synthetic peers, including native TCP bootstrap, user discovery, an empty-password
login and confirmed logout, plus checklist orchestration and SOCKS5 routing.
Network isolation prevented contact with external targets.

This establishes Linux execution of the implementation, not new live 1C server
acceptance. Existing live native evidence remains bounded to 8.3.18.1208.
SecPswd, native27 policies, explicit NTLMv2 and Kerberos retain the limits in
[compatibility](COMPATIBILITY.md) and [authentication](AUTHENTICATION.md).

Protocol references: [MS-NLMP anonymous response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3),
[client negotiation requirements](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b535636e-49c4-43af-8685-801cc381882f).
