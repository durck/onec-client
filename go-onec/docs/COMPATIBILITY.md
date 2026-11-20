# Server-version compatibility

Support is a bounded protocol subset, selected by known interfaces and response
schemas. Matching an advertised build is insufficient; unknown schemas and
management signatures fail explicitly. No installed 1C client is needed.

## Live and synthetic evidence

| Evidence | What it establishes |
| --- | --- |
| Native TCP on **8.3.18.1208** | Bounded connection, users/settings, Windows/legacy login, worker enumeration, controlled EPF/form flows and cluster reads |
| Experimental native 27 policy | Exact-build source and original COM27 to synthetic-peer n/c progression; independent Go client synthetic bootstrap/login/cleanup. No Go client to real build-27 server acceptance |
| HTTP Basic on **8.3.18.1208 / 8.3.27.2342** | Service authentication, separate from application login |
| Native SecPswd V1/V3 | Shipped-code synthetic vectors; no live SecPswd login proof |
| Native SecPswd V2 | Schema/synthetic evidence only |
| Web application login | Live build-18 legacy; synthetic V1/V3 acceptance; build-27 V3 final success unconfirmed |
| Eight installed client builds | Source/interface comparison and synthetic schema acceptance, not eight live servers |
| Explicit NTLMv2 / file-backed Kerberos | Pure Go synthetic coverage; live domain/1C compatibility unproven |

The [known-account check](AUTH-ACCEPTANCE.md) reports login and cleanup
separately. Bounded parallel acceptance does not promise that all parallel
logins succeed; precredential context-release failures remain operational errors. EPF opening approval survived logout; its scope
and lifetime remain unknown.

## Advertised identity

`Profile.Version` / `--client-version` defaults to `8.3.18.1208`. It is sent as
client identity, not detected server identity or a decoder selector. Server
version policy and native bootstrap acceptance remain prerequisites.

Administration reports `advertised_client_version` separately from
`interface_methods`. Forms validate metadata and use `scalar-tracked-v1` for
supported context state. Web login uses served `var VERSION` for request/cache
selectors and the loader contract for credential selection; it executes no
JavaScript. SecPswd versions, module image schemas, assembly/config selectors
and NTLM/Kerberos versions are distinct from platform builds.

## Experimental native 27 policy

`--transport-policy` explicitly selects record processing independently of
`--client-version`, application login and the authentication provider:

| Selector | Behavior |
| --- | --- |
| `plain` (default) | Existing native record framing, with no new policy negotiation |
| `native27-n` | Request n/0 with minimum n; accept n or the higher c/2 reply |
| `native27-c` | Request c/2 and require at least c in the initial and subsequent replies |

The option is available on common native client commands, `admin` and
`infobases`. The corresponding library field is `TransportPolicy` on `Config`,
`AdminConfig` and `InfobaseListConfig`. Empty library values mean `plain`.
Port probes and web commands retain their separate protocols.

The experimental subset comes from Windows x64 **8.3.27.2342**: fresh 1024-bit
RSA/PKCS#1 v1.5, empty known-key identifier, base64 policy fields, n/c levels and
mode-zero DES-EDE3-CBC. The first application reply is encrypted even for n.
Subsequent c exchanges use the source-defined IV increment and level marker.
Known-key identifiers, initial y selection, AES modes and alternate providers
are unsupported. This policy does not itself establish peer authentication.

Independent offline peers complete bootstrap, interface query, users, synthetic
inner authentication, login/logout and release, plus administration/enumeration.
They also check minimum levels, malformed records and cancellation: a complete
valid reply advances policy state before cleanup, while an incomplete or invalid
exchange is terminal. There is no fallback or replay after such a failure.
The separate narrow [precredential context recovery](API.md#prelogin-and-login)
keeps the selected transport policy; it has no real build-27 acceptance.

Original COM27 observations exercised a synthetic peer, not a real build-27
server. No configured build-27 server was used for the new Go client path.
These checks establish an experimental implementation boundary, not full native
8.3.27 compatibility, live authentication or application acceptance.

## Supported contracts

| Surface | Selection and limits |
| --- | --- |
| Native connection, login, users/settings, batch/acceptance | Known bootstrap/RPC/HTTP schemas; no automatic server-build discovery or authentication fallback |
| Administration | Interface method-count profiles 68/79/80/89/96, per-operation signatures and strict collection shapes; [optional payload limits](ADMINISTRATION.md#compatibility-and-evidence) apply |
| Worker infobases | Known interface and short-base schema; unknown interfaces rejected |
| Port checks | Reachability is build-independent; greeting/API recognition covers known signatures |
| EPF upload | Delimiter selects raw-backspace or URI tuple; mixed/invalid encodings fail and raw percent escapes stay opaque |
| EPF extmd | Explicit route with strict status/Location validation; no fallback |
| EPF opening approval | File-specific challenge/response and explicit consent; inspected 8.3.12 lacks the route |
| Form methods | Embedded method maps or aligned separate table; malformed embedded data does not fall back |
| Snapshots/module images | Supported JSON/undefined subset and module alignment; images are not executed |
| Context calls / workbench | Validated scalar state/revisions; unknown mutations retire context and calls are never replayed |
| Dynamic lists | Flat scalar lists, explicit period and bounded windows; advanced list features excluded |
| Offline form helpers | Supported lifecycle/layout/value schemas, not complete GUI parity |
| Web inventory | Fixed routes/parsers and served `sysver`; unavailable endpoints remain inconclusive |
| Web auto login | Loader's legacy credential construction or parsed `credAns4`/`credAns6`; unknown/mixed contracts stop before credentials |
| Explicit web login / Basic | Strict password proof/application validation or separate supported Basic service-description routes |
| Traffic inspector / BSL images | Known framing/atom/HTTP formats, image schema 1 and supported opcodes; unknown formats fail explicitly |

Native connections use IPv4 and ASCII host/infobase names, one worker context
per client, serialized operations and bounded responses/value types. There is
no connection pool, general reconnect, multi-host cluster routing, general
RPC dispatcher, query/transaction API or complete method catalogue. See
[EPF limits](EXTERNAL-PROCESSING.md#scope) and [authentication](AUTHENTICATION.md)
for additional boundaries. Transport negotiation alone does not establish
application login, execution or successful cleanup.

## Verification

The eight-build comparison used static and synthetic evidence, not eight live
servers. A matching version string or successful offline test is not a live
compatibility certification.

From the repository root, `sh tools/test.sh` (Linux) or `./tools/Test-Project.ps1`
(Windows) runs the current automated checks and builds the CLI. The public tests
cover checklist orchestration, SOCKS5, anonymous transport and CLI behavior. They
need no installed platform, server credentials or sample EPFs. Manual examples
have the separate build and authentication limits documented above.
