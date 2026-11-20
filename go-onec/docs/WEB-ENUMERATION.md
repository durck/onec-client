# Anonymous web-publication inventory

`onec web enum` inspects a **known** 1C publication and highlights observations
that need review. It is independent of the native TCP client and does not need
a worker address, database login, installed 1C libraries or Windows SSPI.
It cannot obtain a server-wide publication/infobase list from a web port alone.

## Run

From `go-onec` in PowerShell:

```powershell
# Preview the exact route profile; no DNS, network or report files.
./bin/onec.exe web enum --url https://example.invalid/demo/ru_RU/

# Perform the profile and save a new JSON report alongside the readable table.
./bin/onec.exe web enum --url https://example.invalid/demo/ru_RU/ --apply --out first.json

# Include seven known static assets; scripts are parsed as data, never executed.
./bin/onec.exe web enum --url https://example.invalid/demo/ru_RU/ --assets --apply --json

# Compare selected metadata with a complete report using identical URL/options.
./bin/onec.exe web enum --url https://example.invalid/demo/ru_RU/ --apply --baseline first.json --out second.json --fail-on-findings

./bin/onec.exe web enum --help
./bin/onec.exe web completion powershell
```

Flags are explicit; no account, proxy, cookie, environment or configuration-file
credentials are consumed. `--json` emits only the report to stdout; errors go
to stderr. `--out` refuses an existing destination **before network access**.
Do not commit reports: publication names, certificate names, authentication
settings and selected IIS paths may describe private infrastructure.

`--insecure` explicitly bypasses certificate verification for that run, adds a
warning and marks the peer identity unverified. There is no automatic fallback
after a TLS failure. This can be needed when checking an IP URL whose private-CA
certificate is issued to a DNS name; it does not establish that name's ownership.

The path is a directory. `/team/demo/ru_RU/` uses `/team/demo/` for service routes
and the localized directory for the web client. A final `xx_YY` segment is
interpreted as a locale; otherwise the supplied directory is used for both.
Locale-dependent `misc` is skipped when no locale is supplied. Redirects are
reported without following them, including same-origin redirects. If the entry
redirects to a language directory, rerun with the reviewed full directory URL.
Credentials, query strings, fragments, traversal and ambiguous paths in the
input URL are rejected. An origin without a publication path is insufficient.

## Profile and limits

The localized default profile has 17 requests (16 without a locale); `--assets`
adds seven. These are a supported observed subset, not all 1C HTTP routes.

| Surface | Request | Observation |
| --- | --- | --- |
| Entry | `GET <client>/` | Bootstrap version, BASE, LANG, E1CIB, VENDORPREFIX |
| PWA | `GET <client>/manifest.json` | Name, display, colors, start path, icon count |
| Users | `GET <client>/e1cib/users` | Empty/BOM-only versus nonempty candidate payload; names omitted |
| Authentication settings | Empty `POST <client>/e1cib/additionalAuthSettings?version=1` | Selected booleans/numbers and authentication type names |
| Metadata gates | GET `e1cib/about`, `types`, `sysenums`, `modules/defs`, `syspics` | Response representation and anonymous payload/exception indicators |
| Locale | GET `e1cib/misc?cmd=localeInfo&locale=XX_YY` | JSON locale wrapper presence |
| Service roots | GET `<publication>/ws/`, `hs/` | HTTP status and authentication challenge, not a service catalogue |
| OData | GET `odata/standard.odata/` and `$metadata` | XML service/schema recognition; no entity records requested |
| Optional SOAP examples | GET `ws/WebCommonInfoBases?wsdl`, `ws/WebDistributiveLocation?wsdl` | WSDL recognition only; no SOAP method call |
| Missing-path control | GET an unlikely fixed path under the client directory | Detect byte-identical catch-all responses; not proof the path cannot exist |
| Optional assets | GET `mainform.html`, `authform.html`, `resourceStrings`, bootstrap, service-worker, loader and mainform JavaScript | Status, representation, size and SHA-256; no dynamic dependency crawl |

If the entry exposes a recognized four-part `VERSION`, `sysver` is added to
applicable following requests. That is a **web asset build**, not independent
proof of the server worker build. Version/configuration/cache arguments needed
by post-login endpoints are not synthesized beyond `sysver`; refusals can also
reflect missing parameters. The authentication-settings POST has no username,
password, challenge or body. An informational request can still initialize
server-side state; no claim of universally side-effect-free HTTP is made.

One host is resolved once and the first address is pinned for the run; the
original hostname remains the HTTP/TLS identity. The transport has no automatic
proxy, cookie jar, OS authentication, client certificate or redirect following.
It does not expand scope using certificate SANs, source maps, links or JS routes.

Requests are sequential, paced by 250 ms, with 15 seconds per request and a
maximum of 3 minutes overall including DNS (`--timeout` can lower this). Response
headers are limited to 64 KiB. Bodies are limited to 1 MiB each, or 8 MiB with
`--assets`, and 32 MiB of collected body prefixes overall. Limits apply after
HTTP decompression; one extra byte is read to detect truncation. Partial bodies
are hashed but not analyzed. A failed initial connection/TLS handshake stops the
profile. Ctrl+C/SIGTERM preserves the report collected so far.

No login, password recovery, QR/2FA, licensing, module invocation, application
record query, script execution, credential acquisition or external host scan
is performed. The two optional SOAP names are documented examples; they need
not be deployed. A protected route may challenge before route lookup.

## Interpret findings

`INFO` and `WARN` are review labels, not vulnerability ratings. HTTP `401`,
`403` and `404` alone are ordinary observations and do not generate warnings.

| Finding | Meaning / limitation |
| --- | --- |
| `detailed_iis_error` | HTML exposes at least two selected IIS diagnostic fields, possibly a physical path |
| `exception_stack_disclosed` | JSON exception exposes native module names; offsets and full stack are omitted |
| `nonempty_users_payload` | Candidate user-list disclosure; format is not fully validated and account names are not retained |
| `anonymous_service_description` | Recognized XML OData/WSDL description is anonymously readable; operation/data access is unproven |
| `anonymous_metadata_payload` | HTTP 200 non-HTML response from a metadata route; semantics/completeness need review |
| `unexpected_representation` | E.g. HTML login/catch-all page instead of a manifest or metadata response |
| `success_with_exception` | HTTP 200 carries a 1C JSON exception |
| `matches_missing_control` | Bytes match the missing-path control; a 200 does not confirm a distinct endpoint |
| `authentication_payload_omitted` | Recognized JSON authentication field; all body summary fields omitted |
| `server_error`, `missing_auth_challenge` | HTTP 5xx, or 401 without a recognized challenge scheme |
| `tls_unverified`, `plaintext_http` | Explicitly unverified TLS or HTTP without encryption |
| `incomplete_response` | Transport/read/size failure; report is incomplete |
| `baseline_changed`, `baseline_tls_changed` | Selected semantic metadata or TLS verification state changed |

A BOM-only users response is empty **for this request**; it does not mean that
the infobase contains no users. Empty-prefix `hs/`/`ws/` responses do not list
configured services. `authTypes=["standard"]` describes returned client settings,
not every server authentication capability. Numeric durations are retained as
reported without assuming units. TLS names and HTTP banners are peer claims.

JSON includes each requested URL, method, status, selected headers, challenge
schemes/Basic realm, representation, byte count, hash, timing, selected summary,
TLS certificate details and findings. It contains no raw response bodies,
cookies, NTLM/Negotiate challenge tokens, user names or arbitrary JSON fields.
Redirect query/fragment/userinfo are removed. The selected strings are not a
general secret scrubber: inspect a report before sharing it. A hash identifies
the collected prefix when truncated, and the complete body otherwise.

Baseline comparison requires complete matching plans, URL and `--assets` value.
It compares status, content type, representation, authentication schemes/realm,
sanitized redirects and selected body metadata. Timing, response hashes/sizes,
server banners, certificate rotation and remote IP are ignored to reduce noise;
the full reports retain those observations for manual comparison. A lack of
differences is not a security verdict. Incomplete reports cannot be baselines.

Exit codes for this command: `0` complete operation/preview/help; `1` operational
failure, or warning findings when `--fail-on-findings` is supplied; `2` invalid
arguments or incompatible baseline. Warning findings do not fail by default.
The `web completion` subcommand emits scoped completion snippets for bash, zsh,
fish and PowerShell; it does not install or execute them.

## Basic authentication and provenance

Basic is an ordinary HTTP authentication scheme, not necessarily an extra IIS
configuration layered on top of the infobase. 1C documents that, when the web
server accepts anonymous access, its extension can request Basic itself to
authenticate an infobase user. IIS also offers its own separate Basic module,
disabled by default. A response realm alone cannot identify the configuration.

An IIS error naming `IsapiModule`, `ExecuteRequestHandler`, `1C Web-service
Extension`, `Logon Method: Anonymous`, together with a 1C Basic realm, supports
an extension-generated challenge. Confirming the effective configuration and
who changed it requires IIS/publication configuration and administrative logs.

Sources: [1C publication and Internet-service authentication](https://1c-dn.com/anticrisis/tools-and-technologies/embedded-web-client/setting-up/),
[IIS Basic authentication configuration](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/security/authentication/basicauthentication).

## Library and compatibility

Library entry points are `webprobe.NewPlan`, `Enumerate`, `CompatibleBaseline`
and `Compare`. `Enumerate` returns a partial report and error on incomplete
transport, budget or cancellation failures. Check both the error and
`Report.Complete`; HTTP status codes are observations, not authentication results.

The profile is anonymous. Deployment-specific responses and information
disclosures must be interpreted for the selected endpoint; one publication's
results do not establish compatibility with every web-server configuration.
