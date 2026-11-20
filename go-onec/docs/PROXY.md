# SOCKS5 for native commands

Add `--proxy socks5://HOST:PORT` after a native command. Both `socks5://` and
`socks5h://` use proxy-side target name resolution. The client never falls back
to a direct target connection when the proxy fails.

```powershell
./bin/onec.exe checklist --target server.example --proxy socks5://127.0.0.1:1080 --execute --report-file audit.json
./bin/onec.exe checklist --targets-file targets.txt --proxy socks5://127.0.0.1:1080 --execute
./bin/onec.exe ports scan --host server.example --ports 1540-1591 --proxy socks5://127.0.0.1:1080 --execute
./bin/onec.exe admin clusters --agent server.example:1540 --proxy socks5://127.0.0.1:1080 --execute
./bin/onec.exe users --worker server.example:1560 --database demo --proxy socks5://127.0.0.1:1080 --execute
```

The flag applies to `checklist`, `ports scan/check`, `admin`, `infobases`,
`login`, `users`, `settings`, `auth-check`, `login-batch`, and native `epf`
operations including the workbench's native connection. It is a command option,
not a global option before the command. Web-publication commands and offline
commands do not accept it. The interactive wizard offers the same optional proxy settings for native tasks.

## Authentication

For a proxy requiring username/password authentication, put `username:password`
in an environment variable and supply only its name:

```powershell
# Provision ONEC_PROXY_AUTH in the process environment through your secret workflow.
./bin/onec.exe checklist --target server.example --proxy socks5://127.0.0.1:1080 --proxy-auth-env ONEC_PROXY_AUTH --execute
```

The first colon separates username and password; passwords may contain further
colons. Each field must contain 1..255 bytes. The variable is read once on the
first actual connection, not during preview/help. Missing or malformed values
fail without connecting. Proxy authentication is separate from 1C authentication.
Username/password values in the URL are rejected, as are URL paths, queries,
fragments, unsupported schemes, missing ports and explicitly empty flags.
Report metadata contains the proxy endpoint and whether authentication is
configured, not the username, password or environment-variable value.

## Routing and DNS

The same SOCKS dialer handles the agent, manager, manager-selected worker,
infobase enumeration, prelogin user list, login and cleanup connections.
Port discovery uses it for both initial greetings and subsequent RPC role probes.
Custom/proxied port probes do not inspect the local Windows process table.

Target domains are passed as SOCKS5 domain addresses; no Go target DNS lookup is
performed. The proxy endpoint itself may require local DNS when it is a hostname.
Remote resolution happens for each connection, so the client cannot pin one
resolved target IP or deduplicate domain aliases by IP. Use literal IP targets
when address pinning is required. Returned 1C hostnames do not replace the supplied
target name; manager-selected ports remain on that same name/IP.

In proxy mode, checklist rows omit `resolved_ip` for domain targets, and the
limitations describe remote DNS. Port reports use `dns_resolution: "remote"`
and an empty `resolved_ip` when the selected address is unknown. The SOCKS reply's
bound address is not treated as the target IP.

Proxy failures remain errors, not evidence that a target port is closed.
Proxied `ports` commands return a nonzero exit and `success: false` when any
port check errors, times out or is canceled. A SOCKS refusal does not reliably
distinguish target policy, target reachability and proxy availability. Checklist
retains these uncertainties as incomplete coverage.

Each SOCKS connection/handshake is bounded by ten seconds or the caller's shorter
deadline. Cancellation closes an unfinished handshake. Normal native session
cleanup and retry rules remain in force; checklist disables context recovery.

## Scope and evidence

This routes Go-managed native TCP sockets. It does not configure a system-wide
proxy, browser traffic or the operating system's authentication networking.
File-backed Kerberos/KDC mode combined with `--proxy` is rejected before reading
the credential file, because its separate KDC transport is not proxied.
Windows SSPI retains its OS-managed authentication behavior; explicit anonymous
transport remains the checklist default. HTTP CONNECT and SOCKS4 are unsupported.

Tests use local synthetic SOCKS5 peers for anonymous and authenticated tunnels,
domain forwarding, refusal, cancellation, no-direct-fallback behavior and CLI
routing. This is not a live 1C-through-proxy acceptance claim and does not expand
the existing [server compatibility](COMPATIBILITY.md) boundary.
