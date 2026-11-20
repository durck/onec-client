# Command guide

Build and launch the CLI using the [quick start](../README.md#quick-start).
Examples below run from `go-onec`; replace endpoints and database names with
your own. Network commands preview unless `--execute` is supplied (`--apply`
is a compatible alias). Library methods perform their operations immediately.

## Choose a command

| Task | Command | Guide |
| --- | --- | --- |
| Audit empty credentials across hosts, clusters and databases | `checklist` | [Audit checklist](docs/CHECKLIST.md) |
| Guided setup | `wizard` | [Console workflow](docs/INTERFACE.md) |
| Verify login and log out | `login` | [Authentication](docs/AUTHENTICATION.md) |
| List databases on a worker | `infobases` | [Infobase enumeration](docs/INFOBASES.md) |
| Read the prelogin selection list or settings | `users`, `settings` | [Authentication](docs/AUTHENTICATION.md) |
| Find or check an endpoint | `ports scan`, `ports check` | [Port checks](docs/PORTS.md) |
| Inspect or modify a selected cluster | `admin` | [Administration](docs/ADMINISTRATION.md) |
| Discover/call EPF functions or retrieve module images | `epf methods`, `epf run`, `epf modules` | [External processing](docs/EXTERNAL-PROCESSING.md) |
| Open a local EPF workbench | `epf ui` | [Workbench](docs/EPF-WORKBENCH.md) |
| Inspect saved form events | `epf lifecycle` | [API](docs/API.md#external-processing) |
| Inventory a publication | `web enum` | [Web inventory](docs/WEB-ENUMERATION.md) |
| Check web login or HTTP Basic | `web login`, `web basic-check` | [Web authentication](docs/WEB-AUTHENTICATION.md) |
| Validate a known test account | `auth-check` | [Acceptance](docs/AUTH-ACCEPTANCE.md) |
| Check supplied credentials with bounded workers | `login-batch` | [Batch checks](docs/LOGIN-BATCH.md) |
| Inspect a saved TCP stream offline | `inspect` | [Traffic inspector](docs/TRAFFIC-INSPECTOR.md) |

## Common examples

```powershell
# Preview login through a known worker or discover one through the manager.
./bin/onec.exe login --worker 127.0.0.1:1560 --database demo
./bin/onec.exe login --manager 127.0.0.1:1541 --database demo

# Explicitly perform a read or login/logout.
./bin/onec.exe users --worker 127.0.0.1:1560 --database demo --execute
./bin/onec.exe login --worker 127.0.0.1:1560 --database demo --execute

# Preview structured output; use --execute to collect the list.
./bin/onec.exe --output json infobases --worker 127.0.0.1:1560
```

`--worker` connects directly to a current working-process endpoint. `--manager`
discovers a worker port on the configured manager host; worker ports can change.
`--agent` belongs to the separate administration interface. Transport credentials
and infobase login are distinct; a user/settings response does not prove login.

Native commands also accept `--proxy socks5://127.0.0.1:1080`, including the full
`checklist` workflow. Target DNS is delegated to SOCKS5, with no direct fallback.
See [proxy routing and authentication](docs/PROXY.md) for scope and examples.

Native commands, `admin` and `infobases` also accept explicit
`--transport-policy plain|native27-n|native27-c`. The default stays `plain`;
changing `--client-version` never enables a policy. The two native27 selectors
are experimental and have no real build-27 server acceptance. See the
[policy contracts and limits](docs/COMPATIBILITY.md#experimental-native-27-policy)
before selecting one.

Use `<command> --help` for common options and `--verbose help <command>` for all
options. See [console controls](docs/INTERFACE.md) for aliases and completion,
[compatibility](docs/COMPATIBILITY.md) for support limits, and the
[API guide](docs/API.md) for library setup, ownership and cleanup.
