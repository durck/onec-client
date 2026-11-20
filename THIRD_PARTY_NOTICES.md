# Third-party notices

The CLI includes Go runtime/standard-library code and the dependency modules below.
Original license/notice texts are retained in `licenses/`. Dependency source is
resolved by `go.mod` and `go.sum`; it is not vendored. The project MIT license
does not replace third-party terms. Refresh this inventory when dependencies change.

| Component | Version | License and notice texts |
| --- | --- | --- |
| `github.com/hashicorp/go-uuid` | `v1.0.3` | [LICENSE](licenses/github.com-hashicorp-go-uuid-LICENSE.txt) |
| `github.com/jcmturner/aescts/v2` | `v2.0.0` | [LICENSE](licenses/github.com-jcmturner-aescts-v2-LICENSE.txt) |
| `github.com/jcmturner/dnsutils/v2` | `v2.0.0` | [LICENSE](licenses/github.com-jcmturner-dnsutils-v2-LICENSE.txt) |
| `github.com/jcmturner/gofork` | `v1.7.6` | [LICENSE](licenses/github.com-jcmturner-gofork-LICENSE.txt) |
| `github.com/jcmturner/gokrb5/v8` | `v8.4.4` | [LICENSE](licenses/github.com-jcmturner-gokrb5-v8-LICENSE.txt) |
| `github.com/jcmturner/rpc/v2` | `v2.0.3` | [LICENSE](licenses/github.com-jcmturner-rpc-v2-LICENSE.txt) |
| `golang.org/x/crypto` | `v0.53.0` | [LICENSE](licenses/golang.org-x-crypto-LICENSE.txt) |
| `golang.org/x/net` | `v0.56.0` | [LICENSE](licenses/golang.org-x-net-LICENSE.txt) |
| `golang.org/x/sys` | `v0.46.0` | [LICENSE](licenses/golang.org-x-sys-LICENSE.txt) |
| `golang.org/x/term` | `v0.44.0` | [LICENSE](licenses/golang.org-x-term-LICENSE.txt) |
| `golang.org/x/text` | `v0.39.0` | [LICENSE](licenses/golang.org-x-text-LICENSE.txt) |
| Go runtime and standard library | Toolchain from `go.mod` | [LICENSE](licenses/go-LICENSE.txt) |

EPF fixtures contain controlled project BSL with source alongside the compiled
fixtures. Sanitized form fixtures and synthetic authentication vectors are
documented in [fixture provenance](go-onec/testdata/README.md). Official 1C
executables, DLLs, JavaScript bundles and raw captures are not distributed here.
