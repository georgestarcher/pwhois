# pwhois documentation

The README and Go package documentation are the authoritative references for
the released API. These guides route readers to the material for their task.

| Audience | Start here | Continue with |
| --- | --- | --- |
| Go application developer | [Project README](../README.md) | [Go package documentation](https://pkg.go.dev/github.com/georgestarcher/pwhois) |
| AI coding assistant integrating the module | [Consumer-agent integration guide](consumer-agent-guide.md) | README usage and the exact version selected in `go.mod` |
| Application cache implementer | [Cache contract guide](cache-contract.md) | `Cache`, `CacheEnvelope`, and `CacheCoordinator` package documentation |
| Repository maintainer | [Maintainer guide](../AGENTS.md) | Deterministic tests and the open repository issues |

## Current validation

Run the default deterministic checks with:

```shell
go test ./...
go vet ./...
go build ./...
```

The available live checks use only the public default native PWHOIS server and
are opt-in:

```shell
go test -tags=integration ./...
```

Required native PWHOIS, Team Cymru, RISwhois, IRR, IANA-bootstrap, RDAP, and
Redis protocol coverage uses only scripted IPv4 loopback servers, an
in-process Redis-compatible server, local HTTP servers, or injected
connections. It exercises connect, request, response, redirect, timeout,
cancellation, response bounds, expiration, and connection cleanup without
depending on a public service.

The repository does not yet have a canonical documentation-validation command;
that work is tracked in issue #28.
