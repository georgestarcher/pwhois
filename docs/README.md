# pwhois documentation

The README and Go package documentation are the authoritative references for
the released API. These guides route readers to the material for their task.

| Audience | Start here | Continue with |
| --- | --- | --- |
| Go application developer | [Project README](../README.md) | [Go package documentation](https://pkg.go.dev/github.com/georgestarcher/pwhois) |
| AI coding assistant integrating the module | [Consumer-agent integration guide](consumer-agent-guide.md) | README usage and the exact version selected in `go.mod` |
| Repository maintainer | [Maintainer guide](../AGENTS.md) | Deterministic tests and the open repository issues |

## Current validation

Run the default deterministic checks with:

```shell
go test ./...
go vet ./...
go build ./...
```

Live checks use the public default PWHOIS server and are opt-in:

```shell
go test -tags=integration ./...
```

The repository does not yet have a canonical documentation-validation command;
that work is tracked in issue #28.
