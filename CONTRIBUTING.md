# Contributing

Thanks for improving `pwhois`.

## Scope

`pwhois` is a Go client and parser for native PWHOIS IP, RouteView, registry,
and netblock queries. It is not a generic WHOIS, IRR, or RDAP client. Keep
network policy, retries, logging, storage, scheduling, and application actions
in the consuming application.

## Before opening a pull request

Run the deterministic local checks:

```shell
go test ./...
go vet ./...
go build ./...
```

Also run `go test -race ./...` for concurrency or network changes. Public
PWHOIS checks are opt-in and must not become required CI:

```shell
go test -tags=integration ./...
```

Use a focused, signed commit. Update the README and relevant documentation for
public behavior changes. Before merge, comment `@codex review`, wait for the
completed review, resolve actionable threads, and ensure CI is green.

## Tests and data

Use deterministic loopback tests and synthetic/reserved values. Do not commit
live PWHOIS responses, organization or contact data, credentials, local paths,
or rate-limit artifacts. Keep private experiments under ignored paths such as
`testdata/private/`.

## Public API and release impact

Exported Go symbols, JSON field names, error behavior, and documented network
contracts are consumer-facing. Preserve them deliberately and call out any
compatibility or release impact in the pull request. Stable error sentinels and
typed error metadata require `errors.Is`/`errors.As` compatibility tests and a
release-impact note in the pull request. Formal changelog and release
automation work is tracked in issue #37.
