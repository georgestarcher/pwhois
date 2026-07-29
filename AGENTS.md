# Repository maintainer guide for pwhois

This repository is a Go client and parser for native PWHOIS queries plus
explicit source-specific enrichment providers. This file is the maintainer
contract for automated coding assistants changing this repository. It is not
consumer integration guidance; assistants adding the released module to
another application must start with
[`docs/consumer-agent-guide.md`](docs/consumer-agent-guide.md).

## Scope and contracts

- `pwhois` supports native PWHOIS IP, RouteView, registry, and netblock queries
  plus the explicit `TeamCymruProvider` IP-to-ASN protocol. It is not a generic
  WHOIS, IRR, or RDAP client. Changing only `WhoisServer.Server` or a provider
  hostname does not establish compatibility with another response format; add
  a source-specific implementation and tests first.
- The exported Go API, JSON field names, README, and deterministic tests are
  consumer-facing contracts. Keep them aligned when behavior changes. Preserve
  the serialization conventions corrected in #22 and #25 deliberately; use
  the stable error taxonomy and `OperationError` contract from #34, and see
  issue #36 for compatibility work.
- Treat every server response as untrusted. Handle malformed, truncated,
  delimiter-containing, and oversized values without panics or data loss.
  All lookups enforce their configured `MaxResponseBytes`; preserve the shared
  bounded-reader semantics and the stable error contract.
- Do not add library stdout output. Return errors through the documented
  response types and keep logging, retries, orchestration, and policy in the
  calling application.

## Network behavior

- Prefer the context-aware high-level lookup methods. Each call owns one
  connection from dial through close. A configured `WhoisServer` is safe for
  concurrent high-level calls only while its fields and custom `ContextDialer`
  remain unchanged.
- The deprecated low-level API remains a caller-owned lifecycle:
  call `Connect`, use one connection for one lookup, check the returned response
  error, and close `WhoisServer.Connection`.
- `WhoisServer.Timeout` bounds connection establishment and the full lookup
  write/read exchange. Its zero value uses the five-second default. A shorter
  context deadline takes precedence for high-level calls.
- `TeamCymruProvider` is always explicit, uses one bulk request for grouped
  inputs, and never falls back to native PWHOIS. Its country and registry
  fields are allocation metadata, not geolocation.
- Respect server rate limits. Rate-limit responses and network errors are
  normal caller-visible outcomes, not conditions to hide with automatic retry.

## Development and test data

- Run `go test ./...`, `go vet ./...`, and `go build ./...` before opening a
  pull request. Use `go test -race ./...` when changing concurrency or network
  behavior.
- Default tests must be deterministic and must not contact public PWHOIS, Team
  Cymru, or other provider servers. Native PWHOIS live checks are opt-in:
  `go test -tags=integration ./...`.
- Use reserved and synthetic addresses, ASNs, organizations, and response data
  in tests and documentation. Never commit live/private registry responses,
  contact data, credentials, local paths, or rate-limit artifacts.

## Pull requests

- Keep a change focused and update README or documentation whenever a public
  behavior or contract changes.
- Make signed commits. Before merge, comment `@codex review`, wait for the
  completed Codex response, resolve actionable threads, and require green CI.
