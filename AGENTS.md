# Repository maintainer guide for pwhois

This repository is a Go client and parser for native PWHOIS queries. This file
is the maintainer contract for automated coding assistants changing this
repository. It is not consumer integration guidance; assistants adding the
released module to another application must start with
[`docs/consumer-agent-guide.md`](docs/consumer-agent-guide.md).

## Scope and contracts

- `pwhois` supports PWHOIS IP, RouteView, registry, and netblock queries.
  It is not a generic WHOIS, IRR, or RDAP client. Changing only
  `WhoisServer.Server` does not establish compatibility with another server or
  response format; add format-specific implementation and tests first.
- The exported Go API, JSON field names, README, and deterministic tests are
  consumer-facing contracts. Keep them aligned when behavior changes. Preserve
  the serialization conventions corrected in #22 and #25 deliberately; see
  the tracked error and compatibility work in issues #34 and #36.
- Treat every server response as untrusted. Handle malformed, truncated,
  delimiter-containing, and oversized values without panics or data loss.
  Response-size limits are tracked in #32.
- Do not add library stdout output. Return errors through the documented
  response types and keep logging, retries, orchestration, and policy in the
  calling application.

## Network behavior

- A caller owns `WhoisServer.Connection`: call `Connect`, use one connection
  for one lookup, check the returned response error, and close the connection.
- `WhoisServer.Timeout` bounds connection establishment and the full lookup
  write/read exchange. Its zero value uses the five-second default. The current
  API has no context-aware high-level lookup; do not invent one. See #33 for
  that future API work.
- Respect server rate limits. Rate-limit responses and network errors are
  normal caller-visible outcomes, not conditions to hide with automatic retry.

## Development and test data

- Run `go test ./...`, `go vet ./...`, and `go build ./...` before opening a
  pull request. Use `go test -race ./...` when changing concurrency or network
  behavior.
- Default tests must be deterministic and must not contact public PWHOIS
  servers. Live checks are opt-in: `go test -tags=integration ./...`.
- Use reserved and synthetic addresses, ASNs, organizations, and response data
  in tests and documentation. Never commit live/private registry responses,
  contact data, credentials, local paths, or rate-limit artifacts.

## Pull requests

- Keep a change focused and update README or documentation whenever a public
  behavior or contract changes.
- Make signed commits. Before merge, comment `@codex review`, wait for the
  completed Codex response, resolve actionable threads, and require green CI.
