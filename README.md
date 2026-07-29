# pwhois

[![Go Reference](https://pkg.go.dev/badge/github.com/georgestarcher/pwhois.svg)](https://pkg.go.dev/github.com/georgestarcher/pwhois)
[![CI](https://github.com/georgestarcher/pwhois/actions/workflows/go.yml/badge.svg)](https://github.com/georgestarcher/pwhois/actions/workflows/go.yml)

`pwhois` is a Go module for querying a [PWHOIS](https://pwhois.org/)
server and parsing its IP, routing, registry, and netblock responses. It also
provides an explicit, source-specific client for
[Team Cymru IP-to-ASN mapping](https://www.team-cymru.com/ip-asn-mapping).

Created by George Starcher. The implementation references the original [`whob` source code](https://github.com/irr/whob/blob/master/whob).

## Supported lookups

- Individual or batched IP addresses
- RouteView data for an autonomous system number (ASN)
- Registry data for an ASN
- Netblocks announced by an ASN
- Team Cymru IP-to-origin-ASN and prefix enrichment

## Install

```shell
go get github.com/georgestarcher/pwhois
```

## Usage

The context-aware lookup methods format the query, establish a dedicated TCP
connection, complete the exchange, parse the response, and close the connection
before returning. The zero-value `WhoisServer` uses the documented defaults.
By default, connection establishment and the complete lookup operation time out
after five seconds; set `WhoisServer.Timeout` to use a different
`time.Duration`. A shorter caller deadline takes precedence, and cancellation
interrupts an in-progress dial, write, or read.

Responses are limited to 8 MiB by default; set
`WhoisServer.MaxResponseBytes` to a positive byte count when an application
needs a different bound. Batch IP lookups accept up to 500 addresses. Callers
should also respect the selected server's rate limits.

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/georgestarcher/pwhois"
)

func main() {
	server := pwhois.WhoisServer{}
	records, err := server.LookupIPContext(
		context.Background(),
		[]string{"192.0.2.1"},
	)
	if err != nil {
		if errors.Is(err, pwhois.ErrRateLimited) {
			// Apply the calling application's rate-limit policy.
		}
		var operationError *pwhois.OperationError
		if errors.As(err, &operationError) {
			log.Printf("%s against %s failed", operationError.Operation, operationError.Server)
		}
		log.Fatal(err)
	}

	for _, record := range records {
		fmt.Printf("%s: AS%s (%s)\n", record.IP, record.OriginAS, record.OrgName)
	}
}
```

The other supported lookup types follow the same pattern. A configured
`WhoisServer` may be shared by concurrent high-level calls as long as its
fields—and any custom `Dialer`—are not mutated while calls are
running. Every call uses an independent connection. The older `Connect`,
`Connection`, query-formatter, channel-response API remains available for
compatibility but is deprecated for new integrations; callers using it must
continue to use one connected server per lookup and close the connection.

All four lookup methods enforce the same response-size limit before parsing.
An over-limit response closes its connection and returns a
`*pwhois.ResponseTooLargeError`; callers can detect the stable failure class
with `errors.Is(err, pwhois.ErrResponseTooLarge)`. The error reports
the configured limit but does not include remote response content. The 8 MiB
default provides more than 16 KiB per result for a maximum 500-address IP
batch. RouteView or netblock queries with unusually large legitimate results
may require a higher application-specific limit.

## Error handling

Every formatter, connection, and lookup error uses a stable class that can be
tested with `errors.Is`; error wording is not an API contract.

| Error class | Meaning |
| --- | --- |
| `ErrInvalidInput` | A query formatter rejected caller input. |
| `ErrConnection` | The connection is absent or a network operation failed. |
| `ErrTimeout` / `ErrCanceled` | The lookup deadline expired or its connection reported cancellation. |
| `ErrRateLimited` | A provider reported its query limit. |
| `ErrProviderRejected` | A provider rejected the query. |
| `ErrResponseTooLarge` | The response exceeded `MaxResponseBytes`. |
| `ErrMalformedResponse` | A non-empty response could not be parsed safely. |
| `ErrNoRecords` | The server returned no records for the lookup. |

`Connect` and lookup methods wrap failures in `*pwhois.OperationError`, which
contains the operation and configured endpoint while preserving the stable
class and underlying transport/parser error. Use `errors.As` only when that
additional context is useful, as shown in the example above.

Rate-limit and remote parser failures never include the full server response
in the returned error. `*pwhois.ResponseTooLargeError` additionally reports
the configured byte limit.

## Cache foundation

The module includes a source-aware cache contract for applications that build
context-aware lookup orchestration. `CacheCoordinator` supports bypass,
read-through, forced refresh, fresh-only, and bounded stale-if-error policies.
It also coalesces concurrent misses for one canonical key within a process.

The coordinator does **not** automatically wrap the four high-level lookup
methods. A calling application supplies a context-aware fetch function, a
`Cache` backend, and an explicit `SourceCachePolicy` for every provider/source.
This keeps caching and retry policy in the application rather than silently
changing lookup behavior.

Cache keys include the source, endpoint, protocol, normalized query, options,
parser version, and result schema version. Stored `CacheEnvelope` values
contain bounded normalized JSON, timestamps, provider error class, and
provenance; there is no raw-response field. `MemoryCache` is available for
process-local use. File, gateway, and Redis implementations can satisfy the
same `Cache` interface without changing lookup policy.

See the [cache contract guide](docs/cache-contract.md) for policy semantics,
error handling, and an integration example.

AI coding assistants integrating this module should use the
[consumer-agent integration guide](docs/consumer-agent-guide.md). Repository
maintainers should use the [maintainer guide](AGENTS.md).

| Lookup | Preferred high-level method | Result type |
| --- | --- | --- | --- |
| IP | `LookupIPContext` | `[]WhoIs` |
| RouteView | `LookupRouteViewContext` | `BGPRoutes` |
| Registry | `LookupRegistryContext` | `RegistryRecord` |
| Netblock | `LookupNetblockContext` | `NetblockRecord` |

## Team Cymru IP-to-ASN provider

`TeamCymruProvider` uses Team Cymru's distinct bulk TCP protocol and
pipe-delimited response format. It is not a replacement hostname for
`WhoisServer`. The provider validates and deduplicates all inputs, sends one
bounded bulk request even for a single address, and returns
`[]TeamCymruIPResult` with explicit source, endpoint, and fetch-time
provenance.

```go
provider := pwhois.TeamCymruProvider{
	BatchMaxSize: 1000,
}
results, err := provider.LookupIPContext(context.Background(), []string{
	"192.0.2.1",
	"198.51.100.2",
})
```

The zero value uses `whois.cymru.com:43`, a five-second timeout, a
1,000-address batch limit, and the shared 8 MiB response limit. The provider
never retries, falls back to PWHOIS, or automatically caches results.

Team Cymru describes the returned country code, registry, and allocation date
as RIR allocation metadata and explicitly warns that the service is not
geolocation. The service recommends one bulk request for groups of addresses
and warns against high volumes of individual WHOIS queries. It reports that
its underlying mapping data is updated at four-hour intervals. Keep cache TTL
and rate-limit policy explicit in the calling application.
`TeamCymruProvider.CacheKeySpec` returns a source-, endpoint-, protocol-,
parser-, and schema-aware identity for use with `CacheCoordinator`.

`FetchedAt` records when this client received the response. It is not a claim
about when the route was first observed by a collector.

Port 43 traffic is plaintext. Do not send an address to this third-party
provider unless the calling application's privacy and data-handling policy
allows it.

## Providers and servers

`SetDefaultValues` configures `whois.pwhois.org:43`. You can set `WhoisServer.Server` and `WhoisServer.Port` before calling `Connect`, but compatibility with alternative servers is not yet validated. Availability and rate limits are controlled by each server operator.

`TeamCymruProvider` is the only additional protocol-specific provider
currently implemented. Generic WHOIS, IRR, and RDAP endpoints are not
drop-in-compatible with either client.

## Development

The default checks are deterministic and do not contact public PWHOIS or Team
Cymru servers:

```shell
go test ./...
go vet ./...
go build ./...
```

The required test suite includes an IPv4 loopback-only scripted PWHOIS server
that verifies the complete connect, exact request, response, orderly EOF, and
connection cleanup lifecycle for every supported lookup type. It covers both
automatic high-level cleanup and the deprecated caller-owned lifecycle.
Malformed, truncated, rate-limited, oversized, and non-responsive server paths
also use deterministic local fixtures.

Live integration tests use `whois.pwhois.org:43` and must be requested explicitly:

```shell
go test -tags=integration ./...
```

The live tests depend on the public service's availability, response data, and rate limits, so they are not part of the default GitHub Actions workflow.

## JSON output

The explicit JSON-tagged data records (`WhoIs`, `BGPRoute`, `BGPRoutes`,
`RegistryRecord`, `Registry`, `NetblockRecord`, `Netblock`, and
`TeamCymruIPResult`) use normalized snake_case keys and are covered by
serialization tests. Postal codes are text so leading zeros and alphanumeric
values are preserved.

`WhoisServer`, `TeamCymruProvider`, and the channel response wrappers are
connection/control types, not JSON output contracts.

## License

Licensed under the [MIT License](LICENSE). See `LICENSE` for the copyright and permission notice that must accompany copies or substantial portions of the software.
