# pwhois

[![Go Reference](https://pkg.go.dev/badge/github.com/georgestarcher/pwhois.svg)](https://pkg.go.dev/github.com/georgestarcher/pwhois)
[![CI](https://github.com/georgestarcher/pwhois/actions/workflows/go.yml/badge.svg)](https://github.com/georgestarcher/pwhois/actions/workflows/go.yml)

`pwhois` is a Go module for querying a [PWHOIS](https://pwhois.org/) server and parsing its IP, routing, registry, and netblock responses.

Created by George Starcher. The implementation references the original [`whob` source code](https://github.com/irr/whob/blob/master/whob).

## Supported lookups

- Individual or batched IP addresses
- RouteView data for an autonomous system number (ASN)
- Registry data for an ASN
- Netblocks announced by an ASN

## Install

```shell
go get github.com/georgestarcher/pwhois
```

## Usage

Each lookup uses a TCP connection to a PWHOIS server. Close the connection when the lookup is complete. By default, connection establishment and the complete lookup exchange time out after five seconds; set `WhoisServer.Timeout` to use a different `time.Duration`. Responses are limited to 8 MiB by default; set `WhoisServer.MaxResponseBytes` to a positive byte count when an application needs a different bound. Batch IP lookups accept up to 500 addresses; callers should also respect the selected server's rate limits.

```go
package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/georgestarcher/pwhois"
)

func main() {
	server := new(pwhois.WhoisServer)
	server.SetDefaultValues()

	if err := server.Connect(); err != nil {
		log.Fatal(err)
	}
	defer server.Connection.Close()

	query, err := server.FormatIpQuery([]string{"8.8.8.8"})
	if err != nil {
		log.Fatal(err)
	}

	responses := make(chan pwhois.IpLookupResponse, 1)
	server.LookupIP(query, responses)
	response := <-responses

	if response.Error != nil {
		if errors.Is(response.Error, pwhois.ErrRateLimited) {
			// Apply the calling application's rate-limit policy.
		}
		var operationError *pwhois.OperationError
		if errors.As(response.Error, &operationError) {
			log.Printf("%s against %s failed", operationError.Operation, operationError.Server)
		}
		log.Fatal(response.Error)
	}

	for _, record := range response.Response {
		fmt.Printf("%s: AS%s (%s)\n", record.IP, record.OriginAS, record.OrgName)
	}
}
```

The other supported lookup types follow the same pattern. Use a separate connected `WhoisServer` for each lookup.

All four lookup methods enforce the same response-size limit before parsing.
An over-limit response closes its connection and returns a
`*pwhois.ResponseTooLargeError`; callers can detect the stable failure class
with `errors.Is(response.Error, pwhois.ErrResponseTooLarge)`. The error reports
the configured limit but does not include remote response content. The 8 MiB
default provides more than 16 KiB per result for a maximum 500-address IP
batch. RouteView or netblock queries with unusually large legitimate results
may require a higher application-specific limit.

## Error handling

Every formatter, `Connect`, and lookup response error uses a stable class that
can be tested with `errors.Is`; error wording is not an API contract.

| Error class | Meaning |
| --- | --- |
| `ErrInvalidInput` | A query formatter rejected caller input. |
| `ErrConnection` | The connection is absent or a network operation failed. |
| `ErrTimeout` / `ErrCanceled` | The lookup deadline expired or its connection reported cancellation. |
| `ErrRateLimited` | The PWHOIS server reported its query limit. |
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

AI coding assistants integrating this module should use the
[consumer-agent integration guide](docs/consumer-agent-guide.md). Repository
maintainers should use the [maintainer guide](AGENTS.md).

| Lookup | Query formatter | Lookup method | Response type |
| --- | --- | --- | --- |
| IP | `FormatIpQuery` | `LookupIP` | `IpLookupResponse` |
| RouteView | `FormatRouteViewQuery` | `LookupRouteView` | `BGPLookupResponse` |
| Registry | `FormatRegistryQuery` | `LookupRegistry` | `RegistryLookupResponse` |
| Netblock | `FormatNetblockQuery` | `LookupNetblock` | `NetblockLookupResponse` |

## PWHOIS servers

`SetDefaultValues` configures `whois.pwhois.org:43`. You can set `WhoisServer.Server` and `WhoisServer.Port` before calling `Connect`, but compatibility with alternative servers is not yet validated. Availability and rate limits are controlled by each server operator.

## Development

The default checks are deterministic and do not contact public PWHOIS servers:

```shell
go test ./...
go vet ./...
go build ./...
```

Live integration tests use `whois.pwhois.org:43` and must be requested explicitly:

```shell
go test -tags=integration ./...
```

The live tests depend on the public service's availability, response data, and rate limits, so they are not part of the default GitHub Actions workflow.

## JSON output

The explicit JSON-tagged data records (`WhoIs`, `BGPRoute`, `BGPRoutes`, `RegistryRecord`, `Registry`, `NetblockRecord`, and `Netblock`) use normalized snake_case keys and are covered by serialization tests. Postal codes are text so leading zeros and alphanumeric values are preserved.

`WhoisServer` and the channel response wrappers are connection/control types, not JSON output contracts.

## License

Licensed under the [MIT License](LICENSE). See `LICENSE` for the copyright and permission notice that must accompany copies or substantial portions of the software.
