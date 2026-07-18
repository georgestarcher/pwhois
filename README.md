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

Each lookup uses a TCP connection to a PWHOIS server. Close the connection when the lookup is complete. By default, batch IP lookups accept up to 500 addresses; callers should also respect the selected server's rate limits.

```go
package main

import (
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
		log.Fatal(response.Error)
	}

	for _, record := range response.Response {
		fmt.Printf("%s: AS%s (%s)\n", record.IP, record.OriginAS, record.OrgName)
	}
}
```

The other supported lookup types follow the same pattern. Use a separate connected `WhoisServer` for each lookup.

| Lookup | Query formatter | Lookup method | Response type |
| --- | --- | --- | --- |
| IP | `FormatIpQuery` | `LookupIP` | `IpLookupResponse` |
| RouteView | `FormatRouteViewQuery` | `LookupRouteView` | `BGPLookupResponse` |
| Registry | `FormatRegistryQuery` | `LookupRegistry` | `RegistryLookupResponse` |
| Netblock | `FormatNetblockQuery` | `LookupNetblock` | `NetblockLookupResponse` |

## PWHOIS servers

`SetDefaultValues` configures `whois.pwhois.org:43`. You can set `WhoisServer.Server` and `WhoisServer.Port` before calling `Connect`, but compatibility with alternative servers is not yet validated. Availability and rate limits are controlled by each server operator.

## License

Licensed under the [MIT License](LICENSE). See `LICENSE` for the copyright and permission notice that must accompany copies or substantial portions of the software.
