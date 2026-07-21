# Consumer-agent integration guide

This is the self-contained starting guide for an AI coding assistant adding
`github.com/georgestarcher/pwhois` to another Go application. It is consumer
guidance, not permission to change this repository or to invent a server
contract.

## Install and inspect

For a new dependency, install an explicit version that the application has
reviewed. Do not use `@latest` as a substitute for selecting that version:

```shell
go get github.com/georgestarcher/pwhois@v1.0.0
```

If the application already selects `pwhois` in `go.mod`, do not run `go get`.
Inspect that selected version and its exported API instead:

```shell
go list -m -f '{{.Version}}' github.com/georgestarcher/pwhois
go doc github.com/georgestarcher/pwhois
```

Read the selected `go.mod` version and the project README. Do not copy future
APIs from open issues or assume a generic WHOIS, IRR, or RDAP server accepts
the PWHOIS query and response format.

## Choose a lookup

| Need | Build a query with | Execute with | Response type |
| --- | --- | --- | --- |
| IP or IP batch information | `FormatIpQuery` | `LookupIP` | `IpLookupResponse` |
| Routing paths for an ASN | `FormatRouteViewQuery` | `LookupRouteView` | `BGPLookupResponse` |
| Registry data for an ASN | `FormatRegistryQuery` | `LookupRegistry` | `RegistryLookupResponse` |
| Announced netblocks for an ASN | `FormatNetblockQuery` | `LookupNetblock` | `NetblockLookupResponse` |

Use the query formatter instead of constructing wire text manually. ASN
formatters accept decimal input with an optional `AS` prefix. The default IP
batch limit is 500 addresses. Responses are limited to 8 MiB by default.

## Connection and error handling

The application owns the TCP connection. Create a `WhoisServer`, set defaults,
connect, use one connection for one lookup, and close the connection when the
lookup is complete. Every lookup returns its result through a channel, so use a
buffered channel and always check `response.Error`.

```go
server := new(pwhois.WhoisServer)
server.SetDefaultValues()
if err := server.Connect(); err != nil {
	return err
}
defer server.Connection.Close()

query, err := server.FormatIpQuery([]string{"192.0.2.1"})
if err != nil {
	return err
}

responses := make(chan pwhois.IpLookupResponse, 1)
server.LookupIP(query, responses)
response := <-responses
if response.Error != nil {
	return response.Error
}
```

`WhoisServer.Timeout` bounds connection establishment and the full request and
response exchange; its zero value uses the five-second default. Set it to an
application-appropriate `time.Duration` before calling `Connect` when a
different bound is required. The current module has no context-aware high-level
lookup API; that is tracked in issue #33.

`WhoisServer.MaxResponseBytes` bounds response data before parsing. Its zero
value uses `DefaultMaxResponseBytes` (8 MiB), which provides more than 16 KiB
per result in a maximum 500-address IP batch. Set a positive application-
specific value before lookup if unusually large RouteView or netblock results
are expected. If the limit is exceeded, the lookup closes the connection and
returns a `*ResponseTooLargeError`. Detect it with
`errors.Is(err, pwhois.ErrResponseTooLarge)`; do not compare error strings.

Use `errors.Is` to classify every failure: `ErrInvalidInput`, `ErrConnection`,
`ErrTimeout`, `ErrCanceled`, `ErrRateLimited`, `ErrResponseTooLarge`,
`ErrMalformedResponse`, and `ErrNoRecords`. `Connect` and lookup failures are
wrapped in `*OperationError`, so `errors.As` can retrieve the operation and
configured endpoint without losing the underlying transport or parser cause.
Do not compare error strings or expose full server response content in calling
application logs.

Handle connection, write, read, rate-limit, and parser errors as normal
application outcomes. Do not silently retry rate-limit errors, share one
connection among unrelated lookups, or treat a partial result as successful.

## Optional cache orchestration

`CacheCoordinator` is a building block for an application's future
context-aware lookup layer. It does not automatically wrap `LookupIP`,
`LookupRouteView`, `LookupRegistry`, or `LookupNetblock`, and it does not change
their caller-owned connection lifecycle. Do not introduce a goroutine around a
legacy lookup merely to make it fit the coordinator; use the high-level API
tracked in issue #33 when it becomes available, or supply an application-owned
context-aware fetch operation.

If the application uses this cache contract, read the
[cache contract guide](cache-contract.md). In particular, configure a policy
for each source, version parser/result schemas in the key, inspect
`CacheLookupResult.CacheError` and stale metadata, and never put a raw provider
response in `NormalizedResult`.

## Server and data boundaries

`SetDefaultValues` configures `whois.pwhois.org:43`, the tested default. A
different hostname alone does not establish compatibility with a generic WHOIS
or IRR service. Public servers control their availability and rate limits.

Keep credentials, private addresses, live registry responses, contact data,
and rate-limit details out of source code, committed fixtures, and prompts. Use
synthetic/reserved documentation values such as `192.0.2.1` in examples.

## Integration checklist

1. Confirm that native PWHOIS is the required protocol and select one lookup.
2. Inspect the chosen module version and its formatter and response type.
3. Set application-appropriate timeout, response-size, and rate-limit policy.
4. Close the connection, classify every returned error with `errors.Is`, and
   test malformed or unavailable-server behavior in the application.
5. Keep orchestration, retries, logging, credentials, storage, and any action
   taken from results in application code.
