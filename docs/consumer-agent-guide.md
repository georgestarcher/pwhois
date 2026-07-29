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

| Need | Preferred method | Result type |
| --- | --- | --- | --- |
| IP or IP batch information | `LookupIPContext` | `[]WhoIs` |
| Routing paths for an ASN | `LookupRouteViewContext` | `BGPRoutes` |
| Registry data for an ASN | `LookupRegistryContext` | `RegistryRecord` |
| Announced netblocks for an ASN | `LookupNetblockContext` | `NetblockRecord` |

Pass domain inputs to the high-level method instead of constructing wire text.
ASN lookups accept decimal input with an optional `AS` prefix. The default IP
batch limit is 500 addresses. Responses are limited to 8 MiB by default.

## Connection and error handling

Each high-level call owns its TCP connection from dial through close and returns
its result synchronously. The zero-value `WhoisServer` applies the documented
defaults.

```go
server := pwhois.WhoisServer{}
records, err := server.LookupIPContext(ctx, []string{"192.0.2.1"})
if err != nil {
	return err
}
```

`WhoisServer.Timeout` bounds connection establishment and the full request and
response exchange; its zero value uses the five-second default. Set it to an
application-appropriate `time.Duration` before starting a lookup when a
different bound is required. A shorter context deadline takes precedence.
Cancellation interrupts an in-progress dial, write, or read.

A configured `WhoisServer` is safe for concurrent high-level calls when the
application does not mutate its fields during use. Each call has an independent
connection. A custom `DialContext` hook must itself be concurrency-safe and
must honor its context. This hook is intended for deterministic tests and
controlled transport integration.

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
application outcomes. Do not silently retry rate-limit errors or treat a
partial result as successful.

The exported query formatters, `Connect`, `Connection`, channel lookup methods,
and channel response wrappers remain for compatibility with existing
integrations. They are deprecated for new code. If maintaining a legacy
integration, use one connected `WhoisServer` for one lookup and close its
`Connection`.

## Optional cache orchestration

`CacheCoordinator` does not automatically wrap `LookupIPContext`,
`LookupRouteViewContext`, `LookupRegistryContext`, or
`LookupNetblockContext`. Supply a high-level lookup as the application's
context-aware fetch operation and retain explicit source policy.

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
4. Classify every returned error with `errors.Is`, and test cancellation,
   malformed responses, and unavailable-server behavior in the application.
5. Keep orchestration, retries, logging, credentials, storage, and any action
   taken from results in application code.
