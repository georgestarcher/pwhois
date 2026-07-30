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
the PWHOIS query and response format. Team Cymru support uses the separate
`TeamCymruProvider`, and RISwhois support uses `RISWhoisProvider`; neither is
a `WhoisServer` endpoint. Published IRR policy uses `IRRProvider` with an
allowlisted endpoint identifier and exact-prefix query. Registration lookups
use `RDAPProvider` with IANA bootstrap discovery rather than a caller-selected
legacy WHOIS hostname.

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

For explicit BGP-origin enrichment from Team Cymru, use
`TeamCymruProvider.LookupIPContext`. It accepts one or more IP addresses and
returns `[]TeamCymruIPResult`. Do not route Team Cymru responses through the
native PWHOIS parsers or treat its RIR allocation country code as geolocation.

For observed BGP route evidence from RIPE RIS collectors, use
`RISWhoisProvider.LookupRouteContext`. It accepts one IP address or CIDR prefix
and returns every matching `RISWhoisRouteResult`. IP queries request all
longest-match origins; prefix queries request exact matches. These are
observations from collected routing tables, not RIR registration, geolocation,
or published IRR policy.

For published route/route6 policy, use
`IRRProvider.LookupRoutePolicyContext`. It accepts only a canonical CIDR
network prefix and returns every exact `IRRRoutePolicyResult` from the selected
allowlisted IRRd endpoint. Do not treat the result as proof of current BGP
propagation, resource ownership, geolocation, sender identity, or independent
RPKI validation.

For registration/allocation context, use `RDAPProvider.LookupIPContext` or
`LookupASNContext`. These return privacy-minimized `RDAPIPResult` or
`RDAPASNResult` values. They omit complete jCards, personal names, contact
details, addresses, event actors, raw JSON, and redaction paths. Do not infer
current routing or geolocation from RDAP registration data.

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
connection. A custom `ContextDialer` must itself be concurrency-safe and must
honor its context. This hook is intended for deterministic tests and
controlled transport integration.

`TeamCymruProvider` follows the same owned-connection and concurrency model.
Its zero value uses `whois.cymru.com:43`, a five-second timeout, a
1,000-address batch limit, and the shared 8 MiB response limit. It sends one
bulk request for all deduplicated inputs and does not automatically retry,
fall back, or cache.

`RISWhoisProvider` also follows that owned-connection and concurrency model.
Its zero value uses `riswhois.ripe.net:43`, a five-second timeout, and the
shared 8 MiB response limit. It performs one query, preserves multiple origins,
and does not automatically retry, fall back, or cache.

`IRRProvider` uses the same owned-connection model. Its zero value selects
`IRREndpointRADb`; `IRREndpointARIN` and `IRREndpointNTT` are also supported.
Unknown endpoint identifiers return `ErrInvalidInput` before dialing. Every
lookup sends one RIPE-style `-T route,route6 -x <prefix>` request and never
retries, falls back, or caches automatically.

`RDAPProvider` applies one deadline to bootstrap resolution and the final
lookup. Its zero value uses the shared cached IANA bootstrap resolver, HTTPS,
an 8 MiB final-response bound, and at most three manually followed referrals.
Use `NewRDAPProvider(client)` when both bootstrap and authoritative requests
must use a custom HTTP client with a provider-owned bootstrap cache.
Cross-origin referrals must retain the same IP or ASN and target an authority
listed in the trusted bootstrap document. Do not enable insecure HTTP or
private-network targets outside controlled local tests.

`WhoisServer.MaxResponseBytes` bounds response data before parsing. Its zero
value uses `DefaultMaxResponseBytes` (8 MiB), which provides more than 16 KiB
per result in a maximum 500-address IP batch. Set a positive application-
specific value before lookup if unusually large RouteView or netblock results
are expected. If the limit is exceeded, the lookup closes the connection and
returns a `*ResponseTooLargeError`. Detect it with
`errors.Is(err, pwhois.ErrResponseTooLarge)`; do not compare error strings.

Use `errors.Is` to classify every failure: `ErrInvalidInput`, `ErrConnection`,
`ErrTimeout`, `ErrCanceled`, `ErrRateLimited`, `ErrProviderRejected`,
`ErrResponseTooLarge`, `ErrMalformedResponse`, and `ErrNoRecords`. `Connect`
and lookup failures are wrapped in `*OperationError`, so `errors.As` can
retrieve the operation and configured endpoint without losing the underlying
transport or parser cause. Do not compare error strings or expose full server
response content in calling application logs.

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

`TeamCymruProvider.CacheKeySpec` builds the provider-specific cache identity.
Configure a separate `SourceCachePolicy` for `TeamCymruSource`; do not reuse a
native PWHOIS key or silently merge results from the two sources.

`RISWhoisProvider.CacheKeySpec` also records whether the normalized query is a
longest-match IP lookup or an exact prefix lookup. Configure a separate policy
for `RISWhoisSource`. A 15-minute success TTL, 5-minute no-record TTL,
1-minute rate-limit TTL, and 30-minute maximum successful-stale window are a
reasonable short-lived starting policy; callers needing current routing
evidence should shorten or bypass it.

`IRRProvider.CacheKeySpec` records the allowlisted endpoint identity, exact
query mode, route/route6 object types, protocol, parser, and result schema.
Configure a separate policy for `IRRSource`. A conservative starting point is
a 1-hour success TTL, 15-minute no-record TTL, 1-minute rate-limit TTL, and
6-hour maximum successful-stale window; applications sensitive to recent
policy changes should shorten or bypass it.

`RDAPProvider.IPCacheKeySpec` and `ASNCacheKeySpec` include the bootstrap
identity, object type, referral bound, transport/target scope, privacy profile,
parser, and result schema. Configure a separate policy for `RDAPSource`. A
24-hour success TTL, 15-minute no-record TTL, 1-minute rate-limit TTL, and
24-hour maximum successful-stale window are a reasonable
registration-enrichment starting point.

If the application uses this cache contract, read the
[cache contract guide](cache-contract.md). In particular, configure a policy
for each source, version parser/result schemas in the key, inspect
`CacheLookupResult.CacheError` and stale metadata, and never put a raw provider
response in `NormalizedResult`.

For process-local caching, use `NewMemoryCache`. For shared Redis storage, use
`NewRedisCache` with an explicit non-empty key prefix and either address/URL
configuration or a caller-owned go-redis client. Do not load Redis credentials
implicitly in integration code or include Redis URLs in logs. Configure TLS
and ACL credentials for networked deployments. `RedisCache.Close` closes only
a client it created.

The Redis key expires at the envelope's freshness deadline unless
`StaleRetention` is configured. A non-zero retention only preserves the
envelope for the coordinator's bounded stale-if-error decision; it does not
extend freshness. Keep retention at or below the largest applicable
`SourceCachePolicy.MaxStale`. Redis failures appear separately through
`CacheLookupResult.CacheError` and must not be treated as provider failures.

## Server and data boundaries

`SetDefaultValues` configures `whois.pwhois.org:43`, the tested native PWHOIS
default. `TeamCymruProvider` explicitly configures the separate Team Cymru
protocol, and `RISWhoisProvider` explicitly configures RISwhois RPSL routing
observations. `IRRProvider` explicitly selects one allowlisted IRRd endpoint
and supports only exact route/route6 prefix queries. `RDAPProvider` explicitly
uses IANA bootstrap registries and bounded referral validation. A different
hostname alone does not establish compatibility with a generic WHOIS or
port-43 service. Public providers control their availability and rate limits,
and port 43 sends queries in plaintext.

Keep credentials, private addresses, live registry responses, contact data,
and rate-limit details out of source code, committed fixtures, and prompts. Use
synthetic/reserved documentation values such as `192.0.2.1` in examples.
Only send an address to a third-party provider when the application's privacy
policy permits it.

## Integration checklist

1. Select native PWHOIS, Team Cymru, RISwhois, IRR, or RDAP based on the
   required data source and semantics.
2. Inspect the chosen module version, lookup method, and response type.
3. Set application-appropriate timeout, response-size, and rate-limit policy.
4. Classify every returned error with `errors.Is`, and test cancellation,
   malformed responses, and unavailable-server behavior in the application.
5. Keep orchestration, retries, logging, credentials, storage, and any action
   taken from results in application code.
