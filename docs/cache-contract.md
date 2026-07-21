# Source-aware cache contract

The cache API separates three responsibilities:

1. A calling application performs one context-aware provider fetch and returns
   normalized JSON plus non-sensitive provenance.
2. A `Cache` implementation stores and retrieves versioned `CacheEnvelope`
   values.
3. `CacheCoordinator` applies source-specific freshness policy and coalesces
   concurrent fetches for the same canonical key.

This is cache infrastructure, not a replacement high-level PWHOIS client. The
existing channel-based lookup methods continue to require a caller-owned
connection. Context-aware high-level lookup work remains tracked in issue #33.

## Canonical keys and envelopes

Build a `CacheKeySpec` with all values that can affect the meaning or shape of
a result:

- source/provider identity;
- endpoint and protocol;
- the provider-specific normalized query;
- behavior-changing options;
- parser version; and
- normalized result schema version.

`CanonicalCacheKey` sorts options and hashes a versioned representation. The
source remains visible in the key prefix for cache operations, while the
digest prevents delimiter ambiguity. The same query against a different
source, endpoint, option set, parser, or schema produces a different key.

Every stored `CacheEnvelope` records that key contract, fetch and expiry times,
normalized JSON, a stable provider error class when applicable, and
provenance. The complete serialized envelope is bounded by `MaxEntryBytes`;
the default is `DefaultMaxResponseBytes` (8 MiB). The envelope deliberately has
no raw-response field.

## Source policies

Every configured source requires its own `SourceCachePolicy`; the coordinator
has no global TTL fallback:

| Field | Use |
| --- | --- |
| `SuccessTTL` | Fresh lifetime for a normalized successful result; must be positive. |
| `NoRecordsTTL` | Negative-cache lifetime for `ErrNoRecords`; zero disables it. |
| `RateLimitedTTL` | Cache lifetime for `ErrRateLimited`; zero disables it. |
| `MaxStale` | Maximum time after expiry that a successful result may be returned by stale-if-error; zero disables fallback. |

Connection, timeout, cancellation, malformed-response, oversized-response,
invalid-input, and unknown errors are not cached. Stale-if-error may use a
successful stale result for a provider timeout, but does not hide cancellation
or deadline expiry of the caller's context. It never falls back to a stale
negative or rate-limit entry.

## Lookup policies

| Policy | Cache read | Provider fetch | Cache write |
| --- | --- | --- | --- |
| `CachePolicyBypass` | Never | Always | Never |
| `CachePolicyReadThrough` | Return a fresh hit | On miss or stale entry | Successful and configured negative/rate-limit results |
| `CachePolicyRefresh` | Never | Always | Successful and configured negative/rate-limit results |
| `CachePolicyFreshOnly` | Return only a fresh hit | Never | Never |
| `CachePolicyStaleIfError` | Return a fresh hit | On miss or stale entry | Same as read-through unless bounded stale data is used |

Fresh-only returns `ErrCacheMiss` or `ErrCacheStale`. A bounded stale fallback
returns no top-level error because the requested fallback succeeded, but sets
`CacheLookupResult.Stale` and `RefreshErrorClass`. Applications that require a
live result must reject stale state explicitly.

Backend read/write failures are represented by `*CacheError` and
`ErrCacheUnavailable`. When a provider result remains usable, it is returned
with `CacheLookupResult.CacheError` set. This preserves useful provider data
without disguising a cache outage as a provider result. A cached negative or
rate-limit hit returns `*CachedProviderError`; use `errors.Is` with
`ErrNoRecords` or `ErrRateLimited` as usual.

If a valid provider result would make the serialized envelope exceed
`MaxEntryBytes`, the result remains usable with `CacheStateProvider` while
`CacheError` matches `ErrCacheEntryTooLarge`; the oversized value is not sent
to the backend.

## Example

The fetch callback below is intentionally application-owned. It stands in for
a context-aware provider operation; it must not be implemented by abandoning a
legacy lookup goroutine when its context is canceled.

```go
cache := pwhois.NewMemoryCache()
coordinator, err := pwhois.NewCacheCoordinator(pwhois.CacheCoordinatorConfig{
	Cache: cache,
	SourcePolicies: map[string]pwhois.SourceCachePolicy{
		"pwhois": {
			SuccessTTL:     6 * time.Hour,
			NoRecordsTTL:   10 * time.Minute,
			RateLimitedTTL: time.Minute,
			MaxStale:       30 * time.Minute,
		},
	},
})
if err != nil {
	return err
}

request := pwhois.CacheRequest{
	Policy: pwhois.CachePolicyReadThrough,
	Key: pwhois.CacheKeySpec{
		Source:              "pwhois",
		Endpoint:            "whois.pwhois.org:43",
		Protocol:            "pwhois",
		NormalizedQuery:     "192.0.2.1",
		Options:             map[string]string{"lookup": "ip"},
		ParserVersion:       "ip-v1",
		ResultSchemaVersion: "whois-v1",
	},
}

result, err := coordinator.Lookup(ctx, request, fetchNormalizedIP)
if err != nil {
	return err
}
if result.CacheError != nil {
	// Report cache health separately from the provider result.
}
if result.Stale {
	// Apply the application's policy for bounded stale data.
}
useNormalizedJSON(result.Envelope.NormalizedResult)
```

## Backend requirements

A `Cache` backend must:

- honor context cancellation;
- treat a missing key as `found=false` rather than fabricating a provider
  error;
- preserve the complete envelope;
- avoid logging or retaining normalized results in error text;
- apply its own capacity/eviction controls; and
- be safe for its documented concurrency model.

`MemoryCache` is concurrency-safe and copies mutable JSON and provenance maps
on reads and writes. It is intentionally process-local and non-persistent.
Distributed stampede protection is a backend/gateway concern; the coordinator
only coalesces identical in-flight fetches inside one process.
