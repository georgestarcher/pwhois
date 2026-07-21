package pwhois

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// CacheEnvelopeVersion identifies the on-disk/wire representation used by
	// cache backends. Backends must preserve this value with each entry.
	CacheEnvelopeVersion = 1
	cacheKeyVersion      = 1
)

// Stable cache error classes. Cache errors are deliberately separate from
// provider errors so a backend failure cannot be mistaken for a PWHOIS result.
var (
	ErrCacheMiss          = errors.New("pwhois cache miss")
	ErrCacheStale         = errors.New("pwhois cache entry is stale")
	ErrCacheUnavailable   = errors.New("pwhois cache unavailable")
	ErrInvalidCacheEntry  = errors.New("pwhois invalid cache entry")
	ErrCacheEntryTooLarge = errors.New("pwhois cache entry exceeds maximum size")
)

// CacheError adds the failed cache operation and canonical key while
// preserving its stable class through errors.Is and errors.As.
type CacheError struct {
	Operation string
	Key       string
	Err       error
}

func (err *CacheError) Error() string {
	if err.Key == "" {
		return fmt.Sprintf("pwhois cache %s: %v", err.Operation, err.Err)
	}
	return fmt.Sprintf("pwhois cache %s for %s: %v", err.Operation, err.Key, err.Err)
}

func (err *CacheError) Unwrap() error {
	return err.Err
}

// CacheEntryTooLargeError reports the configured cache-entry limit without
// retaining or exposing the normalized result.
type CacheEntryTooLargeError struct {
	Limit int64
}

func (err *CacheEntryTooLargeError) Error() string {
	return fmt.Sprintf("%s: limit %d bytes", ErrCacheEntryTooLarge, err.Limit)
}

func (err *CacheEntryTooLargeError) Unwrap() error {
	return ErrCacheEntryTooLarge
}

// Cache is the storage contract implemented by in-memory, file, gateway, or
// Redis-backed caches. Get reports a miss with found=false, not ErrCacheMiss.
// Backend failures are returned as errors and classified by CacheCoordinator.
type Cache interface {
	Get(ctx context.Context, key string) (entry CacheEnvelope, found bool, err error)
	Set(ctx context.Context, key string, entry CacheEnvelope) error
	Delete(ctx context.Context, key string) error
}

// CacheClock allows deterministic expiry and stale-window tests.
type CacheClock interface {
	Now() time.Time
}

type systemCacheClock struct{}

func (systemCacheClock) Now() time.Time { return time.Now() }

// CacheKeySpec contains every value that can change the meaning or shape of a
// normalized result. NormalizedQuery must already be in the provider-specific
// canonical form chosen by the caller.
type CacheKeySpec struct {
	Source              string
	Endpoint            string
	Protocol            string
	NormalizedQuery     string
	Options             map[string]string
	ParserVersion       string
	ResultSchemaVersion string
}

type cacheKeyOption struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type canonicalCacheKey struct {
	Version             int              `json:"version"`
	Source              string           `json:"source"`
	Endpoint            string           `json:"endpoint"`
	Protocol            string           `json:"protocol"`
	NormalizedQuery     string           `json:"normalized_query"`
	Options             []cacheKeyOption `json:"options"`
	ParserVersion       string           `json:"parser_version"`
	ResultSchemaVersion string           `json:"result_schema_version"`
}

func normalizeCacheKeySpec(spec CacheKeySpec) (CacheKeySpec, error) {
	spec.Source = strings.ToLower(strings.TrimSpace(spec.Source))
	spec.Endpoint = strings.ToLower(strings.TrimSpace(spec.Endpoint))
	spec.Protocol = strings.ToLower(strings.TrimSpace(spec.Protocol))
	spec.NormalizedQuery = strings.TrimSpace(spec.NormalizedQuery)
	spec.ParserVersion = strings.TrimSpace(spec.ParserVersion)
	spec.ResultSchemaVersion = strings.TrimSpace(spec.ResultSchemaVersion)

	switch {
	case spec.Source == "":
		return CacheKeySpec{}, invalidInputError("cache source is required")
	case spec.Endpoint == "":
		return CacheKeySpec{}, invalidInputError("cache endpoint is required")
	case spec.Protocol == "":
		return CacheKeySpec{}, invalidInputError("cache protocol is required")
	case spec.NormalizedQuery == "":
		return CacheKeySpec{}, invalidInputError("normalized cache query is required")
	case spec.ParserVersion == "":
		return CacheKeySpec{}, invalidInputError("cache parser version is required")
	case spec.ResultSchemaVersion == "":
		return CacheKeySpec{}, invalidInputError("cache result schema version is required")
	}

	return spec, nil
}

// CanonicalCacheKey returns a deterministic, source-aware cache key. The
// digest prevents delimiter ambiguity while the prefix makes the key format
// and source recognizable to cache operators.
func CanonicalCacheKey(spec CacheKeySpec) (string, error) {
	normalized, err := normalizeCacheKeySpec(spec)
	if err != nil {
		return "", err
	}

	optionNames := make([]string, 0, len(normalized.Options))
	for name := range normalized.Options {
		optionNames = append(optionNames, name)
	}
	sort.Strings(optionNames)

	options := make([]cacheKeyOption, 0, len(optionNames))
	for _, name := range optionNames {
		options = append(options, cacheKeyOption{Name: name, Value: normalized.Options[name]})
	}

	payload, err := json.Marshal(canonicalCacheKey{
		Version:             cacheKeyVersion,
		Source:              normalized.Source,
		Endpoint:            normalized.Endpoint,
		Protocol:            normalized.Protocol,
		NormalizedQuery:     normalized.NormalizedQuery,
		Options:             options,
		ParserVersion:       normalized.ParserVersion,
		ResultSchemaVersion: normalized.ResultSchemaVersion,
	})
	if err != nil {
		return "", fmt.Errorf("build canonical cache key: %w", err)
	}

	digest := sha256.Sum256(payload)
	return fmt.Sprintf("pwhois-cache:v%d:%s:%s", cacheKeyVersion, normalized.Source, hex.EncodeToString(digest[:])), nil
}

// ProviderErrorClass is the serializable form of a stable provider error.
// It records only the class, never error text or remote response content.
type ProviderErrorClass string

const (
	ProviderErrorNone              ProviderErrorClass = ""
	ProviderErrorInvalidInput      ProviderErrorClass = "invalid_input"
	ProviderErrorConnection        ProviderErrorClass = "connection"
	ProviderErrorTimeout           ProviderErrorClass = "timeout"
	ProviderErrorCanceled          ProviderErrorClass = "canceled"
	ProviderErrorRateLimited       ProviderErrorClass = "rate_limited"
	ProviderErrorResponseTooLarge  ProviderErrorClass = "response_too_large"
	ProviderErrorMalformedResponse ProviderErrorClass = "malformed_response"
	ProviderErrorNoRecords         ProviderErrorClass = "no_records"
	ProviderErrorUnknown           ProviderErrorClass = "unknown"
)

// ClassifyProviderError converts a provider error into a stable serializable
// class. Unknown errors remain visibly unknown and are never negative-cached.
func ClassifyProviderError(err error) ProviderErrorClass {
	if err == nil {
		return ProviderErrorNone
	}

	switch {
	case errors.Is(err, ErrInvalidInput):
		return ProviderErrorInvalidInput
	case errors.Is(err, ErrConnection):
		return ProviderErrorConnection
	case errors.Is(err, ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		return ProviderErrorTimeout
	case errors.Is(err, ErrCanceled), errors.Is(err, context.Canceled):
		return ProviderErrorCanceled
	case errors.Is(err, ErrRateLimited):
		return ProviderErrorRateLimited
	case errors.Is(err, ErrResponseTooLarge):
		return ProviderErrorResponseTooLarge
	case errors.Is(err, ErrMalformedResponse):
		return ProviderErrorMalformedResponse
	case errors.Is(err, ErrNoRecords):
		return ProviderErrorNoRecords
	default:
		return ProviderErrorUnknown
	}
}

func providerErrorSentinel(class ProviderErrorClass) error {
	switch class {
	case ProviderErrorInvalidInput:
		return ErrInvalidInput
	case ProviderErrorConnection:
		return ErrConnection
	case ProviderErrorTimeout:
		return ErrTimeout
	case ProviderErrorCanceled:
		return ErrCanceled
	case ProviderErrorRateLimited:
		return ErrRateLimited
	case ProviderErrorResponseTooLarge:
		return ErrResponseTooLarge
	case ProviderErrorMalformedResponse:
		return ErrMalformedResponse
	case ProviderErrorNoRecords:
		return ErrNoRecords
	default:
		return nil
	}
}

// CachedProviderError reports a provider failure reconstructed from a cached
// negative or rate-limit entry. errors.Is continues to match the stable class.
type CachedProviderError struct {
	Class     ProviderErrorClass
	Source    string
	FetchedAt time.Time
}

func (err *CachedProviderError) Error() string {
	return fmt.Sprintf("cached %s provider result from %s at %s", err.Class, err.Source, err.FetchedAt.Format(time.RFC3339))
}

func (err *CachedProviderError) Unwrap() error {
	return providerErrorSentinel(err.Class)
}

// CacheProvenance identifies where a normalized result came from. Details
// should contain non-sensitive provider metadata, never raw response content.
type CacheProvenance struct {
	Provider string            `json:"provider"`
	Endpoint string            `json:"endpoint"`
	Protocol string            `json:"protocol"`
	Details  map[string]string `json:"details,omitempty"`
}

// CacheEnvelope is the versioned value stored by a Cache implementation.
// NormalizedResult is parsed, bounded JSON; the contract has no raw-response
// field so backends do not retain provider payloads by default.
type CacheEnvelope struct {
	Version             int                `json:"version"`
	Key                 string             `json:"key"`
	Source              string             `json:"source"`
	Endpoint            string             `json:"endpoint"`
	Protocol            string             `json:"protocol"`
	NormalizedQuery     string             `json:"normalized_query"`
	ParserVersion       string             `json:"parser_version"`
	FetchedAt           time.Time          `json:"fetched_at"`
	ExpiresAt           time.Time          `json:"expires_at"`
	ResultSchemaVersion string             `json:"result_schema_version"`
	NormalizedResult    json.RawMessage    `json:"normalized_result,omitempty"`
	ProviderErrorClass  ProviderErrorClass `json:"provider_error_class,omitempty"`
	Provenance          CacheProvenance    `json:"provenance"`
}

// CachePolicy controls whether a lookup may read, refresh, or bypass cache.
type CachePolicy string

const (
	CachePolicyBypass       CachePolicy = "bypass"
	CachePolicyReadThrough  CachePolicy = "read-through"
	CachePolicyRefresh      CachePolicy = "refresh"
	CachePolicyFreshOnly    CachePolicy = "fresh-only"
	CachePolicyStaleIfError CachePolicy = "stale-if-error"
)

func (policy CachePolicy) valid() bool {
	switch policy {
	case CachePolicyBypass, CachePolicyReadThrough, CachePolicyRefresh, CachePolicyFreshOnly, CachePolicyStaleIfError:
		return true
	default:
		return false
	}
}

// SourceCachePolicy gives each provider/source its own success, negative,
// rate-limit, and bounded-staleness lifetimes. A zero negative or rate-limit
// TTL disables caching for that class.
type SourceCachePolicy struct {
	SuccessTTL     time.Duration
	NoRecordsTTL   time.Duration
	RateLimitedTTL time.Duration
	MaxStale       time.Duration
}

func (policy SourceCachePolicy) validate(source string) error {
	if policy.SuccessTTL <= 0 {
		return invalidInputError(fmt.Sprintf("cache source %q requires a positive success TTL", source))
	}
	if policy.NoRecordsTTL < 0 || policy.RateLimitedTTL < 0 || policy.MaxStale < 0 {
		return invalidInputError(fmt.Sprintf("cache source %q TTLs cannot be negative", source))
	}
	return nil
}

// CacheRequest combines the canonical key inputs with the desired cache
// behavior. It does not perform a network lookup itself.
type CacheRequest struct {
	Key    CacheKeySpec
	Policy CachePolicy
}

// CacheFetchResult is returned by a caller-supplied provider function. Only a
// normalized JSON result and provenance can enter the cache envelope.
type CacheFetchResult struct {
	NormalizedResult json.RawMessage
	Provenance       CacheProvenance
}

// CacheFetchFunc performs one context-aware provider operation for Lookup.
type CacheFetchFunc func(context.Context) (CacheFetchResult, error)

// CacheState describes where CacheLookupResult came from.
type CacheState string

const (
	CacheStateBypassed  CacheState = "bypassed"
	CacheStateHit       CacheState = "hit"
	CacheStateRefreshed CacheState = "refreshed"
	CacheStateProvider  CacheState = "provider"
	CacheStateStale     CacheState = "stale"
)

// CacheLookupResult makes cache and fallback behavior explicit. CacheError is
// set when a provider result remains usable despite a backend read/write
// failure. RefreshErrorClass is set when stale-if-error returned bounded stale
// data after a failed provider refresh.
type CacheLookupResult struct {
	Envelope          CacheEnvelope
	State             CacheState
	CacheHit          bool
	Stale             bool
	Coalesced         bool
	CacheError        error
	RefreshErrorClass ProviderErrorClass
}

// CacheCoordinatorConfig configures source-aware cache orchestration.
type CacheCoordinatorConfig struct {
	Cache          Cache
	Clock          CacheClock
	SourcePolicies map[string]SourceCachePolicy
	// MaxEntryBytes bounds the complete serialized envelope. A value less than
	// or equal to zero uses DefaultMaxResponseBytes.
	MaxEntryBytes int64
}

type cacheCall struct {
	done    chan struct{}
	result  CacheLookupResult
	err     error
	waiters int
}

// CacheCoordinator applies cache policies and coalesces concurrent provider
// fetches for the same canonical key within one process.
type CacheCoordinator struct {
	cache          Cache
	clock          CacheClock
	sourcePolicies map[string]SourceCachePolicy
	maxEntryBytes  int64

	mu       sync.Mutex
	inflight map[string]*cacheCall
}

// NewCacheCoordinator validates configuration and returns a reusable
// coordinator. SourcePolicies must explicitly name every source; there is no
// global TTL fallback.
func NewCacheCoordinator(config CacheCoordinatorConfig) (*CacheCoordinator, error) {
	if config.Cache == nil {
		return nil, invalidInputError("cache backend is required")
	}
	if len(config.SourcePolicies) == 0 {
		return nil, invalidInputError("at least one source-specific cache policy is required")
	}

	policies := make(map[string]SourceCachePolicy, len(config.SourcePolicies))
	for source, policy := range config.SourcePolicies {
		normalizedSource := strings.ToLower(strings.TrimSpace(source))
		if normalizedSource == "" {
			return nil, invalidInputError("cache policy source is required")
		}
		if err := policy.validate(normalizedSource); err != nil {
			return nil, err
		}
		if _, duplicate := policies[normalizedSource]; duplicate {
			return nil, invalidInputError(fmt.Sprintf("duplicate cache policy source %q", normalizedSource))
		}
		policies[normalizedSource] = policy
	}

	clock := config.Clock
	if clock == nil {
		clock = systemCacheClock{}
	}
	maxEntryBytes := config.MaxEntryBytes
	if maxEntryBytes <= 0 {
		maxEntryBytes = DefaultMaxResponseBytes
	}

	return &CacheCoordinator{
		cache:          config.Cache,
		clock:          clock,
		sourcePolicies: policies,
		maxEntryBytes:  maxEntryBytes,
		inflight:       make(map[string]*cacheCall),
	}, nil
}

// Lookup applies the requested cache policy around fetch. fetch should perform
// exactly one provider operation and return its stable classified error. It is
// never called for a fresh hit or a FreshOnly miss.
func (coordinator *CacheCoordinator) Lookup(ctx context.Context, request CacheRequest, fetch CacheFetchFunc) (CacheLookupResult, error) {
	if ctx == nil {
		return CacheLookupResult{}, invalidInputError("cache lookup context is required")
	}
	if fetch == nil {
		return CacheLookupResult{}, invalidInputError("cache fetch function is required")
	}
	if !request.Policy.valid() {
		return CacheLookupResult{}, invalidInputError(fmt.Sprintf("unknown cache policy %q", request.Policy))
	}
	if err := ctx.Err(); err != nil {
		return CacheLookupResult{}, classifiedContextError(err)
	}

	spec, err := normalizeCacheKeySpec(request.Key)
	if err != nil {
		return CacheLookupResult{}, err
	}
	key, err := CanonicalCacheKey(spec)
	if err != nil {
		return CacheLookupResult{}, err
	}
	sourcePolicy, ok := coordinator.sourcePolicies[spec.Source]
	if !ok {
		return CacheLookupResult{}, invalidInputError(fmt.Sprintf("no cache policy configured for source %q", spec.Source))
	}

	if request.Policy == CachePolicyBypass {
		return coordinator.fetch(ctx, key, spec, sourcePolicy, request.Policy, fetch, CacheEnvelope{}, nil)
	}

	var (
		cached     CacheEnvelope
		cacheFound bool
		cacheErr   error
	)
	if request.Policy != CachePolicyRefresh {
		cached, cacheFound, cacheErr = coordinator.get(ctx, key, spec)
		if cacheErr != nil && request.Policy == CachePolicyFreshOnly {
			return CacheLookupResult{CacheError: cacheErr}, cacheErr
		}
		if cacheFound && coordinator.clock.Now().UTC().Before(cached.ExpiresAt) {
			result := CacheLookupResult{Envelope: cached, State: CacheStateHit, CacheHit: true}
			if cached.ProviderErrorClass != ProviderErrorNone {
				return result, &CachedProviderError{Class: cached.ProviderErrorClass, Source: cached.Source, FetchedAt: cached.FetchedAt}
			}
			return result, nil
		}
	}

	if request.Policy == CachePolicyFreshOnly {
		if cacheFound {
			staleErr := &CacheError{Operation: "get", Key: key, Err: ErrCacheStale}
			return CacheLookupResult{Envelope: cached, State: CacheStateStale, CacheHit: true, Stale: true, CacheError: staleErr}, staleErr
		}
		missErr := &CacheError{Operation: "get", Key: key, Err: ErrCacheMiss}
		return CacheLookupResult{CacheError: missErr}, missErr
	}

	// Policies are part of in-process coordination even though they are not
	// part of the stored key. This prevents a stale-if-error caller from
	// changing the fallback semantics observed by a concurrent read-through.
	inflightKey := key + "\x00" + string(request.Policy)
	return coordinator.coalescedFetch(ctx, inflightKey, func() (CacheLookupResult, error) {
		return coordinator.fetch(ctx, key, spec, sourcePolicy, request.Policy, fetch, cached, cacheErr)
	})
}

func (coordinator *CacheCoordinator) get(ctx context.Context, key string, spec CacheKeySpec) (CacheEnvelope, bool, error) {
	entry, found, err := coordinator.cache.Get(ctx, key)
	if err != nil {
		return CacheEnvelope{}, false, &CacheError{Operation: "get", Key: key, Err: fmt.Errorf("%w: %w", ErrCacheUnavailable, err)}
	}
	if !found {
		return CacheEnvelope{}, false, nil
	}
	if err := coordinator.validateEnvelope(key, spec, entry); err != nil {
		return CacheEnvelope{}, false, &CacheError{Operation: "get", Key: key, Err: err}
	}
	return entry, true, nil
}

func (coordinator *CacheCoordinator) validateEnvelope(key string, spec CacheKeySpec, entry CacheEnvelope) error {
	if entry.Version != CacheEnvelopeVersion || entry.Key != key || entry.Source != spec.Source ||
		entry.Endpoint != spec.Endpoint || entry.Protocol != spec.Protocol ||
		entry.NormalizedQuery != spec.NormalizedQuery || entry.ParserVersion != spec.ParserVersion ||
		entry.ResultSchemaVersion != spec.ResultSchemaVersion || entry.FetchedAt.IsZero() || entry.ExpiresAt.IsZero() ||
		!entry.ExpiresAt.After(entry.FetchedAt) {
		return ErrInvalidCacheEntry
	}
	if entry.ProviderErrorClass == ProviderErrorNone {
		if len(entry.NormalizedResult) == 0 || !json.Valid(entry.NormalizedResult) {
			return ErrInvalidCacheEntry
		}
	} else {
		if providerErrorSentinel(entry.ProviderErrorClass) == nil || len(entry.NormalizedResult) != 0 {
			return ErrInvalidCacheEntry
		}
	}
	if strings.TrimSpace(entry.Provenance.Provider) == "" || strings.TrimSpace(entry.Provenance.Endpoint) == "" || strings.TrimSpace(entry.Provenance.Protocol) == "" {
		return ErrInvalidCacheEntry
	}
	return coordinator.validateEntrySize(entry)
}

func (coordinator *CacheCoordinator) validateEntrySize(entry CacheEnvelope) error {
	encoded, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("%w: encode envelope: %v", ErrInvalidCacheEntry, err)
	}
	if int64(len(encoded)) > coordinator.maxEntryBytes {
		return &CacheEntryTooLargeError{Limit: coordinator.maxEntryBytes}
	}
	return nil
}

func (coordinator *CacheCoordinator) fetch(
	ctx context.Context,
	key string,
	spec CacheKeySpec,
	sourcePolicy SourceCachePolicy,
	requestPolicy CachePolicy,
	fetch func(context.Context) (CacheFetchResult, error),
	stale CacheEnvelope,
	priorCacheErr error,
) (CacheLookupResult, error) {
	if err := ctx.Err(); err != nil {
		return CacheLookupResult{CacheError: priorCacheErr}, classifiedContextError(err)
	}

	fetched, providerErr := fetch(ctx)
	fetchedAt := coordinator.clock.Now().UTC()
	providerClass := ClassifyProviderError(providerErr)

	if providerErr != nil && requestPolicy == CachePolicyStaleIfError &&
		stale.ProviderErrorClass == ProviderErrorNone && coordinator.canUseStale(stale, fetchedAt, sourcePolicy.MaxStale) &&
		ctx.Err() == nil && providerClass != ProviderErrorCanceled {
		return CacheLookupResult{
			Envelope:          stale,
			State:             CacheStateStale,
			CacheHit:          true,
			Stale:             true,
			CacheError:        priorCacheErr,
			RefreshErrorClass: providerClass,
		}, nil
	}

	ttl := sourcePolicy.SuccessTTL
	if providerErr != nil {
		switch providerClass {
		case ProviderErrorNoRecords:
			ttl = sourcePolicy.NoRecordsTTL
		case ProviderErrorRateLimited:
			ttl = sourcePolicy.RateLimitedTTL
		default:
			ttl = 0
		}
	}

	entry := CacheEnvelope{
		Version:             CacheEnvelopeVersion,
		Key:                 key,
		Source:              spec.Source,
		Endpoint:            spec.Endpoint,
		Protocol:            spec.Protocol,
		NormalizedQuery:     spec.NormalizedQuery,
		ParserVersion:       spec.ParserVersion,
		FetchedAt:           fetchedAt,
		ResultSchemaVersion: spec.ResultSchemaVersion,
		ProviderErrorClass:  providerClass,
		Provenance:          normalizeProvenance(fetched.Provenance, spec),
	}
	if ttl > 0 {
		entry.ExpiresAt = fetchedAt.Add(ttl)
	}
	if providerErr == nil {
		entry.NormalizedResult = append(json.RawMessage(nil), fetched.NormalizedResult...)
		if len(entry.NormalizedResult) == 0 || !json.Valid(entry.NormalizedResult) {
			return CacheLookupResult{CacheError: priorCacheErr}, fmt.Errorf("%w: normalized result must be valid JSON", ErrInvalidCacheEntry)
		}
	}

	state := CacheStateRefreshed
	if requestPolicy == CachePolicyBypass || ttl == 0 {
		state = CacheStateBypassed
		if requestPolicy != CachePolicyBypass {
			state = CacheStateProvider
		}
	}
	result := CacheLookupResult{
		Envelope:   entry,
		State:      state,
		CacheError: priorCacheErr,
	}

	if requestPolicy != CachePolicyBypass && ttl > 0 {
		if err := coordinator.validateEnvelope(key, spec, entry); err != nil {
			result.State = CacheStateProvider
			result.CacheError = &CacheError{Operation: "set", Key: key, Err: err}
			if providerErr != nil {
				return result, providerErr
			}
			return result, nil
		}
		if err := coordinator.cache.Set(ctx, key, entry); err != nil {
			result.State = CacheStateProvider
			result.CacheError = &CacheError{Operation: "set", Key: key, Err: fmt.Errorf("%w: %w", ErrCacheUnavailable, err)}
		}
	}

	if providerErr != nil {
		return result, providerErr
	}
	return result, nil
}

func normalizeProvenance(provenance CacheProvenance, spec CacheKeySpec) CacheProvenance {
	if strings.TrimSpace(provenance.Provider) == "" {
		provenance.Provider = spec.Source
	}
	if strings.TrimSpace(provenance.Endpoint) == "" {
		provenance.Endpoint = spec.Endpoint
	}
	if strings.TrimSpace(provenance.Protocol) == "" {
		provenance.Protocol = spec.Protocol
	}
	return provenance
}

func (coordinator *CacheCoordinator) canUseStale(entry CacheEnvelope, now time.Time, maxStale time.Duration) bool {
	return !entry.ExpiresAt.IsZero() && maxStale > 0 && !now.Before(entry.ExpiresAt) && now.Sub(entry.ExpiresAt) <= maxStale
}

func (coordinator *CacheCoordinator) coalescedFetch(ctx context.Context, key string, fetch func() (CacheLookupResult, error)) (CacheLookupResult, error) {
	coordinator.mu.Lock()
	if call, ok := coordinator.inflight[key]; ok {
		call.waiters++
		coordinator.mu.Unlock()
		select {
		case <-call.done:
			return completedCacheCall(ctx, call)
		case <-ctx.Done():
			return CacheLookupResult{Coalesced: true}, classifiedContextError(ctx.Err())
		}
	}

	call := &cacheCall{done: make(chan struct{})}
	coordinator.inflight[key] = call
	coordinator.mu.Unlock()

	call.result, call.err = fetch()
	close(call.done)

	coordinator.mu.Lock()
	delete(coordinator.inflight, key)
	coordinator.mu.Unlock()
	return call.result, call.err
}

func completedCacheCall(ctx context.Context, call *cacheCall) (CacheLookupResult, error) {
	// The call and context can become ready together. Recheck cancellation
	// after receiving the shared result so select cannot return provider or
	// stale data past this waiter's deadline.
	if err := ctx.Err(); err != nil {
		return CacheLookupResult{Coalesced: true}, classifiedContextError(err)
	}
	result := call.result
	result.Coalesced = true
	return result, call.err
}

func classifiedContextError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", ErrTimeout, err)
	}
	return fmt.Errorf("%w: %w", ErrCanceled, err)
}

// MemoryCache is a bounded-by-coordinator, process-local implementation of
// Cache. Entries are copied on read and write so callers cannot mutate stored
// byte slices or provenance maps.
type MemoryCache struct {
	mu      sync.RWMutex
	entries map[string]CacheEnvelope
}

// NewMemoryCache returns an empty concurrency-safe in-memory cache.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{entries: make(map[string]CacheEnvelope)}
}

func (cache *MemoryCache) Get(ctx context.Context, key string) (CacheEnvelope, bool, error) {
	if err := ctx.Err(); err != nil {
		return CacheEnvelope{}, false, err
	}
	cache.mu.RLock()
	entry, found := cache.entries[key]
	cache.mu.RUnlock()
	if !found {
		return CacheEnvelope{}, false, nil
	}
	return cloneCacheEnvelope(entry), true, nil
}

func (cache *MemoryCache) Set(ctx context.Context, key string, entry CacheEnvelope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cache.mu.Lock()
	if cache.entries == nil {
		cache.entries = make(map[string]CacheEnvelope)
	}
	cache.entries[key] = cloneCacheEnvelope(entry)
	cache.mu.Unlock()
	return nil
}

func (cache *MemoryCache) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cache.mu.Lock()
	delete(cache.entries, key)
	cache.mu.Unlock()
	return nil
}

func cloneCacheEnvelope(entry CacheEnvelope) CacheEnvelope {
	entry.NormalizedResult = append(json.RawMessage(nil), entry.NormalizedResult...)
	if entry.Provenance.Details != nil {
		details := make(map[string]string, len(entry.Provenance.Details))
		for key, value := range entry.Provenance.Details {
			details[key] = value
		}
		entry.Provenance.Details = details
	}
	return entry
}
