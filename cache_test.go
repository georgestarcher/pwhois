package pwhois

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var cacheTestTime = time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

type fakeCacheClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *fakeCacheClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *fakeCacheClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

type fakeCache struct {
	mu          sync.Mutex
	entries     map[string]CacheEnvelope
	getError    error
	setError    error
	getCalls    int
	setCalls    int
	deleteCalls int
}

func newFakeCache() *fakeCache {
	return &fakeCache{entries: make(map[string]CacheEnvelope)}
}

func (cache *fakeCache) Get(ctx context.Context, key string) (CacheEnvelope, bool, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.getCalls++
	if cache.getError != nil {
		return CacheEnvelope{}, false, cache.getError
	}
	entry, found := cache.entries[key]
	return cloneCacheEnvelope(entry), found, nil
}

func (cache *fakeCache) Set(ctx context.Context, key string, entry CacheEnvelope) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.setCalls++
	if cache.setError != nil {
		return cache.setError
	}
	cache.entries[key] = cloneCacheEnvelope(entry)
	return nil
}

func (cache *fakeCache) Delete(ctx context.Context, key string) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.deleteCalls++
	delete(cache.entries, key)
	return nil
}

func (cache *fakeCache) counts() (int, int) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return cache.getCalls, cache.setCalls
}

func testCacheKey(source string) CacheKeySpec {
	return CacheKeySpec{
		Source:              source,
		Endpoint:            "whois.example.test:43",
		Protocol:            "pwhois",
		NormalizedQuery:     "192.0.2.1",
		Options:             map[string]string{"lookup": "ip"},
		ParserVersion:       "ip-v1",
		ResultSchemaVersion: "whois-v1",
	}
}

func testCacheCoordinator(t *testing.T, cache Cache, clock CacheClock) *CacheCoordinator {
	t.Helper()
	coordinator, err := NewCacheCoordinator(CacheCoordinatorConfig{
		Cache: cache,
		Clock: clock,
		SourcePolicies: map[string]SourceCachePolicy{
			"pwhois": {
				SuccessTTL:     time.Hour,
				NoRecordsTTL:   5 * time.Minute,
				RateLimitedTTL: time.Minute,
				MaxStale:       30 * time.Minute,
			},
			"alternative": {
				SuccessTTL:     2 * time.Hour,
				NoRecordsTTL:   10 * time.Minute,
				RateLimitedTTL: 2 * time.Minute,
				MaxStale:       time.Hour,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewCacheCoordinator() error = %v", err)
	}
	return coordinator
}

func successfulCacheFetch(result string) func(context.Context) (CacheFetchResult, error) {
	return func(context.Context) (CacheFetchResult, error) {
		return CacheFetchResult{
			NormalizedResult: json.RawMessage(result),
			Provenance: CacheProvenance{
				Provider: "pwhois",
				Details:  map[string]string{"parser": "ip"},
			},
		}, nil
	}
}

func TestCanonicalCacheKeyIsSourceAwareAndDeterministic(t *testing.T) {
	first := testCacheKey("PWHOIS")
	first.Options = map[string]string{"z": "last", "a": "first"}
	second := testCacheKey("pwhois")
	second.Options = map[string]string{"a": "first", "z": "last"}

	firstKey, err := CanonicalCacheKey(first)
	if err != nil {
		t.Fatalf("CanonicalCacheKey(first) error = %v", err)
	}
	secondKey, err := CanonicalCacheKey(second)
	if err != nil {
		t.Fatalf("CanonicalCacheKey(second) error = %v", err)
	}
	if firstKey != secondKey {
		t.Fatalf("keys with reordered options differ:\n%s\n%s", firstKey, secondKey)
	}

	alternative := second
	alternative.Source = "alternative"
	alternativeKey, err := CanonicalCacheKey(alternative)
	if err != nil {
		t.Fatalf("CanonicalCacheKey(alternative) error = %v", err)
	}
	if alternativeKey == secondKey {
		t.Fatal("identical query collided across sources")
	}

	changedEndpoint := second
	changedEndpoint.Endpoint = "other.example.test:43"
	changedEndpointKey, err := CanonicalCacheKey(changedEndpoint)
	if err != nil {
		t.Fatalf("CanonicalCacheKey(changed endpoint) error = %v", err)
	}
	if changedEndpointKey == secondKey {
		t.Fatal("identical query collided across endpoints")
	}
}

func TestCanonicalCacheKeyRequiresContractVersions(t *testing.T) {
	key := testCacheKey("pwhois")
	key.ParserVersion = ""
	if _, err := CanonicalCacheKey(key); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("CanonicalCacheKey() error = %v, want ErrInvalidInput", err)
	}

	key = testCacheKey("pwhois")
	key.ResultSchemaVersion = ""
	if _, err := CanonicalCacheKey(key); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("CanonicalCacheKey() error = %v, want ErrInvalidInput", err)
	}
}

func TestCacheCoordinatorReadThroughThenHit(t *testing.T) {
	clock := &fakeCacheClock{now: cacheTestTime}
	cache := newFakeCache()
	coordinator := testCacheCoordinator(t, cache, clock)
	request := CacheRequest{Key: testCacheKey("pwhois"), Policy: CachePolicyReadThrough}
	var fetchCalls int
	fetch := func(ctx context.Context) (CacheFetchResult, error) {
		fetchCalls++
		return successfulCacheFetch(`{"ip":"192.0.2.1"}`)(ctx)
	}

	first, err := coordinator.Lookup(context.Background(), request, fetch)
	if err != nil {
		t.Fatalf("first Lookup() error = %v", err)
	}
	if first.State != CacheStateRefreshed || first.CacheHit || first.Stale {
		t.Fatalf("first Lookup() state = %+v", first)
	}
	if first.Envelope.Source != "pwhois" || first.Envelope.NormalizedQuery != "192.0.2.1" {
		t.Fatalf("first envelope provenance = %+v", first.Envelope)
	}
	if !first.Envelope.FetchedAt.Equal(cacheTestTime) || !first.Envelope.ExpiresAt.Equal(cacheTestTime.Add(time.Hour)) {
		t.Fatalf("first envelope times = %v to %v", first.Envelope.FetchedAt, first.Envelope.ExpiresAt)
	}

	second, err := coordinator.Lookup(context.Background(), request, fetch)
	if err != nil {
		t.Fatalf("second Lookup() error = %v", err)
	}
	if second.State != CacheStateHit || !second.CacheHit || second.Stale {
		t.Fatalf("second Lookup() state = %+v", second)
	}
	if fetchCalls != 1 {
		t.Fatalf("fetch calls = %d, want 1", fetchCalls)
	}
	getCalls, setCalls := cache.counts()
	if getCalls != 2 || setCalls != 1 {
		t.Fatalf("cache calls = get %d, set %d; want get 2, set 1", getCalls, setCalls)
	}
}

func TestCacheCoordinatorPolicyBehavior(t *testing.T) {
	tests := []struct {
		name         string
		policy       CachePolicy
		seedFresh    bool
		seedStale    bool
		wantFetches  int
		wantState    CacheState
		wantCacheHit bool
		wantError    error
	}{
		{name: "bypass ignores fresh entry", policy: CachePolicyBypass, seedFresh: true, wantFetches: 1, wantState: CacheStateBypassed},
		{name: "refresh ignores fresh entry", policy: CachePolicyRefresh, seedFresh: true, wantFetches: 1, wantState: CacheStateRefreshed},
		{name: "fresh only hit", policy: CachePolicyFreshOnly, seedFresh: true, wantFetches: 0, wantState: CacheStateHit, wantCacheHit: true},
		{name: "fresh only miss", policy: CachePolicyFreshOnly, wantFetches: 0, wantError: ErrCacheMiss},
		{name: "fresh only stale", policy: CachePolicyFreshOnly, seedStale: true, wantFetches: 0, wantState: CacheStateStale, wantCacheHit: true, wantError: ErrCacheStale},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := &fakeCacheClock{now: cacheTestTime}
			cache := newFakeCache()
			coordinator := testCacheCoordinator(t, cache, clock)
			keySpec := testCacheKey("pwhois")
			key, err := CanonicalCacheKey(keySpec)
			if err != nil {
				t.Fatalf("CanonicalCacheKey() error = %v", err)
			}
			if test.seedFresh || test.seedStale {
				expiresAt := cacheTestTime.Add(time.Hour)
				if test.seedStale {
					expiresAt = cacheTestTime.Add(-time.Minute)
				}
				cache.entries[key] = CacheEnvelope{
					Version: CacheEnvelopeVersion, Key: key, Source: "pwhois",
					Endpoint: keySpec.Endpoint, Protocol: keySpec.Protocol, NormalizedQuery: keySpec.NormalizedQuery,
					ParserVersion: keySpec.ParserVersion, FetchedAt: expiresAt.Add(-time.Hour), ExpiresAt: expiresAt,
					ResultSchemaVersion: keySpec.ResultSchemaVersion, NormalizedResult: json.RawMessage(`{"seeded":true}`),
					Provenance: CacheProvenance{Provider: "pwhois", Endpoint: keySpec.Endpoint, Protocol: keySpec.Protocol},
				}
			}

			fetchCalls := 0
			result, lookupErr := coordinator.Lookup(context.Background(), CacheRequest{Key: keySpec, Policy: test.policy}, func(ctx context.Context) (CacheFetchResult, error) {
				fetchCalls++
				return successfulCacheFetch(`{"fresh":true}`)(ctx)
			})
			if !errors.Is(lookupErr, test.wantError) {
				t.Fatalf("Lookup() error = %v, want %v", lookupErr, test.wantError)
			}
			if fetchCalls != test.wantFetches {
				t.Fatalf("fetch calls = %d, want %d", fetchCalls, test.wantFetches)
			}
			if result.State != test.wantState || result.CacheHit != test.wantCacheHit {
				t.Fatalf("Lookup() state = %+v, want state %q hit %t", result, test.wantState, test.wantCacheHit)
			}
		})
	}
}

func TestCacheCoordinatorUsesSourceSpecificTTLs(t *testing.T) {
	clock := &fakeCacheClock{now: cacheTestTime}
	cache := newFakeCache()
	coordinator := testCacheCoordinator(t, cache, clock)

	result, err := coordinator.Lookup(context.Background(), CacheRequest{Key: testCacheKey("alternative"), Policy: CachePolicyReadThrough}, successfulCacheFetch(`{"ok":true}`))
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if got := result.Envelope.ExpiresAt.Sub(result.Envelope.FetchedAt); got != 2*time.Hour {
		t.Fatalf("alternative success TTL = %v, want 2h", got)
	}
}

func TestCacheCoordinatorNegativeAndRateLimitCaching(t *testing.T) {
	tests := []struct {
		name      string
		fetchErr  error
		wantError error
		wantClass ProviderErrorClass
		wantTTL   time.Duration
	}{
		{name: "no records", fetchErr: fmt.Errorf("query: %w", ErrNoRecords), wantError: ErrNoRecords, wantClass: ProviderErrorNoRecords, wantTTL: 5 * time.Minute},
		{name: "rate limited", fetchErr: fmt.Errorf("query: %w", ErrRateLimited), wantError: ErrRateLimited, wantClass: ProviderErrorRateLimited, wantTTL: time.Minute},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := &fakeCacheClock{now: cacheTestTime}
			cache := newFakeCache()
			coordinator := testCacheCoordinator(t, cache, clock)
			request := CacheRequest{Key: testCacheKey("pwhois"), Policy: CachePolicyReadThrough}
			fetchCalls := 0
			fetch := func(context.Context) (CacheFetchResult, error) {
				fetchCalls++
				return CacheFetchResult{}, test.fetchErr
			}

			first, err := coordinator.Lookup(context.Background(), request, fetch)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("first Lookup() error = %v, want %v", err, test.wantError)
			}
			if first.Envelope.ProviderErrorClass != test.wantClass {
				t.Fatalf("provider class = %q, want %q", first.Envelope.ProviderErrorClass, test.wantClass)
			}
			if got := first.Envelope.ExpiresAt.Sub(first.Envelope.FetchedAt); got != test.wantTTL {
				t.Fatalf("negative TTL = %v, want %v", got, test.wantTTL)
			}

			second, err := coordinator.Lookup(context.Background(), request, fetch)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("second Lookup() error = %v, want stable class from cached result", err)
			}
			var cachedErr *CachedProviderError
			if !errors.As(err, &cachedErr) {
				t.Fatalf("second Lookup() error type = %T, want *CachedProviderError", err)
			}
			if second.State != CacheStateHit || !second.CacheHit || fetchCalls != 1 {
				t.Fatalf("second Lookup() = %+v, fetch calls %d", second, fetchCalls)
			}
		})
	}
}

func TestCacheCoordinatorStaleIfErrorIsBounded(t *testing.T) {
	clock := &fakeCacheClock{now: cacheTestTime}
	cache := newFakeCache()
	coordinator := testCacheCoordinator(t, cache, clock)
	request := CacheRequest{Key: testCacheKey("pwhois"), Policy: CachePolicyReadThrough}

	if _, err := coordinator.Lookup(context.Background(), request, successfulCacheFetch(`{"generation":1}`)); err != nil {
		t.Fatalf("seed Lookup() error = %v", err)
	}
	clock.Advance(time.Hour + 10*time.Minute)
	request.Policy = CachePolicyStaleIfError

	stale, err := coordinator.Lookup(context.Background(), request, func(context.Context) (CacheFetchResult, error) {
		return CacheFetchResult{}, fmt.Errorf("temporary failure: %w", ErrConnection)
	})
	if err != nil {
		t.Fatalf("stale Lookup() error = %v", err)
	}
	if stale.State != CacheStateStale || !stale.CacheHit || !stale.Stale || stale.RefreshErrorClass != ProviderErrorConnection {
		t.Fatalf("stale Lookup() result = %+v", stale)
	}

	clock.Advance(21 * time.Minute)
	outside, err := coordinator.Lookup(context.Background(), request, func(context.Context) (CacheFetchResult, error) {
		return CacheFetchResult{}, fmt.Errorf("temporary failure: %w", ErrConnection)
	})
	if !errors.Is(err, ErrConnection) {
		t.Fatalf("outside-window Lookup() error = %v, want ErrConnection", err)
	}
	if outside.Stale {
		t.Fatalf("outside-window Lookup() returned stale data: %+v", outside)
	}
}

func TestCacheCoordinatorDoesNotHideCancellationWithStaleData(t *testing.T) {
	clock := &fakeCacheClock{now: cacheTestTime}
	cache := newFakeCache()
	coordinator := testCacheCoordinator(t, cache, clock)
	request := CacheRequest{Key: testCacheKey("pwhois"), Policy: CachePolicyReadThrough}
	if _, err := coordinator.Lookup(context.Background(), request, successfulCacheFetch(`{"ok":true}`)); err != nil {
		t.Fatalf("seed Lookup() error = %v", err)
	}
	clock.Advance(time.Hour + time.Minute)
	request.Policy = CachePolicyStaleIfError

	result, err := coordinator.Lookup(context.Background(), request, func(context.Context) (CacheFetchResult, error) {
		return CacheFetchResult{}, fmt.Errorf("caller stopped: %w", ErrCanceled)
	})
	if !errors.Is(err, ErrCanceled) {
		t.Fatalf("Lookup() error = %v, want ErrCanceled", err)
	}
	if result.Stale {
		t.Fatalf("Lookup() hid cancellation with stale data: %+v", result)
	}
}

func TestCacheCoordinatorUsesStaleDataForProviderTimeout(t *testing.T) {
	clock := &fakeCacheClock{now: cacheTestTime}
	cache := newFakeCache()
	coordinator := testCacheCoordinator(t, cache, clock)
	request := CacheRequest{Key: testCacheKey("pwhois"), Policy: CachePolicyReadThrough}
	if _, err := coordinator.Lookup(context.Background(), request, successfulCacheFetch(`{"ok":true}`)); err != nil {
		t.Fatalf("seed Lookup() error = %v", err)
	}
	clock.Advance(time.Hour + time.Minute)
	request.Policy = CachePolicyStaleIfError

	result, err := coordinator.Lookup(context.Background(), request, func(context.Context) (CacheFetchResult, error) {
		return CacheFetchResult{}, fmt.Errorf("provider timed out: %w", ErrTimeout)
	})
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if !result.Stale || result.RefreshErrorClass != ProviderErrorTimeout {
		t.Fatalf("Lookup() result = %+v, want stale timeout fallback", result)
	}
}

func TestCacheCoordinatorSurfacesBackendFailureSeparately(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*fakeCache, error)
		wantState CacheState
	}{
		{name: "read failure", configure: func(cache *fakeCache, backendErr error) { cache.getError = backendErr }, wantState: CacheStateRefreshed},
		{name: "write failure", configure: func(cache *fakeCache, backendErr error) { cache.setError = backendErr }, wantState: CacheStateProvider},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := &fakeCacheClock{now: cacheTestTime}
			cache := newFakeCache()
			backendErr := errors.New("backend unavailable")
			test.configure(cache, backendErr)
			coordinator := testCacheCoordinator(t, cache, clock)

			result, err := coordinator.Lookup(context.Background(), CacheRequest{Key: testCacheKey("pwhois"), Policy: CachePolicyReadThrough}, successfulCacheFetch(`{"ok":true}`))
			if err != nil {
				t.Fatalf("Lookup() provider error = %v", err)
			}
			if result.State != test.wantState || result.CacheError == nil || !errors.Is(result.CacheError, ErrCacheUnavailable) || !errors.Is(result.CacheError, backendErr) {
				t.Fatalf("Lookup() result = %+v, want usable provider result with cache error", result)
			}
			if result.Envelope.ProviderErrorClass != ProviderErrorNone {
				t.Fatalf("cache failure was represented as provider class %q", result.Envelope.ProviderErrorClass)
			}
		})
	}
}

func TestCacheCoordinatorRejectsOversizedEnvelope(t *testing.T) {
	clock := &fakeCacheClock{now: cacheTestTime}
	cache := newFakeCache()
	coordinator, err := NewCacheCoordinator(CacheCoordinatorConfig{
		Cache:         cache,
		Clock:         clock,
		MaxEntryBytes: 256,
		SourcePolicies: map[string]SourceCachePolicy{
			"pwhois": {SuccessTTL: time.Hour},
		},
	})
	if err != nil {
		t.Fatalf("NewCacheCoordinator() error = %v", err)
	}

	result, err := coordinator.Lookup(context.Background(), CacheRequest{Key: testCacheKey("pwhois"), Policy: CachePolicyReadThrough}, successfulCacheFetch(`{"data":"`+strings.Repeat("x", 512)+`"}`))
	if err != nil {
		t.Fatalf("Lookup() provider error = %v", err)
	}
	if result.State != CacheStateProvider || !errors.Is(result.CacheError, ErrCacheEntryTooLarge) {
		t.Fatalf("Lookup() result = %+v, want usable provider result with ErrCacheEntryTooLarge", result)
	}
	if len(result.Envelope.NormalizedResult) == 0 {
		t.Fatal("oversized cache entry discarded usable provider result")
	}
	_, setCalls := cache.counts()
	if setCalls != 0 {
		t.Fatalf("cache Set calls = %d, want 0", setCalls)
	}
}

func TestCacheEnvelopeContainsNoRawResponseField(t *testing.T) {
	entry := CacheEnvelope{
		Version:          CacheEnvelopeVersion,
		NormalizedResult: json.RawMessage(`{"safe":"normalized"}`),
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if strings.Contains(string(encoded), "raw_response") || strings.Contains(string(encoded), "provider_payload") {
		t.Fatalf("cache envelope exposed raw-response field: %s", encoded)
	}
}

func TestCacheCoordinatorCoalescesConcurrentMisses(t *testing.T) {
	const workers = 16
	clock := &fakeCacheClock{now: cacheTestTime}
	cache := newFakeCache()
	coordinator := testCacheCoordinator(t, cache, clock)
	request := CacheRequest{Key: testCacheKey("pwhois"), Policy: CachePolicyReadThrough}
	key, err := CanonicalCacheKey(request.Key)
	if err != nil {
		t.Fatalf("CanonicalCacheKey() error = %v", err)
	}

	start := make(chan struct{})
	releaseFetch := make(chan struct{})
	var fetchCalls atomic.Int32
	fetch := func(context.Context) (CacheFetchResult, error) {
		fetchCalls.Add(1)
		<-releaseFetch
		return CacheFetchResult{NormalizedResult: json.RawMessage(`{"ok":true}`)}, nil
	}

	type outcome struct {
		result CacheLookupResult
		err    error
	}
	outcomes := make(chan outcome, workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			<-start
			result, lookupErr := coordinator.Lookup(context.Background(), request, fetch)
			outcomes <- outcome{result: result, err: lookupErr}
		}()
	}
	close(start)

	deadline := time.Now().Add(2 * time.Second)
	for {
		coordinator.mu.Lock()
		call := coordinator.inflight[key+"\x00"+string(request.Policy)]
		waiters := 0
		if call != nil {
			waiters = call.waiters
		}
		coordinator.mu.Unlock()
		if waiters == workers-1 {
			break
		}
		if time.Now().After(deadline) {
			close(releaseFetch)
			t.Fatalf("coalesced waiters = %d, want %d", waiters, workers-1)
		}
		runtime.Gosched()
	}
	close(releaseFetch)

	coalesced := 0
	for worker := 0; worker < workers; worker++ {
		outcome := <-outcomes
		if outcome.err != nil {
			t.Errorf("Lookup() error = %v", outcome.err)
		}
		if outcome.result.Coalesced {
			coalesced++
		}
	}
	if fetchCalls.Load() != 1 {
		t.Fatalf("fetch calls = %d, want 1", fetchCalls.Load())
	}
	if coalesced != workers-1 {
		t.Fatalf("coalesced results = %d, want %d", coalesced, workers-1)
	}
}

func TestCompletedCacheCallHonorsWaitingContext(t *testing.T) {
	tests := []struct {
		name      string
		context   func() context.Context
		wantError error
	}{
		{
			name: "canceled",
			context: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			wantError: ErrCanceled,
		},
		{
			name: "deadline exceeded",
			context: func() context.Context {
				ctx, cancel := context.WithDeadline(context.Background(), cacheTestTime.Add(-time.Second))
				t.Cleanup(cancel)
				return ctx
			},
			wantError: ErrTimeout,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			call := &cacheCall{
				result: CacheLookupResult{State: CacheStateHit},
				err:    errors.New("leader result must not escape"),
			}
			result, err := completedCacheCall(test.context(), call)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("completedCacheCall() error = %v, want %v", err, test.wantError)
			}
			if !result.Coalesced || result.State != "" {
				t.Fatalf("completedCacheCall() result = %+v, want canceled coalesced result", result)
			}
		})
	}
}

func TestMemoryCacheCopiesMutableData(t *testing.T) {
	cache := new(MemoryCache)
	entry := CacheEnvelope{
		NormalizedResult: json.RawMessage(`{"value":1}`),
		Provenance:       CacheProvenance{Details: map[string]string{"source": "original"}},
	}
	if err := cache.Set(context.Background(), "key", entry); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	entry.NormalizedResult[2] = 'X'
	entry.Provenance.Details["source"] = "changed"

	stored, found, err := cache.Get(context.Background(), "key")
	if err != nil || !found {
		t.Fatalf("Get() = found %t, error %v", found, err)
	}
	if string(stored.NormalizedResult) != `{"value":1}` || stored.Provenance.Details["source"] != "original" {
		t.Fatalf("stored entry mutated through caller: %+v", stored)
	}

	stored.NormalizedResult[2] = 'Y'
	stored.Provenance.Details["source"] = "changed again"
	storedAgain, _, _ := cache.Get(context.Background(), "key")
	if string(storedAgain.NormalizedResult) != `{"value":1}` || storedAgain.Provenance.Details["source"] != "original" {
		t.Fatalf("stored entry mutated through Get result: %+v", storedAgain)
	}
}

func TestNewCacheCoordinatorRequiresPerSourcePolicy(t *testing.T) {
	_, err := NewCacheCoordinator(CacheCoordinatorConfig{Cache: NewMemoryCache()})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("NewCacheCoordinator() error = %v, want ErrInvalidInput", err)
	}

	coordinator := testCacheCoordinator(t, NewMemoryCache(), &fakeCacheClock{now: cacheTestTime})
	_, err = coordinator.Lookup(context.Background(), CacheRequest{Key: testCacheKey("unconfigured"), Policy: CachePolicyReadThrough}, successfulCacheFetch(`{"ok":true}`))
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Lookup() error = %v, want ErrInvalidInput", err)
	}
}
