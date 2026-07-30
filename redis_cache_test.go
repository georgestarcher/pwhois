package pwhois

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func testRedisEnvelope(t *testing.T, source string, fetchedAt, expiresAt time.Time) (string, CacheKeySpec, CacheEnvelope) {
	t.Helper()

	spec := testCacheKey(source)
	key, entry := testRedisEnvelopeForSpec(t, spec, fetchedAt, expiresAt)
	return key, spec, entry
}

func testRedisEnvelopeForSpec(t *testing.T, spec CacheKeySpec, fetchedAt, expiresAt time.Time) (string, CacheEnvelope) {
	t.Helper()

	key, err := CanonicalCacheKey(spec)
	if err != nil {
		t.Fatalf("CanonicalCacheKey: %v", err)
	}
	entry := CacheEnvelope{
		Version:             CacheEnvelopeVersion,
		Key:                 key,
		Source:              strings.ToLower(spec.Source),
		Endpoint:            spec.Endpoint,
		Protocol:            spec.Protocol,
		NormalizedQuery:     spec.NormalizedQuery,
		ParserVersion:       spec.ParserVersion,
		FetchedAt:           fetchedAt,
		ExpiresAt:           expiresAt,
		ResultSchemaVersion: spec.ResultSchemaVersion,
		NormalizedResult:    json.RawMessage(`{"ip":"192.0.2.1"}`),
		Provenance: CacheProvenance{
			Provider: spec.Source,
			Endpoint: spec.Endpoint,
			Protocol: spec.Protocol,
		},
	}
	return key, entry
}

func newTestRedisCaches(t *testing.T, server *miniredis.Miniredis, clock CacheClock, prefix string, staleRetention time.Duration) (*RedisCache, *RedisCache) {
	t.Helper()

	config := RedisCacheConfig{
		Address:        server.Addr(),
		KeyPrefix:      prefix,
		Clock:          clock,
		StaleRetention: staleRetention,
	}
	first, err := NewRedisCache(config)
	if err != nil {
		t.Fatalf("NewRedisCache(first): %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := NewRedisCache(config)
	if err != nil {
		t.Fatalf("NewRedisCache(second): %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	return first, second
}

func TestRedisCacheSharesEntriesAndExactTTL(t *testing.T) {
	server := miniredis.RunT(t)
	clock := &fakeCacheClock{now: cacheTestTime}
	first, second := newTestRedisCaches(t, server, clock, "workers", 0)
	key, _, entry := testRedisEnvelope(t, "pwhois", cacheTestTime, cacheTestTime.Add(time.Hour))

	if err := first.Set(context.Background(), key, entry); err != nil {
		t.Fatalf("Set: %v", err)
	}
	storageKey, err := first.storageKey(key)
	if err != nil {
		t.Fatalf("storageKey: %v", err)
	}
	if ttl := server.TTL(storageKey); ttl != time.Hour {
		t.Fatalf("Redis TTL = %v, want 1h", ttl)
	}

	stored, found, err := second.Get(context.Background(), key)
	if err != nil || !found {
		t.Fatalf("second Get = found %t, error %v", found, err)
	}
	if !reflect.DeepEqual(stored, entry) {
		t.Fatalf("shared entry = %+v, want %+v", stored, entry)
	}

	server.FastForward(time.Hour)
	if _, found, err := second.Get(context.Background(), key); err != nil || found {
		t.Fatalf("expired Get = found %t, error %v", found, err)
	}
}

func TestRedisCacheKeepsBoundedStaleEnvelope(t *testing.T) {
	server := miniredis.RunT(t)
	clock := &fakeCacheClock{now: cacheTestTime}
	first, second := newTestRedisCaches(t, server, clock, "stale-workers:", 30*time.Minute)
	key, _, entry := testRedisEnvelope(t, "pwhois", cacheTestTime, cacheTestTime.Add(time.Hour))

	if err := first.Set(context.Background(), key, entry); err != nil {
		t.Fatalf("Set: %v", err)
	}
	storageKey, _ := first.storageKey(key)
	if ttl := server.TTL(storageKey); ttl != 90*time.Minute {
		t.Fatalf("Redis TTL = %v, want 90m", ttl)
	}

	clock.Advance(time.Hour + time.Minute)
	server.FastForward(time.Hour + time.Minute)
	stale, found, err := second.Get(context.Background(), key)
	if err != nil || !found {
		t.Fatalf("stale Get = found %t, error %v", found, err)
	}
	if stale.ExpiresAt.After(clock.Now()) {
		t.Fatalf("entry is not stale: expires %v, now %v", stale.ExpiresAt, clock.Now())
	}

	coordinator := testCacheCoordinator(t, second, clock)
	result, lookupErr := coordinator.Lookup(context.Background(), CacheRequest{
		Key:    testCacheKey("pwhois"),
		Policy: CachePolicyFreshOnly,
	}, successfulCacheFetch(`{"must":"not fetch"}`))
	if !errors.Is(lookupErr, ErrCacheStale) {
		t.Fatalf("fresh-only Lookup error = %v, want ErrCacheStale", lookupErr)
	}
	if result.State != CacheStateStale || !result.CacheHit || !result.Stale {
		t.Fatalf("fresh-only stale result = %+v", result)
	}

	server.FastForward(29 * time.Minute)
	if _, found, err := second.Get(context.Background(), key); err != nil || found {
		t.Fatalf("retention-expired Get = found %t, error %v", found, err)
	}
}

func TestRedisCacheSeparatesCanonicalSources(t *testing.T) {
	server := miniredis.RunT(t)
	clock := &fakeCacheClock{now: cacheTestTime}
	cache, _ := newTestRedisCaches(t, server, clock, "source-isolation", 0)
	firstKey, _, firstEntry := testRedisEnvelope(t, "pwhois", cacheTestTime, cacheTestTime.Add(time.Hour))
	secondKey, _, secondEntry := testRedisEnvelope(t, "alternative", cacheTestTime, cacheTestTime.Add(time.Hour))

	if firstKey == secondKey {
		t.Fatal("canonical keys collided across sources")
	}
	if err := cache.Set(context.Background(), firstKey, firstEntry); err != nil {
		t.Fatalf("Set first: %v", err)
	}
	if err := cache.Set(context.Background(), secondKey, secondEntry); err != nil {
		t.Fatalf("Set second: %v", err)
	}
	if keys := server.Keys(); len(keys) != 2 {
		t.Fatalf("Redis keys = %v, want two isolated entries", keys)
	}

	if err := cache.Delete(context.Background(), firstKey); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, found, err := cache.Get(context.Background(), firstKey); err != nil || found {
		t.Fatalf("deleted Get = found %t, error %v", found, err)
	}
	if _, found, err := cache.Get(context.Background(), secondKey); err != nil || !found {
		t.Fatalf("unrelated Get = found %t, error %v", found, err)
	}
}

func TestRedisCacheSeparatesQueryAndContractVersions(t *testing.T) {
	server := miniredis.RunT(t)
	clock := &fakeCacheClock{now: cacheTestTime}
	cache, _ := newTestRedisCaches(t, server, clock, "contract-isolation", 0)

	base := testCacheKey("pwhois")
	queryVariant := base
	queryVariant.NormalizedQuery = "198.51.100.2"
	parserVariant := base
	parserVariant.ParserVersion = "ip-v2"
	schemaVariant := base
	schemaVariant.ResultSchemaVersion = "whois-v2"

	seen := make(map[string]string)
	for name, spec := range map[string]CacheKeySpec{
		"base":           base,
		"query":          queryVariant,
		"parser version": parserVariant,
		"schema version": schemaVariant,
	} {
		key, entry := testRedisEnvelopeForSpec(t, spec, cacheTestTime, cacheTestTime.Add(time.Hour))
		if prior, found := seen[key]; found {
			t.Fatalf("%s key collided with %s", name, prior)
		}
		seen[key] = name
		if err := cache.Set(context.Background(), key, entry); err != nil {
			t.Fatalf("Set %s: %v", name, err)
		}
	}
	if keys := server.Keys(); len(keys) != len(seen) {
		t.Fatalf("Redis keys = %v, want %d isolated entries", keys, len(seen))
	}
}

func TestRedisCacheSharesCachedProviderFailure(t *testing.T) {
	server := miniredis.RunT(t)
	clock := &fakeCacheClock{now: cacheTestTime}
	first, second := newTestRedisCaches(t, server, clock, "negative", 0)
	firstCoordinator := testCacheCoordinator(t, first, clock)
	secondCoordinator := testCacheCoordinator(t, second, clock)
	request := CacheRequest{Key: testCacheKey("pwhois"), Policy: CachePolicyReadThrough}

	_, err := firstCoordinator.Lookup(context.Background(), request, func(context.Context) (CacheFetchResult, error) {
		return CacheFetchResult{}, ErrNoRecords
	})
	if !errors.Is(err, ErrNoRecords) {
		t.Fatalf("first Lookup error = %v, want ErrNoRecords", err)
	}

	fetchCalls := 0
	result, err := secondCoordinator.Lookup(context.Background(), request, func(context.Context) (CacheFetchResult, error) {
		fetchCalls++
		return CacheFetchResult{}, errors.New("must not fetch")
	})
	if !errors.Is(err, ErrNoRecords) {
		t.Fatalf("second Lookup error = %v, want cached ErrNoRecords", err)
	}
	var cachedError *CachedProviderError
	if !errors.As(err, &cachedError) || cachedError.Class != ProviderErrorNoRecords {
		t.Fatalf("cached provider error = %v", err)
	}
	if result.State != CacheStateHit || !result.CacheHit || fetchCalls != 0 {
		t.Fatalf("cached result = %+v, fetch calls %d", result, fetchCalls)
	}
}

func TestRedisCacheOutageRemainsSeparateFromProviderError(t *testing.T) {
	server := miniredis.RunT(t)
	clock := &fakeCacheClock{now: cacheTestTime}
	cache, err := NewRedisCache(RedisCacheConfig{
		Address:   server.Addr(),
		KeyPrefix: "outage",
		Clock:     clock,
	})
	if err != nil {
		t.Fatalf("NewRedisCache: %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })
	coordinator := testCacheCoordinator(t, cache, clock)
	server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, lookupErr := coordinator.Lookup(ctx, CacheRequest{
		Key:    testCacheKey("pwhois"),
		Policy: CachePolicyReadThrough,
	}, func(context.Context) (CacheFetchResult, error) {
		return CacheFetchResult{}, ErrConnection
	})
	if !errors.Is(lookupErr, ErrConnection) {
		t.Fatalf("provider error = %v, want ErrConnection", lookupErr)
	}
	if result.CacheError == nil || !errors.Is(result.CacheError, ErrCacheUnavailable) {
		t.Fatalf("cache outage result = %+v", result)
	}
	if errors.Is(result.CacheError, ErrConnection) {
		t.Fatalf("cache outage was misclassified as provider connection error: %v", result.CacheError)
	}
}

func TestRedisCacheRejectsCorruptedAndOversizedValues(t *testing.T) {
	server := miniredis.RunT(t)
	clock := &fakeCacheClock{now: cacheTestTime}
	cache, err := NewRedisCache(RedisCacheConfig{
		Address:       server.Addr(),
		KeyPrefix:     "corruption",
		Clock:         clock,
		MaxEntryBytes: 512,
	})
	if err != nil {
		t.Fatalf("NewRedisCache: %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })
	key, _, entry := testRedisEnvelope(t, "pwhois", cacheTestTime, cacheTestTime.Add(time.Hour))
	storageKey, _ := cache.storageKey(key)

	tests := []struct {
		name      string
		value     string
		wantError error
	}{
		{name: "empty", value: "", wantError: ErrInvalidCacheEntry},
		{name: "malformed JSON", value: "{", wantError: ErrInvalidCacheEntry},
		{name: "unknown field", value: `{"unknown":true}`, wantError: ErrInvalidCacheEntry},
		{name: "oversized", value: strings.Repeat("x", 513), wantError: ErrCacheEntryTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server.Set(storageKey, test.value)
			_, found, err := cache.Get(context.Background(), key)
			if found || !errors.Is(err, test.wantError) {
				t.Fatalf("Get = found %t, error %v; want %v", found, err, test.wantError)
			}
		})
	}

	entry.Key = "different-key"
	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal mismatched entry: %v", err)
	}
	server.Set(storageKey, string(encoded))
	if _, found, err := cache.Get(context.Background(), key); found || !errors.Is(err, ErrInvalidCacheEntry) {
		t.Fatalf("mismatched Get = found %t, error %v", found, err)
	}
}

func TestRedisCacheSetValidation(t *testing.T) {
	server := miniredis.RunT(t)
	clock := &fakeCacheClock{now: cacheTestTime}
	cache, err := NewRedisCache(RedisCacheConfig{
		Address:       server.Addr(),
		KeyPrefix:     "set-validation",
		Clock:         clock,
		MaxEntryBytes: 512,
	})
	if err != nil {
		t.Fatalf("NewRedisCache: %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })
	key, _, entry := testRedisEnvelope(t, "pwhois", cacheTestTime, cacheTestTime.Add(time.Hour))

	expired := entry
	expired.ExpiresAt = cacheTestTime.Add(-time.Second)
	if err := cache.Set(context.Background(), key, expired); !errors.Is(err, ErrInvalidCacheEntry) {
		t.Fatalf("expired Set error = %v", err)
	}

	oversized := entry
	oversized.NormalizedResult = json.RawMessage(`{"value":"` + strings.Repeat("x", 512) + `"}`)
	if err := cache.Set(context.Background(), key, oversized); !errors.Is(err, ErrCacheEntryTooLarge) {
		t.Fatalf("oversized Set error = %v", err)
	}

	mismatched := entry
	mismatched.Key = "different"
	if err := cache.Set(context.Background(), key, mismatched); !errors.Is(err, ErrInvalidCacheEntry) {
		t.Fatalf("mismatched Set error = %v", err)
	}
}

func TestNewRedisCacheConfiguration(t *testing.T) {
	caller := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = caller.Close() })
	secret := "do-not-expose"

	tests := []struct {
		name   string
		config RedisCacheConfig
	}{
		{name: "missing prefix", config: RedisCacheConfig{Address: "127.0.0.1:6379"}},
		{name: "blank prefix", config: RedisCacheConfig{Address: "127.0.0.1:6379", KeyPrefix: " \t "}},
		{name: "control prefix", config: RedisCacheConfig{Address: "127.0.0.1:6379", KeyPrefix: "bad\nprefix"}},
		{name: "missing connection", config: RedisCacheConfig{KeyPrefix: "test"}},
		{name: "address and URL", config: RedisCacheConfig{Address: "127.0.0.1:6379", URL: "redis://127.0.0.1:6379", KeyPrefix: "test"}},
		{name: "negative database", config: RedisCacheConfig{Address: "127.0.0.1:6379", DB: -1, KeyPrefix: "test"}},
		{name: "credential conflict", config: RedisCacheConfig{
			Address: "127.0.0.1:6379", Username: "user", Password: "password",
			CredentialsProvider: func() (string, string) { return "dynamic", "secret" },
			KeyPrefix:           "test",
		}},
		{name: "URL credential override", config: RedisCacheConfig{
			URL: "redis://127.0.0.1:6379", Password: "password", KeyPrefix: "test",
		}},
		{name: "caller client conflict", config: RedisCacheConfig{
			Client: caller, Address: "127.0.0.1:6379", KeyPrefix: "test",
		}},
		{name: "negative stale retention", config: RedisCacheConfig{
			Address: "127.0.0.1:6379", KeyPrefix: "test", StaleRetention: -time.Second,
		}},
		{name: "invalid URL", config: RedisCacheConfig{
			URL: "not-a-url://" + secret, KeyPrefix: "test",
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cache, err := NewRedisCache(test.config)
			if cache != nil || !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("NewRedisCache = cache %v, error %v; want ErrInvalidInput", cache, err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("configuration error exposed Redis URL secret: %v", err)
			}
		})
	}
}

func TestNewRedisCacheMapsAddressAndURLSettings(t *testing.T) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "redis.example.test"}
	credentialsProvider := func() (string, string) { return "dynamic-user", "dynamic-password" }
	cache, err := NewRedisCache(RedisCacheConfig{
		Address:             "redis.example.test:6380",
		DB:                  3,
		CredentialsProvider: credentialsProvider,
		TLSConfig:           tlsConfig,
		KeyPrefix:           "settings:",
	})
	if err != nil {
		t.Fatalf("NewRedisCache(address): %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })
	client, ok := cache.client.(*redis.Client)
	if !ok {
		t.Fatalf("client type = %T, want *redis.Client", cache.client)
	}
	options := client.Options()
	if options.Addr != "redis.example.test:6380" || options.DB != 3 ||
		options.Protocol != 2 || options.MaxRetries != 0 || options.DialerRetries != 1 ||
		!options.ContextTimeoutEnabled || !options.DisableIdentity {
		t.Fatalf("address options = %+v", options)
	}
	if username, password := options.CredentialsProvider(); username != "dynamic-user" || password != "dynamic-password" {
		t.Fatalf("dynamic credentials = %q/%q", username, password)
	}
	if options.TLSConfig == tlsConfig || options.TLSConfig.MinVersion != tls.VersionTLS13 ||
		options.TLSConfig.ServerName != "redis.example.test" {
		t.Fatalf("TLS options were not cloned: %+v", options.TLSConfig)
	}
	if cache.keyPrefix != "settings:" {
		t.Fatalf("normalized key prefix = %q", cache.keyPrefix)
	}

	urlCache, err := NewRedisCache(RedisCacheConfig{
		URL:       "redis://url-user:url-password@127.0.0.1:6379/4",
		KeyPrefix: "url-settings",
	})
	if err != nil {
		t.Fatalf("NewRedisCache(URL): %v", err)
	}
	t.Cleanup(func() { _ = urlCache.Close() })
	urlClient := urlCache.client.(*redis.Client)
	urlOptions := urlClient.Options()
	if urlOptions.Username != "url-user" || urlOptions.Password != "url-password" ||
		urlOptions.DB != 4 || urlOptions.Protocol != 2 || urlOptions.MaxRetries != 0 ||
		urlOptions.DialerRetries != 1 {
		t.Fatalf("URL options = %+v", urlOptions)
	}
}

func TestRedisCacheSupportsACLAndDatabaseConfiguration(t *testing.T) {
	server := miniredis.RunT(t)
	server.RequireUserAuth("cache-user", "cache-password")
	clock := &fakeCacheClock{now: cacheTestTime}
	writer, err := NewRedisCache(RedisCacheConfig{
		Address:   server.Addr(),
		DB:        2,
		Username:  "cache-user",
		Password:  "cache-password",
		KeyPrefix: "authenticated",
		Clock:     clock,
	})
	if err != nil {
		t.Fatalf("NewRedisCache writer: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	reader, err := NewRedisCache(RedisCacheConfig{
		Address: server.Addr(),
		DB:      2,
		CredentialsProvider: func() (string, string) {
			return "cache-user", "cache-password"
		},
		KeyPrefix: "authenticated",
		Clock:     clock,
	})
	if err != nil {
		t.Fatalf("NewRedisCache reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	key, _, entry := testRedisEnvelope(t, "pwhois", cacheTestTime, cacheTestTime.Add(time.Hour))

	if err := writer.Set(context.Background(), key, entry); err != nil {
		t.Fatalf("authenticated Set: %v", err)
	}
	if _, found, err := reader.Get(context.Background(), key); err != nil || !found {
		t.Fatalf("dynamic-credential Get = found %t, error %v", found, err)
	}
	storageKey, _ := writer.storageKey(key)
	if !server.DB(2).Exists(storageKey) || server.DB(0).Exists(storageKey) {
		t.Fatalf("entry was not isolated in configured Redis database")
	}
}

func TestRedisCacheCallerOwnsSuppliedClient(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{
		Addr:            server.Addr(),
		Protocol:        2,
		DisableIdentity: true,
	})
	t.Cleanup(func() { _ = client.Close() })
	cache, err := NewRedisCache(RedisCacheConfig{
		Client:    client,
		KeyPrefix: "caller-owned",
	})
	if err != nil {
		t.Fatalf("NewRedisCache: %v", err)
	}
	if err := cache.Close(); err != nil {
		t.Fatalf("Close caller-owned cache: %v", err)
	}
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("caller-owned client was closed: %v", err)
	}

	owned, err := NewRedisCache(RedisCacheConfig{
		Address:   server.Addr(),
		KeyPrefix: "owned",
	})
	if err != nil {
		t.Fatalf("NewRedisCache owned: %v", err)
	}
	ownedClient := owned.client
	if err := owned.Close(); err != nil {
		t.Fatalf("Close owned cache: %v", err)
	}
	if err := owned.Close(); err != nil {
		t.Fatalf("second Close owned cache: %v", err)
	}
	if err := ownedClient.Ping(context.Background()).Err(); err == nil {
		t.Fatal("owned client remained usable after Close")
	}
}

func TestRedisCacheContextAndKeyValidation(t *testing.T) {
	server := miniredis.RunT(t)
	cache, err := NewRedisCache(RedisCacheConfig{
		Address:   server.Addr(),
		KeyPrefix: "validation",
	})
	if err != nil {
		t.Fatalf("NewRedisCache: %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })
	key, _, entry := testRedisEnvelope(t, "pwhois", time.Now().UTC(), time.Now().UTC().Add(time.Hour))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := cache.Get(ctx, key); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Get error = %v", err)
	}
	if err := cache.Set(ctx, key, entry); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Set error = %v", err)
	}
	if err := cache.Delete(ctx, key); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Delete error = %v", err)
	}
	for _, invalidKey := range []string{"", "bad key", "bad\nkey"} {
		if _, _, err := cache.Get(context.Background(), invalidKey); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("key %q Get error = %v", invalidKey, err)
		}
	}

	var zero RedisCache
	if _, _, err := zero.Get(context.Background(), key); !errors.Is(err, ErrCacheUnavailable) {
		t.Fatalf("zero RedisCache Get error = %v", err)
	}
}
