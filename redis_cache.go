package pwhois

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisCacheKeyMaximumBytes = 1024

// RedisCacheConfig configures a Redis-backed Cache. KeyPrefix is required so
// entries cannot collide with unrelated applications in a shared Redis
// deployment.
//
// Set either Address or URL when RedisCache should create and own a go-redis
// client. Set Client instead to use a caller-owned client; connection and
// credential fields must then remain empty. Credentials are never discovered
// from environment variables or files by this package.
type RedisCacheConfig struct {
	Address  string
	URL      string
	DB       int
	Username string
	Password string
	// CredentialsProvider supplies ACL username and password values when a
	// newly created client opens a connection. It is mutually exclusive with
	// Username and Password.
	CredentialsProvider func() (username string, password string)
	TLSConfig           *tls.Config

	KeyPrefix string
	// MaxEntryBytes bounds a Redis value both before storage and while reading.
	// A value less than or equal to zero uses DefaultMaxResponseBytes.
	MaxEntryBytes int64
	// StaleRetention keeps an expired envelope physically available for a
	// bounded stale-if-error window. It does not change ExpiresAt or make the
	// entry fresh. Zero removes the Redis key at ExpiresAt.
	StaleRetention time.Duration
	// Clock exists for deterministic expiration tests. The zero value uses the
	// system clock.
	Clock CacheClock

	// Client is an optional caller-owned go-redis client. RedisCache.Close does
	// not close it.
	Client redis.UniversalClient
}

// RedisCache stores versioned CacheEnvelope values in Redis using atomic SET
// with expiration. The zero value is not usable; construct one with
// NewRedisCache.
type RedisCache struct {
	client         redis.UniversalClient
	keyPrefix      string
	maxEntryBytes  int64
	staleRetention time.Duration
	clock          CacheClock
	ownsClient     bool
	closeOnce      sync.Once
	closeErr       error
}

// NewRedisCache validates config and returns a Redis-backed cache. Address
// clients use RESP2, context-aware command deadlines, no automatic retries,
// and no client-identity command. URL clients retain URL transport settings
// while applying those same cache-operation safeguards.
func NewRedisCache(config RedisCacheConfig) (*RedisCache, error) {
	keyPrefix, err := normalizeRedisCacheKeyPrefix(config.KeyPrefix)
	if err != nil {
		return nil, err
	}
	if config.DB < 0 {
		return nil, invalidInputError("Redis database must not be negative")
	}
	if config.StaleRetention < 0 {
		return nil, invalidInputError("Redis stale retention must not be negative")
	}

	maxEntryBytes := config.MaxEntryBytes
	if maxEntryBytes <= 0 {
		maxEntryBytes = DefaultMaxResponseBytes
	}
	clock := config.Clock
	if clock == nil {
		clock = systemCacheClock{}
	}

	cache := &RedisCache{
		keyPrefix:      keyPrefix,
		maxEntryBytes:  maxEntryBytes,
		staleRetention: config.StaleRetention,
		clock:          clock,
	}

	if config.Client != nil {
		if redisConnectionConfigPresent(config) {
			return nil, invalidInputError("caller-owned Redis client cannot be combined with connection configuration")
		}
		cache.client = config.Client
		return cache, nil
	}

	options, err := redisClientOptions(config)
	if err != nil {
		return nil, err
	}
	cache.client = redis.NewClient(options)
	cache.ownsClient = true
	return cache, nil
}

func redisConnectionConfigPresent(config RedisCacheConfig) bool {
	return strings.TrimSpace(config.Address) != "" ||
		strings.TrimSpace(config.URL) != "" ||
		config.DB != 0 ||
		config.Username != "" ||
		config.Password != "" ||
		config.CredentialsProvider != nil ||
		config.TLSConfig != nil
}

func redisClientOptions(config RedisCacheConfig) (*redis.Options, error) {
	address := strings.TrimSpace(config.Address)
	redisURL := strings.TrimSpace(config.URL)
	if address == "" && redisURL == "" {
		return nil, invalidInputError("Redis address or URL is required")
	}
	if address != "" && redisURL != "" {
		return nil, invalidInputError("Redis address and URL are mutually exclusive")
	}
	if config.CredentialsProvider != nil && (config.Username != "" || config.Password != "") {
		return nil, invalidInputError("Redis credential provider is mutually exclusive with static credentials")
	}

	var options *redis.Options
	if redisURL != "" {
		if config.DB != 0 || config.Username != "" || config.Password != "" || config.CredentialsProvider != nil {
			return nil, invalidInputError("Redis URL cannot be combined with separate database or credentials")
		}
		parsed, err := redis.ParseURL(redisURL)
		if err != nil {
			// Do not retain or expose a URL that may contain credentials.
			return nil, invalidInputError("Redis URL is invalid")
		}
		options = parsed
	} else {
		options = &redis.Options{
			Addr:                address,
			DB:                  config.DB,
			Username:            config.Username,
			Password:            config.Password,
			CredentialsProvider: config.CredentialsProvider,
		}
	}

	if config.TLSConfig != nil {
		options.TLSConfig = config.TLSConfig.Clone()
	}
	options.Protocol = 2
	options.ContextTimeoutEnabled = true
	options.MaxRetries = -1
	options.DialerRetries = 1
	options.DisableIdentity = true
	return options, nil
}

func normalizeRedisCacheKeyPrefix(value string) (string, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimRight(value, ":")
	if value == "" {
		return "", invalidInputError("Redis key prefix is required")
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return "", invalidInputError("Redis key prefix must use printable non-space ASCII")
		}
	}
	if len(value)+1 >= redisCacheKeyMaximumBytes {
		return "", invalidInputError("Redis key prefix is too long")
	}
	return value + ":", nil
}

func (cache *RedisCache) storageKey(key string) (string, error) {
	if key == "" {
		return "", invalidInputError("cache key is required")
	}
	for _, character := range key {
		if character < 0x21 || character > 0x7e {
			return "", invalidInputError("cache key must use printable non-space ASCII")
		}
	}
	if len(cache.keyPrefix)+len(key) > redisCacheKeyMaximumBytes {
		return "", invalidInputError("Redis cache key is too long")
	}
	return cache.keyPrefix + key, nil
}

func (cache *RedisCache) usable(ctx context.Context) error {
	if ctx == nil {
		return invalidInputError("cache context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if cache == nil || cache.client == nil || cache.clock == nil || cache.maxEntryBytes <= 0 {
		return ErrCacheUnavailable
	}
	return nil
}

// Get atomically checks existence and reads at most MaxEntryBytes+1 bytes,
// reports a missing key as found=false, and rejects malformed, mismatched, or
// oversized envelopes.
func (cache *RedisCache) Get(ctx context.Context, key string) (CacheEnvelope, bool, error) {
	if err := cache.usable(ctx); err != nil {
		return CacheEnvelope{}, false, err
	}
	storageKey, err := cache.storageKey(key)
	if err != nil {
		return CacheEnvelope{}, false, err
	}

	var (
		valueCommand  *redis.StringCmd
		existsCommand *redis.IntCmd
	)
	_, err = cache.client.TxPipelined(ctx, func(pipeline redis.Pipeliner) error {
		valueCommand = pipeline.GetRange(ctx, storageKey, 0, cache.maxEntryBytes)
		existsCommand = pipeline.Exists(ctx, storageKey)
		return nil
	})
	if err != nil {
		return CacheEnvelope{}, false, err
	}
	if existsCommand.Val() == 0 {
		return CacheEnvelope{}, false, nil
	}
	value := valueCommand.Val()
	if value == "" {
		return CacheEnvelope{}, false, ErrInvalidCacheEntry
	}
	if int64(len(value)) > cache.maxEntryBytes {
		return CacheEnvelope{}, false, &CacheEntryTooLargeError{Limit: cache.maxEntryBytes}
	}

	var entry CacheEnvelope
	decoder := json.NewDecoder(bytes.NewBufferString(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&entry); err != nil {
		return CacheEnvelope{}, false, fmt.Errorf("%w: decode Redis envelope", ErrInvalidCacheEntry)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return CacheEnvelope{}, false, err
	}
	if err := validateCacheEnvelopeStructure(key, entry, cache.maxEntryBytes); err != nil {
		return CacheEnvelope{}, false, err
	}
	return entry, true, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return fmt.Errorf("%w: trailing Redis envelope content", ErrInvalidCacheEntry)
}

// Set atomically stores one versioned envelope with a Redis TTL. The physical
// TTL ends at ExpiresAt plus the configured StaleRetention.
func (cache *RedisCache) Set(ctx context.Context, key string, entry CacheEnvelope) error {
	if err := cache.usable(ctx); err != nil {
		return err
	}
	storageKey, err := cache.storageKey(key)
	if err != nil {
		return err
	}
	if err := validateCacheEnvelopeStructure(key, entry, cache.maxEntryBytes); err != nil {
		return err
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("%w: encode Redis envelope", ErrInvalidCacheEntry)
	}

	ttl := entry.ExpiresAt.Sub(cache.clock.Now().UTC()) + cache.staleRetention
	if ttl < time.Millisecond {
		return fmt.Errorf("%w: Redis envelope retention has elapsed", ErrInvalidCacheEntry)
	}
	return cache.client.Set(ctx, storageKey, encoded, ttl).Err()
}

// Delete removes one namespaced cache entry. Deleting a missing key succeeds.
func (cache *RedisCache) Delete(ctx context.Context, key string) error {
	if err := cache.usable(ctx); err != nil {
		return err
	}
	storageKey, err := cache.storageKey(key)
	if err != nil {
		return err
	}
	return cache.client.Del(ctx, storageKey).Err()
}

// Close releases a client created by NewRedisCache. It is a no-op when Client
// was supplied by the caller.
func (cache *RedisCache) Close() error {
	if cache == nil || !cache.ownsClient || cache.client == nil {
		return nil
	}
	cache.closeOnce.Do(func() {
		cache.closeErr = cache.client.Close()
	})
	return cache.closeErr
}

var _ Cache = (*RedisCache)(nil)
