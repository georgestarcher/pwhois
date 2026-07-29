package pwhois

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	teamCymruSingleRequest = "begin\nverbose\nnoheader\n192.0.2.1\nend\n"
	teamCymruBatchRequest  = "begin\nverbose\nnoheader\n192.0.2.1\n198.51.100.2\nend\n"
	teamCymruSingleResult  = "64500 | 192.0.2.1 | 192.0.2.0/24 | ZZ | test | 2020-01-02 | EXAMPLE-AS - Example Network, ZZ"
)

func loopbackTeamCymruProvider(t *testing.T, script loopbackProtocolScript) (TeamCymruProvider, <-chan loopbackProtocolResult) {
	t.Helper()

	server, results := startLoopbackProtocolServer(t, script)
	return TeamCymruProvider{
		Server:           server.Server,
		Port:             server.Port,
		BatchMaxSize:     DefaultTeamCymruBatchMaxSize,
		Timeout:          server.Timeout,
		MaxResponseBytes: server.MaxResponseBytes,
	}, results
}

func TestTeamCymruSingleAndBatchLookups(t *testing.T) {
	tests := []struct {
		name            string
		inputs          []string
		expectedRequest string
		response        string
		check           func(*testing.T, []TeamCymruIPResult)
	}{
		{
			name:            "single",
			inputs:          []string{"192.0.2.1"},
			expectedRequest: teamCymruSingleRequest,
			response:        teamCymruSingleResult,
			check: func(t *testing.T, results []TeamCymruIPResult) {
				t.Helper()
				if len(results) != 1 {
					t.Fatalf("results = %+v", results)
				}
				result := results[0]
				if !result.Found || result.IP != "192.0.2.1" || result.Prefix != "192.0.2.0/24" {
					t.Fatalf("result = %+v", result)
				}
				if len(result.OriginASNs) != 1 || result.OriginASNs[0] != 64500 {
					t.Fatalf("origin ASNs = %v", result.OriginASNs)
				}
				if result.CountryCode != "ZZ" || result.Registry != "test" ||
					result.ASName != "EXAMPLE-AS - Example Network, ZZ" {
					t.Fatalf("allocation metadata = %+v", result)
				}
				if want := time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC); !result.AllocatedDate.Equal(want) {
					t.Fatalf("allocated date = %v, want %v", result.AllocatedDate, want)
				}
			},
		},
		{
			name:            "batch canonicalizes and deduplicates",
			inputs:          []string{" 192.0.2.1 ", "198.51.100.2", "192.0.2.1"},
			expectedRequest: teamCymruBatchRequest,
			response: "Bulk mode; test fixture\n" +
				"AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name\n" +
				"64500 64501 | 192.0.2.1 | 192.0.2.0/24 | ZZ | TEST | 2020-01-02 | EXAMPLE | NETWORK\n" +
				"64502 | 198.51.100.2 | 198.51.100.0/24 | ZZ | TEST | NA | SECOND-AS",
			check: func(t *testing.T, results []TeamCymruIPResult) {
				t.Helper()
				if len(results) != 2 {
					t.Fatalf("results = %+v", results)
				}
				if got := results[0].OriginASNs; len(got) != 2 || got[0] != 64500 || got[1] != 64501 {
					t.Fatalf("multi-origin ASNs = %v", got)
				}
				if results[0].ASName != "EXAMPLE | NETWORK" {
					t.Fatalf("delimiter-containing AS name = %q", results[0].ASName)
				}
				if !results[1].AllocatedDate.IsZero() {
					t.Fatalf("NA allocation date = %v, want zero", results[1].AllocatedDate)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider, protocolResult := loopbackTeamCymruProvider(t, loopbackProtocolScript{
				expectedRequest: test.expectedRequest,
				responseChunks:  []string{test.response},
			})
			started := time.Now().UTC()

			results, err := provider.LookupIPContext(context.Background(), test.inputs)
			if err != nil {
				t.Fatalf("LookupIPContext: %v", err)
			}
			finished := time.Now().UTC()
			test.check(t, results)
			for _, result := range results {
				if result.Source != TeamCymruSource || result.Endpoint != provider.ServerAddressString() {
					t.Fatalf("provenance = %+v", result)
				}
				if result.FetchedAt.Before(started) || result.FetchedAt.After(finished) {
					t.Fatalf("fetched at = %v, want between %v and %v", result.FetchedAt, started, finished)
				}
			}
			verifyAutomaticallyClosedLoopbackProtocol(t, protocolResult, test.expectedRequest)
		})
	}
}

func TestParseTeamCymruResponseFailures(t *testing.T) {
	fetchedAt := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		requested []string
		response  string
		wantError error
	}{
		{
			name:      "empty",
			requested: []string{"192.0.2.1"},
			response:  "",
			wantError: ErrNoRecords,
		},
		{
			name:      "explicit no record",
			requested: []string{"192.0.2.1"},
			response:  "NA | 192.0.2.1 | NA | NA | NA | NA | NA",
			wantError: ErrNoRecords,
		},
		{
			name:      "too few fields",
			requested: []string{"192.0.2.1"},
			response:  "64500 | 192.0.2.1",
			wantError: ErrMalformedResponse,
		},
		{
			name:      "inconsistent no record",
			requested: []string{"192.0.2.1"},
			response:  "NA | 192.0.2.1 | 192.0.2.0/24 | ZZ | test | NA | NA",
			wantError: ErrMalformedResponse,
		},
		{
			name:      "invalid ASN",
			requested: []string{"192.0.2.1"},
			response:  "not-an-asn | 192.0.2.1 | 192.0.2.0/24 | ZZ | test | NA | Example",
			wantError: ErrMalformedResponse,
		},
		{
			name:      "invalid prefix",
			requested: []string{"192.0.2.1"},
			response:  "64500 | 192.0.2.1 | not-a-prefix | ZZ | test | NA | Example",
			wantError: ErrMalformedResponse,
		},
		{
			name:      "invalid allocation date",
			requested: []string{"192.0.2.1"},
			response:  "64500 | 192.0.2.1 | 192.0.2.0/24 | ZZ | test | yesterday | Example",
			wantError: ErrMalformedResponse,
		},
		{
			name:      "unrequested IP",
			requested: []string{"192.0.2.1"},
			response:  "64500 | 198.51.100.2 | 198.51.100.0/24 | ZZ | test | NA | Example",
			wantError: ErrMalformedResponse,
		},
		{
			name:      "missing requested IP is partial failure",
			requested: []string{"192.0.2.1", "198.51.100.2"},
			response:  teamCymruSingleResult,
			wantError: ErrMalformedResponse,
		},
		{
			name:      "duplicate with different Found state",
			requested: []string{"192.0.2.1"},
			response: teamCymruSingleResult +
				"\nNA | 192.0.2.1 | NA | NA | NA | NA | NA",
			wantError: ErrMalformedResponse,
		},
		{
			name:      "duplicate with different origin data",
			requested: []string{"192.0.2.1"},
			response: teamCymruSingleResult +
				"\n64501 | 192.0.2.1 | 192.0.2.0/24 | ZZ | test | 2020-01-02 | OTHER-AS",
			wantError: ErrMalformedResponse,
		},
		{
			name:      "prefix does not contain IP",
			requested: []string{"192.0.2.1"},
			response:  "64500 | 192.0.2.1 | 198.51.100.0/24 | ZZ | test | NA | Example",
			wantError: ErrMalformedResponse,
		},
		{
			name:      "prefix address family differs",
			requested: []string{"192.0.2.1"},
			response:  "64500 | 192.0.2.1 | 2001:db8::/32 | ZZ | test | NA | Example",
			wantError: ErrMalformedResponse,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseTeamCymruIPResponse(test.requested, test.response, "test.example:43", fetchedAt)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("parse error = %v, want %v", err, test.wantError)
			}
		})
	}
}

func TestParseTeamCymruResponsePreservesPerIPNoRecord(t *testing.T) {
	fetchedAt := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	results, err := parseTeamCymruIPResponse(
		[]string{"192.0.2.1", "198.51.100.2"},
		teamCymruSingleResult+"\nNA | 198.51.100.2 | NA | NA | NA | NA | NA",
		"test.example:43",
		fetchedAt,
	)
	if err != nil {
		t.Fatalf("parse mixed response: %v", err)
	}
	if len(results) != 2 || !results[0].Found || results[1].Found ||
		results[1].IP != "198.51.100.2" || !results[1].FetchedAt.Equal(fetchedAt) {
		t.Fatalf("mixed results = %+v", results)
	}
}

func TestTeamCymruProviderResponseErrors(t *testing.T) {
	tests := []struct {
		name      string
		response  string
		wantError error
	}{
		{name: "rate limit", response: "Error: Query limit exceeded", wantError: ErrRateLimited},
		{name: "provider rejected", response: "Error: invalid query option", wantError: ErrProviderRejected},
		{name: "no records", response: "", wantError: ErrNoRecords},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider, protocolResult := loopbackTeamCymruProvider(t, loopbackProtocolScript{
				expectedRequest: teamCymruSingleRequest,
				responseChunks:  []string{test.response},
			})
			_, err := provider.LookupIPContext(context.Background(), []string{"192.0.2.1"})
			if !errors.Is(err, test.wantError) {
				t.Fatalf("lookup error = %v, want %v", err, test.wantError)
			}
			var operationError *OperationError
			if !errors.As(err, &operationError) || operationError.Operation != "lookup Team Cymru IP-to-ASN" {
				t.Fatalf("operation error = %#v", operationError)
			}
			verifyAutomaticallyClosedLoopbackProtocol(t, protocolResult, teamCymruSingleRequest)
		})
	}
}

func TestTeamCymruRateLimitPhraseInsideASNameIsData(t *testing.T) {
	response := "64500 | 192.0.2.1 | 192.0.2.0/24 | ZZ | test | 2020-01-02 | RATE LIMIT RESEARCH NETWORK"
	provider, protocolResult := loopbackTeamCymruProvider(t, loopbackProtocolScript{
		expectedRequest: teamCymruSingleRequest,
		responseChunks:  []string{response},
	})

	results, err := provider.LookupIPContext(context.Background(), []string{"192.0.2.1"})
	if err != nil {
		t.Fatalf("LookupIPContext: %v", err)
	}
	if len(results) != 1 || results[0].ASName != "RATE LIMIT RESEARCH NETWORK" {
		t.Fatalf("results = %+v", results)
	}
	verifyAutomaticallyClosedLoopbackProtocol(t, protocolResult, teamCymruSingleRequest)
}

func TestTeamCymruProviderCancellationAndTimeout(t *testing.T) {
	tests := []struct {
		name      string
		context   func() (context.Context, context.CancelFunc)
		timeout   time.Duration
		wantError error
	}{
		{
			name: "caller cancellation",
			context: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				time.AfterFunc(50*time.Millisecond, cancel)
				return ctx, cancel
			},
			timeout:   2 * time.Second,
			wantError: ErrCanceled,
		},
		{
			name: "provider timeout",
			context: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			timeout:   50 * time.Millisecond,
			wantError: ErrTimeout,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider, protocolResult := loopbackTeamCymruProvider(t, loopbackProtocolScript{
				expectedRequest: teamCymruSingleRequest,
				noResponse:      true,
			})
			provider.Timeout = test.timeout
			ctx, cancel := test.context()
			defer cancel()

			_, err := provider.LookupIPContext(ctx, []string{"192.0.2.1"})
			if !errors.Is(err, test.wantError) {
				t.Fatalf("lookup error = %v, want %v", err, test.wantError)
			}
			verifyAutomaticallyClosedLoopbackProtocol(t, protocolResult, teamCymruSingleRequest)
		})
	}
}

func TestTeamCymruProviderBoundsResponse(t *testing.T) {
	provider, protocolResult := loopbackTeamCymruProvider(t, loopbackProtocolScript{
		expectedRequest: teamCymruSingleRequest,
		responseChunks:  []string{teamCymruSingleResult},
	})
	provider.MaxResponseBytes = int64(len(teamCymruSingleResult) - 1)

	_, err := provider.LookupIPContext(context.Background(), []string{"192.0.2.1"})
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("lookup error = %v, want ErrResponseTooLarge", err)
	}
	var sizeError *ResponseTooLargeError
	if !errors.As(err, &sizeError) || sizeError.Limit != provider.MaxResponseBytes {
		t.Fatalf("size error = %#v", sizeError)
	}
	verifyAutomaticallyClosedLoopbackProtocol(t, protocolResult, teamCymruSingleRequest)
}

type countingContextDialer struct {
	calls atomic.Int64
}

func (dialer *countingContextDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	dialer.calls.Add(1)
	return nil, fmt.Errorf("unexpected dial")
}

func TestTeamCymruProviderValidatesBeforeDial(t *testing.T) {
	tests := []struct {
		name     string
		inputs   []string
		batchMax int
	}{
		{name: "empty", inputs: nil, batchMax: 1000},
		{name: "invalid IP", inputs: []string{"not-an-ip"}, batchMax: 1000},
		{name: "batch over limit", inputs: []string{"192.0.2.1", "198.51.100.2"}, batchMax: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dialer := &countingContextDialer{}
			provider := TeamCymruProvider{BatchMaxSize: test.batchMax, Dialer: dialer}
			_, err := provider.LookupIPContext(context.Background(), test.inputs)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("lookup error = %v, want ErrInvalidInput", err)
			}
			if calls := dialer.calls.Load(); calls != 0 {
				t.Fatalf("dial calls = %d, want 0", calls)
			}
		})
	}
}

func TestTeamCymruProviderCanonicalizesIPv6(t *testing.T) {
	normalized, err := normalizeTeamCymruIPs(
		[]string{"2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		DefaultTeamCymruBatchMaxSize,
	)
	if err != nil {
		t.Fatalf("normalize IPv6: %v", err)
	}
	if len(normalized) != 1 || normalized[0] != "2001:db8::1" {
		t.Fatalf("normalized IPv6 = %v", normalized)
	}
}

func TestTeamCymruCacheKeyIsSourceSpecific(t *testing.T) {
	provider := TeamCymruProvider{}
	spec, err := provider.CacheKeySpec([]string{"192.0.2.1", "192.0.2.1"})
	if err != nil {
		t.Fatalf("CacheKeySpec: %v", err)
	}
	if spec.Source != TeamCymruSource || spec.Endpoint != "whois.cymru.com:43" ||
		spec.Protocol != TeamCymruProtocolVersion || spec.NormalizedQuery != "192.0.2.1" {
		t.Fatalf("cache spec = %+v", spec)
	}

	cymruKey, err := CanonicalCacheKey(spec)
	if err != nil {
		t.Fatalf("Team Cymru key: %v", err)
	}
	pwhoisSpec := spec
	pwhoisSpec.Source = "pwhois"
	pwhoisSpec.Endpoint = "whois.pwhois.org:43"
	pwhoisSpec.Protocol = "pwhois"
	pwhoisKey, err := CanonicalCacheKey(pwhoisSpec)
	if err != nil {
		t.Fatalf("PWHOIS key: %v", err)
	}
	if cymruKey == pwhoisKey || !strings.HasPrefix(cymruKey, "pwhois-cache:v1:team-cymru:") {
		t.Fatalf("source-specific keys = %q and %q", cymruKey, pwhoisKey)
	}
}

func TestTeamCymruProviderRejectedErrorClassification(t *testing.T) {
	err := &OperationError{Operation: "lookup Team Cymru IP-to-ASN", Err: ErrProviderRejected}
	if got := ClassifyProviderError(err); got != ProviderErrorRejected {
		t.Fatalf("provider class = %q, want %q", got, ProviderErrorRejected)
	}
	if sentinel := providerErrorSentinel(ProviderErrorRejected); !errors.Is(sentinel, ErrProviderRejected) {
		t.Fatalf("provider sentinel = %v, want ErrProviderRejected", sentinel)
	}
}

func TestCacheCoordinatorDoesNotCacheTeamCymruRejection(t *testing.T) {
	clock := &fakeCacheClock{now: cacheTestTime}
	cache := newFakeCache()
	coordinator, err := NewCacheCoordinator(CacheCoordinatorConfig{
		Cache: cache,
		Clock: clock,
		SourcePolicies: map[string]SourceCachePolicy{
			TeamCymruSource: {
				SuccessTTL:     4 * time.Hour,
				NoRecordsTTL:   10 * time.Minute,
				RateLimitedTTL: time.Minute,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewCacheCoordinator: %v", err)
	}
	spec, err := (TeamCymruProvider{}).CacheKeySpec([]string{"192.0.2.1"})
	if err != nil {
		t.Fatalf("CacheKeySpec: %v", err)
	}
	request := CacheRequest{Key: spec, Policy: CachePolicyReadThrough}
	fetchCalls := 0
	fetch := func(context.Context) (CacheFetchResult, error) {
		fetchCalls++
		return CacheFetchResult{}, ErrProviderRejected
	}

	for attempt := 0; attempt < 2; attempt++ {
		if _, err := coordinator.Lookup(context.Background(), request, fetch); !errors.Is(err, ErrProviderRejected) {
			t.Fatalf("Lookup() error = %v, want ErrProviderRejected", err)
		}
	}
	if fetchCalls != 2 {
		t.Fatalf("fetch calls = %d, want uncached rejection on both attempts", fetchCalls)
	}
	_, setCalls := cache.counts()
	if setCalls != 0 {
		t.Fatalf("cache writes = %d, want 0", setCalls)
	}
}

type successfulTeamCymruDialer struct {
	calls  atomic.Int64
	errors chan error
}

func (dialer *successfulTeamCymruDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	dialer.calls.Add(1)
	client, provider := net.Pipe()
	go func() {
		defer provider.Close()
		request := make([]byte, len(teamCymruSingleRequest))
		if _, err := io.ReadFull(provider, request); err != nil {
			dialer.errors <- err
			return
		}
		if string(request) != teamCymruSingleRequest {
			dialer.errors <- fmt.Errorf("request = %q", request)
			return
		}
		_, err := io.WriteString(provider, teamCymruSingleResult)
		dialer.errors <- err
	}()
	return client, nil
}

func TestTeamCymruProviderIsSafeForConcurrentUse(t *testing.T) {
	const lookups = 16

	dialer := &successfulTeamCymruDialer{errors: make(chan error, lookups)}
	provider := TeamCymruProvider{Dialer: dialer}
	lookupErrors := make(chan error, lookups)
	var wait sync.WaitGroup

	for index := 0; index < lookups; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results, err := provider.LookupIPContext(context.Background(), []string{"192.0.2.1"})
			if err == nil && (len(results) != 1 || results[0].IP != "192.0.2.1") {
				err = fmt.Errorf("unexpected results: %+v", results)
			}
			lookupErrors <- err
		}()
	}
	wait.Wait()

	for index := 0; index < lookups; index++ {
		if err := <-lookupErrors; err != nil {
			t.Errorf("concurrent lookup: %v", err)
		}
		if err := <-dialer.errors; err != nil {
			t.Errorf("concurrent provider: %v", err)
		}
	}
	if got := dialer.calls.Load(); got != lookups {
		t.Fatalf("dial calls = %d, want %d independent connections", got, lookups)
	}
}
