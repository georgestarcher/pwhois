package pwhois

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

const (
	risWhoisIPRequest     = "-M 192.0.2.1\n"
	risWhoisPrefixRequest = "-x 198.51.100.0/24\n"
	risWhoisRouteResult   = `route:        192.0.2.0/24
origin:       AS64500
descr:        EXAMPLE-AS - Example Network, ZZ
lastupd-frst: 2026-07-01 12:34Z  198.51.100.10@rrc00
lastupd-last: 2026-07-29 15:45Z  2001:db8::10@rrc25
seen-at:      rrc00,rrc25
num-rispeers: 42
source:       RISWHOIS`
)

func loopbackRISWhoisProvider(t *testing.T, script loopbackProtocolScript) (RISWhoisProvider, <-chan loopbackProtocolResult) {
	t.Helper()

	server, results := startLoopbackProtocolServer(t, script)
	return RISWhoisProvider{
		Server:           server.Server,
		Port:             server.Port,
		Timeout:          server.Timeout,
		MaxResponseBytes: server.MaxResponseBytes,
	}, results
}

func TestRISWhoisIPAndPrefixLookups(t *testing.T) {
	tests := []struct {
		name            string
		query           string
		expectedRequest string
		response        string
		expectedPrefix  string
		expectedASN     uint32
	}{
		{
			name:            "IPv4 address requests longest match",
			query:           " 192.0.2.1 ",
			expectedRequest: risWhoisIPRequest,
			response:        "% synthetic banner\n\n" + risWhoisRouteResult,
			expectedPrefix:  "192.0.2.0/24",
			expectedASN:     64500,
		},
		{
			name:            "prefix requests exact match",
			query:           "198.51.100.0/24",
			expectedRequest: risWhoisPrefixRequest,
			response: `route:        198.51.100.0/24
origin:       AS64501
source:       RISWHOIS`,
			expectedPrefix: "198.51.100.0/24",
			expectedASN:    64501,
		},
		{
			name:            "IPv6 address requests longest match",
			query:           "2001:db8::1",
			expectedRequest: "-M 2001:db8::1\n",
			response: `route6:       2001:db8::/32
origin:       AS64502
seen-at:      rrc01
source:       RISWHOIS`,
			expectedPrefix: "2001:db8::/32",
			expectedASN:    64502,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider, protocolResult := loopbackRISWhoisProvider(t, loopbackProtocolScript{
				expectedRequest: test.expectedRequest,
				responseChunks:  []string{test.response},
			})
			started := time.Now().UTC()

			results, err := provider.LookupRouteContext(context.Background(), test.query)
			if err != nil {
				t.Fatalf("LookupRouteContext: %v", err)
			}
			finished := time.Now().UTC()
			if len(results) != 1 {
				t.Fatalf("results = %+v", results)
			}
			result := results[0]
			if result.Prefix != test.expectedPrefix || result.OriginASN != test.expectedASN {
				t.Fatalf("route result = %+v", result)
			}
			if result.Source != RISWhoisSource || result.Endpoint != provider.ServerAddressString() {
				t.Fatalf("provenance = %+v", result)
			}
			if result.FetchedAt.Before(started) || result.FetchedAt.After(finished) {
				t.Fatalf("fetched at = %v, want between %v and %v", result.FetchedAt, started, finished)
			}
			verifyAutomaticallyClosedLoopbackProtocol(t, protocolResult, test.expectedRequest)
		})
	}
}

func TestParseRISWhoisTypedAndRepeatedAttributes(t *testing.T) {
	query, err := normalizeRISWhoisQuery("192.0.2.1")
	if err != nil {
		t.Fatalf("normalize query: %v", err)
	}
	fetchedAt := time.Date(2026, 7, 29, 20, 0, 0, 0, time.UTC)
	response := `% comment before object
route: 192.0.2.0/24
origin: AS64500
descr: first description
descr: second description
remarks: first line
 continuation: line
seen-at: rrc00
seen-at: rrc01, rrc02
lastupd-frst: 2026-07-01 12:34Z  198.51.100.10@rrc00
lastupd-last: 2026-07-29 15:45Z  2001:db8::10@rrc25
num-rispeers: 42
source: RISWHOIS

route: 192.0.2.0/24
origin: AS64501
descr: alternate origin
source: RISWHOIS`

	results, err := parseRISWhoisResponse(query, response, "ris.example:43", fetchedAt)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %+v", results)
	}

	first := results[0]
	if !reflect.DeepEqual(first.Descriptions, []string{"first description", "second description"}) {
		t.Fatalf("descriptions = %v", first.Descriptions)
	}
	if !reflect.DeepEqual(first.SeenAt, []string{"rrc00", "rrc01", "rrc02"}) {
		t.Fatalf("seen at = %v", first.SeenAt)
	}
	if first.RISPeerCount != 42 {
		t.Fatalf("RIS peer count = %d", first.RISPeerCount)
	}
	if first.FirstObserved.Peer != "198.51.100.10" || first.FirstObserved.Collector != "rrc00" ||
		!first.FirstObserved.ObservedAt.Equal(time.Date(2026, 7, 1, 12, 34, 0, 0, time.UTC)) {
		t.Fatalf("first observation = %+v", first.FirstObserved)
	}
	if first.LastObserved.Peer != "2001:db8::10" || first.LastObserved.Collector != "rrc25" {
		t.Fatalf("last observation = %+v", first.LastObserved)
	}
	if got := first.RPSLAttributes["remarks"]; !reflect.DeepEqual(got, []string{"first line\ncontinuation: line"}) {
		t.Fatalf("continued RPSL attribute = %q", got)
	}
	if results[1].OriginASN != 64501 || results[1].Prefix != first.Prefix {
		t.Fatalf("multiple origin result = %+v", results[1])
	}
}

func TestParseRISWhoisResponseFailures(t *testing.T) {
	ipQuery, err := normalizeRISWhoisQuery("192.0.2.1")
	if err != nil {
		t.Fatalf("normalize IP query: %v", err)
	}
	prefixQuery, err := normalizeRISWhoisQuery("192.0.2.0/24")
	if err != nil {
		t.Fatalf("normalize prefix query: %v", err)
	}
	fetchedAt := time.Date(2026, 7, 29, 20, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		query     risWhoisQuery
		response  string
		wantError error
	}{
		{name: "empty", query: ipQuery, response: "", wantError: ErrNoRecords},
		{name: "comments only", query: ipQuery, response: "% no entries found\n", wantError: ErrNoRecords},
		{
			name:      "malformed line",
			query:     ipQuery,
			response:  "not an RPSL attribute",
			wantError: ErrMalformedResponse,
		},
		{
			name:      "missing route",
			query:     ipQuery,
			response:  "origin: AS64500\nsource: RISWHOIS",
			wantError: ErrMalformedResponse,
		},
		{
			name:      "both route families",
			query:     ipQuery,
			response:  "route: 192.0.2.0/24\nroute6: 2001:db8::/32\norigin: AS64500\nsource: RISWHOIS",
			wantError: ErrMalformedResponse,
		},
		{
			name:      "route field has wrong family",
			query:     ipQuery,
			response:  "route: 2001:db8::/32\norigin: AS64500\nsource: RISWHOIS",
			wantError: ErrMalformedResponse,
		},
		{
			name:      "route does not contain IP",
			query:     ipQuery,
			response:  "route: 198.51.100.0/24\norigin: AS64500\nsource: RISWHOIS",
			wantError: ErrMalformedResponse,
		},
		{
			name:      "prefix response is not exact",
			query:     prefixQuery,
			response:  "route: 192.0.0.0/16\norigin: AS64500\nsource: RISWHOIS",
			wantError: ErrMalformedResponse,
		},
		{
			name:      "invalid origin",
			query:     ipQuery,
			response:  "route: 192.0.2.0/24\norigin: not-an-asn\nsource: RISWHOIS",
			wantError: ErrMalformedResponse,
		},
		{
			name:      "missing source",
			query:     ipQuery,
			response:  "route: 192.0.2.0/24\norigin: AS64500",
			wantError: ErrMalformedResponse,
		},
		{
			name:      "wrong source",
			query:     ipQuery,
			response:  "route: 192.0.2.0/24\norigin: AS64500\nsource: TEST",
			wantError: ErrMalformedResponse,
		},
		{
			name:      "invalid observation",
			query:     ipQuery,
			response:  "route: 192.0.2.0/24\norigin: AS64500\nlastupd-last: yesterday\nsource: RISWHOIS",
			wantError: ErrMalformedResponse,
		},
		{
			name:      "invalid peer count",
			query:     ipQuery,
			response:  "route: 192.0.2.0/24\norigin: AS64500\nnum-rispeers: many\nsource: RISWHOIS",
			wantError: ErrMalformedResponse,
		},
		{
			name:  "duplicate route origin",
			query: ipQuery,
			response: "route: 192.0.2.0/24\norigin: AS64500\nsource: RISWHOIS\n\n" +
				"route: 192.0.2.0/24\norigin: AS64500\nsource: RISWHOIS",
			wantError: ErrMalformedResponse,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseRISWhoisResponse(test.query, test.response, "ris.example:43", fetchedAt)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("parse error = %v, want %v", err, test.wantError)
			}
		})
	}
}

func TestRISWhoisProviderErrors(t *testing.T) {
	tests := []struct {
		name      string
		response  string
		wantError error
	}{
		{
			name:      "rate limited diagnostic",
			response:  "%ERROR: query rate limit exceeded",
			wantError: ErrRateLimited,
		},
		{
			name:      "provider rejection",
			response:  "%ERROR: invalid query",
			wantError: ErrProviderRejected,
		},
		{
			name:      "diagnostic phrase in data is not rate limit",
			response:  risWhoisRouteResult + "\nremarks: rate limit documentation",
			wantError: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider, protocolResult := loopbackRISWhoisProvider(t, loopbackProtocolScript{
				expectedRequest: risWhoisIPRequest,
				responseChunks:  []string{test.response},
			})
			_, err := provider.LookupRouteContext(context.Background(), "192.0.2.1")
			if !errors.Is(err, test.wantError) {
				t.Fatalf("lookup error = %v, want %v", err, test.wantError)
			}
			verifyAutomaticallyClosedLoopbackProtocol(t, protocolResult, risWhoisIPRequest)
		})
	}
}

func TestRISWhoisInputAndCacheKey(t *testing.T) {
	provider := RISWhoisProvider{}
	for _, value := range []string{"", "not-an-ip", "192.0.2.1/24"} {
		if _, err := provider.LookupRouteContext(context.Background(), value); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("query %q error = %v, want ErrInvalidInput", value, err)
		}
	}
	if _, err := provider.LookupRouteContext(nil, "192.0.2.1"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil context error = %v, want ErrInvalidInput", err)
	}

	ipSpec, err := provider.CacheKeySpec(" 192.0.2.1 ")
	if err != nil {
		t.Fatalf("IP CacheKeySpec: %v", err)
	}
	prefixSpec, err := provider.CacheKeySpec("198.51.100.0/24")
	if err != nil {
		t.Fatalf("prefix CacheKeySpec: %v", err)
	}
	if ipSpec.Source != RISWhoisSource || ipSpec.Endpoint != "riswhois.ripe.net:43" ||
		ipSpec.NormalizedQuery != "192.0.2.1" || ipSpec.Options["match"] != "longest" {
		t.Fatalf("IP cache key spec = %+v", ipSpec)
	}
	if prefixSpec.NormalizedQuery != "198.51.100.0/24" || prefixSpec.Options["match"] != "exact" {
		t.Fatalf("prefix cache key spec = %+v", prefixSpec)
	}
	ipKey, err := CanonicalCacheKey(ipSpec)
	if err != nil {
		t.Fatalf("canonical IP key: %v", err)
	}
	prefixKey, err := CanonicalCacheKey(prefixSpec)
	if err != nil {
		t.Fatalf("canonical prefix key: %v", err)
	}
	if ipKey == prefixKey {
		t.Fatalf("IP and prefix cache keys must differ: %q", ipKey)
	}
}

func TestRISWhoisResponseLimit(t *testing.T) {
	provider, protocolResult := loopbackRISWhoisProvider(t, loopbackProtocolScript{
		expectedRequest: risWhoisIPRequest,
		responseChunks:  []string{risWhoisRouteResult},
	})
	provider.MaxResponseBytes = 16

	_, err := provider.LookupRouteContext(context.Background(), "192.0.2.1")
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("lookup error = %v, want ErrResponseTooLarge", err)
	}
	verifyAutomaticallyClosedLoopbackProtocol(t, protocolResult, risWhoisIPRequest)
}

func TestRISWhoisContextDeadline(t *testing.T) {
	provider, protocolResult := loopbackRISWhoisProvider(t, loopbackProtocolScript{
		expectedRequest: risWhoisIPRequest,
		noResponse:      true,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := provider.LookupRouteContext(ctx, "192.0.2.1")
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("lookup error = %v, want ErrTimeout", err)
	}
	verifyAutomaticallyClosedLoopbackProtocol(t, protocolResult, risWhoisIPRequest)
}
