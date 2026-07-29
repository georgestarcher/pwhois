package pwhois

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"
)

const (
	irrIPv4Request = "-T route,route6 -x 192.0.2.0/24\n"
	irrIPv4Result  = `route:          192.0.2.0/24
origin:         AS64500
descr:          Example published policy
mnt-by:         EXAMPLE-MNT
member-of:      RS-EXAMPLE
rpki-ov-state:  valid
source:         TEST-RADB`
)

type irrDialerFunc func(context.Context, string, string) (net.Conn, error)

func (function irrDialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return function(ctx, network, address)
}

func loopbackIRRProvider(t *testing.T, endpoint IRREndpoint, script loopbackProtocolScript) (IRRProvider, <-chan loopbackProtocolResult, <-chan string) {
	t.Helper()

	server, results := startLoopbackProtocolServer(t, script)
	requestedAddresses := make(chan string, 1)
	dialer := irrDialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		requestedAddresses <- address
		return (&net.Dialer{}).DialContext(ctx, network, server.ServerAddressString())
	})
	return IRRProvider{
		Endpoint:         endpoint,
		Timeout:          server.Timeout,
		MaxResponseBytes: server.MaxResponseBytes,
		Dialer:           dialer,
	}, results, requestedAddresses
}

func TestIRRProviderExactRouteLookups(t *testing.T) {
	tests := []struct {
		name            string
		endpoint        IRREndpoint
		query           string
		expectedRequest string
		response        string
		expectedPrefix  string
		expectedASN     uint32
		expectedAddress string
	}{
		{
			name:            "RADb IPv4 route",
			endpoint:        IRREndpointRADb,
			query:           " 192.0.2.0/24 ",
			expectedRequest: irrIPv4Request,
			response:        "% synthetic banner\n\n" + irrIPv4Result,
			expectedPrefix:  "192.0.2.0/24",
			expectedASN:     64500,
			expectedAddress: "whois.radb.net:43",
		},
		{
			name:            "ARIN IPv6 route",
			endpoint:        IRREndpointARIN,
			query:           "2001:db8::/32",
			expectedRequest: "-T route,route6 -x 2001:db8::/32\n",
			response: `route6: 2001:db8::/32
origin: AS64501
source: TEST-ARIN`,
			expectedPrefix:  "2001:db8::/32",
			expectedASN:     64501,
			expectedAddress: "rr.arin.net:43",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider, protocolResult, requestedAddresses := loopbackIRRProvider(t, test.endpoint, loopbackProtocolScript{
				expectedRequest: test.expectedRequest,
				responseChunks:  []string{test.response},
			})
			started := time.Now().UTC()

			results, err := provider.LookupRoutePolicyContext(context.Background(), test.query)
			if err != nil {
				t.Fatalf("LookupRoutePolicyContext: %v", err)
			}
			finished := time.Now().UTC()
			if len(results) != 1 {
				t.Fatalf("results = %+v", results)
			}
			result := results[0]
			if result.Prefix != test.expectedPrefix || result.OriginASN != test.expectedASN {
				t.Fatalf("route-policy result = %+v", result)
			}
			if result.Source != IRRSource || result.EndpointID != test.endpoint ||
				result.Endpoint != test.expectedAddress || result.QueryMode != IRRQueryModeExactRoute {
				t.Fatalf("provenance = %+v", result)
			}
			if result.FetchedAt.Before(started) || result.FetchedAt.After(finished) {
				t.Fatalf("fetched at = %v, want between %v and %v", result.FetchedAt, started, finished)
			}
			if address := <-requestedAddresses; address != test.expectedAddress {
				t.Fatalf("dial address = %q, want %q", address, test.expectedAddress)
			}
			verifyAutomaticallyClosedLoopbackProtocol(t, protocolResult, test.expectedRequest)
		})
	}
}

func TestParseIRRRepeatedAttributesAndMultipleOrigins(t *testing.T) {
	query, err := normalizeIRRQuery("192.0.2.0/24")
	if err != nil {
		t.Fatalf("normalize query: %v", err)
	}
	fetchedAt := time.Date(2026, 7, 29, 20, 0, 0, 0, time.UTC)
	response := `route: 192.0.2.0/24
origin: AS64500
descr: first description
descr: second description
 continuation
mnt-by: FIRST-MNT, SECOND-MNT
mnt-by: THIRD-MNT
member-of: RS-FIRST
member-of: RS-SECOND, RS-THIRD
rpki-ov-state: VALID # synthetic provider annotation
source: TEST-RADB

route: 192.0.2.0/24
origin: as64501
source: TEST-ARIN`
	endpoint := irrEndpointConfig{id: IRREndpointRADb, address: "whois.radb.net:43"}

	results, err := parseIRRResponse(query, response, endpoint, fetchedAt)
	if err != nil {
		t.Fatalf("parseIRRResponse: %v", err)
	}
	if len(results) != 2 || results[0].OriginASN != 64500 || results[1].OriginASN != 64501 {
		t.Fatalf("results = %+v", results)
	}
	first := results[0]
	if !reflect.DeepEqual(first.Descriptions, []string{"first description", "second description\ncontinuation"}) {
		t.Errorf("descriptions = %#v", first.Descriptions)
	}
	if !reflect.DeepEqual(first.Maintainers, []string{"FIRST-MNT", "SECOND-MNT", "THIRD-MNT"}) {
		t.Errorf("maintainers = %#v", first.Maintainers)
	}
	if !reflect.DeepEqual(first.MemberOf, []string{"RS-FIRST", "RS-SECOND", "RS-THIRD"}) {
		t.Errorf("member-of = %#v", first.MemberOf)
	}
	if first.RPKIState != "valid" || first.RPSLSource != "TEST-RADB" {
		t.Errorf("typed policy fields = %+v", first)
	}
	if first.Query != "192.0.2.0/24" || first.FetchedAt != fetchedAt {
		t.Errorf("query provenance = %+v", first)
	}
}

func TestParseIRRResponseFailures(t *testing.T) {
	query, err := normalizeIRRQuery("192.0.2.0/24")
	if err != nil {
		t.Fatalf("normalize query: %v", err)
	}
	endpoint := irrEndpointConfig{id: IRREndpointRADb, address: "whois.radb.net:43"}
	valid := irrIPv4Result

	tests := []struct {
		name      string
		response  string
		wantError error
	}{
		{name: "empty", response: "", wantError: ErrNoRecords},
		{name: "comments only", response: "% No entries found for the selected source(s).", wantError: ErrNoRecords},
		{name: "malformed attribute", response: "not an attribute", wantError: ErrMalformedResponse},
		{name: "missing route", response: "origin: AS64500\nsource: TEST", wantError: ErrMalformedResponse},
		{name: "both route families", response: valid + "\nroute6: 2001:db8::/32", wantError: ErrMalformedResponse},
		{name: "route host bits", response: "route: 192.0.2.1/24\norigin: AS64500\nsource: TEST", wantError: ErrMalformedResponse},
		{name: "wrong route family", response: "route6: 192.0.2.0/24\norigin: AS64500\nsource: TEST", wantError: ErrMalformedResponse},
		{name: "wrong exact prefix", response: "route: 192.0.3.0/24\norigin: AS64500\nsource: TEST", wantError: ErrMalformedResponse},
		{name: "missing origin", response: "route: 192.0.2.0/24\nsource: TEST", wantError: ErrMalformedResponse},
		{name: "duplicate origin", response: valid + "\norigin: AS64501", wantError: ErrMalformedResponse},
		{name: "invalid origin", response: "route: 192.0.2.0/24\norigin: 64500\nsource: TEST", wantError: ErrMalformedResponse},
		{name: "overflow origin", response: "route: 192.0.2.0/24\norigin: AS4294967296\nsource: TEST", wantError: ErrMalformedResponse},
		{name: "missing source", response: "route: 192.0.2.0/24\norigin: AS64500", wantError: ErrMalformedResponse},
		{name: "duplicate source", response: valid + "\nsource: SECOND", wantError: ErrMalformedResponse},
		{name: "invalid source", response: "route: 192.0.2.0/24\norigin: AS64500\nsource: TWO WORDS", wantError: ErrMalformedResponse},
		{name: "empty description", response: valid + "\ndescr:", wantError: ErrMalformedResponse},
		{name: "empty maintainer", response: valid + "\nmnt-by: FIRST,", wantError: ErrMalformedResponse},
		{name: "invalid member-of", response: valid + "\nmember-of: TWO WORDS", wantError: ErrMalformedResponse},
		{name: "duplicate RPKI state", response: valid + "\nrpki-ov-state: invalid", wantError: ErrMalformedResponse},
		{name: "invalid RPKI state", response: "route: 192.0.2.0/24\norigin: AS64500\nrpki-ov-state: not found\nsource: TEST", wantError: ErrMalformedResponse},
		{name: "duplicate object", response: valid + "\n\n" + valid, wantError: ErrMalformedResponse},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseIRRResponse(query, test.response, endpoint, time.Time{})
			if !errors.Is(err, test.wantError) {
				t.Fatalf("parse error = %v, want %v", err, test.wantError)
			}
		})
	}
}

func TestIRRProviderResponseErrors(t *testing.T) {
	tests := []struct {
		name      string
		response  string
		wantError error
	}{
		{name: "empty result", response: "% No entries found for the selected source(s).", wantError: ErrNoRecords},
		{name: "rate limit", response: "%% Too many queries from this client", wantError: ErrRateLimited},
		{name: "query limit", response: "% Query limit exceeded", wantError: ErrRateLimited},
		{name: "provider rejection", response: "%% ERROR: invalid query", wantError: ErrProviderRejected},
		{name: "access denied", response: "% Access denied", wantError: ErrProviderRejected},
		{name: "diagnostic phrase in data is ignored", response: irrIPv4Result + "\nremarks: rate limit documentation", wantError: nil},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider, protocolResult, _ := loopbackIRRProvider(t, IRREndpointRADb, loopbackProtocolScript{
				expectedRequest: irrIPv4Request,
				responseChunks:  []string{test.response},
			})
			_, err := provider.LookupRoutePolicyContext(context.Background(), "192.0.2.0/24")
			if !errors.Is(err, test.wantError) {
				t.Fatalf("lookup error = %v, want %v", err, test.wantError)
			}
			verifyAutomaticallyClosedLoopbackProtocol(t, protocolResult, irrIPv4Request)
		})
	}
}

func TestIRRInputEndpointAndCacheKey(t *testing.T) {
	provider := IRRProvider{}
	for _, value := range []string{"", "not-a-prefix", "192.0.2.1", "192.0.2.1/24"} {
		if _, err := provider.LookupRoutePolicyContext(context.Background(), value); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("query %q error = %v, want ErrInvalidInput", value, err)
		}
	}
	if _, err := provider.LookupRoutePolicyContext(nil, "192.0.2.0/24"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil context error = %v, want ErrInvalidInput", err)
	} else {
		var operationError *OperationError
		if !errors.As(err, &operationError) ||
			operationError.Operation != "lookup IRR route policy" ||
			operationError.Server != "whois.radb.net:43" {
			t.Fatalf("nil context operation error = %+v", operationError)
		}
	}

	endpoints := map[IRREndpoint]string{
		IRREndpointRADb: "whois.radb.net:43",
		IRREndpointARIN: "rr.arin.net:43",
		IRREndpointNTT:  "rr.ntt.net:43",
	}
	var keys []string
	for endpointID, address := range endpoints {
		configured := IRRProvider{Endpoint: endpointID}
		gotAddress, err := configured.EndpointAddressString()
		if err != nil || gotAddress != address {
			t.Fatalf("endpoint %q address = %q, %v; want %q", endpointID, gotAddress, err, address)
		}
		spec, err := configured.CacheKeySpec(" 192.0.2.0/24 ")
		if err != nil {
			t.Fatalf("CacheKeySpec %q: %v", endpointID, err)
		}
		if spec.Source != IRRSource || spec.Endpoint != address ||
			spec.NormalizedQuery != "192.0.2.0/24" ||
			spec.Options["endpoint_id"] != string(endpointID) ||
			spec.Options["match"] != "exact" ||
			spec.Options["object_types"] != "route,route6" ||
			spec.Options["query_mode"] != IRRQueryModeExactRoute {
			t.Fatalf("cache key spec = %+v", spec)
		}
		key, err := CanonicalCacheKey(spec)
		if err != nil {
			t.Fatalf("CanonicalCacheKey %q: %v", endpointID, err)
		}
		keys = append(keys, key)
	}
	if keys[0] == keys[1] || keys[0] == keys[2] || keys[1] == keys[2] {
		t.Fatalf("endpoint cache keys must be distinct: %q", keys)
	}

	defaultAddress, err := provider.EndpointAddressString()
	if err != nil || defaultAddress != "whois.radb.net:43" {
		t.Fatalf("default endpoint = %q, %v", defaultAddress, err)
	}

	unsupported := IRRProvider{
		Endpoint: "arbitrary.example",
		Dialer: irrDialerFunc(func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("unsupported endpoint reached dialer")
			return nil, nil
		}),
	}
	if _, err := unsupported.EndpointAddressString(); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unsupported endpoint address error = %v", err)
	}
	if _, err := unsupported.CacheKeySpec("192.0.2.0/24"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unsupported endpoint cache error = %v", err)
	}
	if _, err := unsupported.LookupRoutePolicyContext(context.Background(), "192.0.2.0/24"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unsupported endpoint lookup error = %v", err)
	} else {
		var operationError *OperationError
		if !errors.As(err, &operationError) || operationError.Server != "" {
			t.Fatalf("unsupported endpoint operation error = %+v", operationError)
		}
	}
}

func TestIRRResponseLimitAndDeadline(t *testing.T) {
	t.Run("response limit", func(t *testing.T) {
		provider, protocolResult, _ := loopbackIRRProvider(t, IRREndpointRADb, loopbackProtocolScript{
			expectedRequest: irrIPv4Request,
			responseChunks:  []string{irrIPv4Result},
		})
		provider.MaxResponseBytes = 16

		_, err := provider.LookupRoutePolicyContext(context.Background(), "192.0.2.0/24")
		if !errors.Is(err, ErrResponseTooLarge) {
			t.Fatalf("lookup error = %v, want ErrResponseTooLarge", err)
		}
		verifyAutomaticallyClosedLoopbackProtocol(t, protocolResult, irrIPv4Request)
	})

	t.Run("context deadline", func(t *testing.T) {
		provider, protocolResult, _ := loopbackIRRProvider(t, IRREndpointRADb, loopbackProtocolScript{
			expectedRequest: irrIPv4Request,
			noResponse:      true,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		_, err := provider.LookupRoutePolicyContext(ctx, "192.0.2.0/24")
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("lookup error = %v, want ErrTimeout", err)
		}
		verifyAutomaticallyClosedLoopbackProtocol(t, protocolResult, irrIPv4Request)
	})
}
