package pwhois

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIANARDAPBootstrapResolutionAndCaching(t *testing.T) {
	var mu sync.Mutex
	requestCounts := make(map[string]int)
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	writeBootstrap := func(response http.ResponseWriter, request *http.Request, body string) {
		mu.Lock()
		requestCounts[request.URL.Path]++
		mu.Unlock()
		if request.Header.Get("Accept") != "application/json" || request.Header.Get("User-Agent") != AppName {
			t.Errorf("bootstrap request headers = %v", request.Header)
		}
		response.Header().Set("Content-Type", "application/json; charset=utf-8")
		response.Header().Set("Expires", time.Now().Add(time.Hour).UTC().Format(http.TimeFormat))
		_, _ = response.Write([]byte(body))
	}

	mux.HandleFunc("/ipv4.json", func(response http.ResponseWriter, request *http.Request) {
		writeBootstrap(response, request, `{
  "version": "1.0",
  "publication": "2026-07-29T12:00:00Z",
  "description": "synthetic IPv4 bootstrap",
  "services": [
    [["192.0.0.0/16"], ["https://broad.example.test/rdap/"]],
    [["192.0.2.0/24"], ["https://specific.example.test/rdap/", "http://specific.example.test/rdap/"]],
    [["198.51.100.0/24"], ["https://other.example.test/rdap/"]]
  ]
}`)
	})
	mux.HandleFunc("/asn.json", func(response http.ResponseWriter, request *http.Request) {
		writeBootstrap(response, request, `{
  "version": "1.0",
  "publication": "2026-07-29T12:00:00Z",
  "services": [
    [["64496-64510"], ["https://asn.example.test/rdap/"]],
    [["65536-65551"], ["https://asn32.example.test/rdap/"]]
  ]
}`)
	})

	resolver := &IANARDAPBootstrapResolver{
		Client:            server.Client(),
		IPv4URL:           server.URL + "/ipv4.json",
		IPv6URL:           server.URL + "/ipv6.json",
		ASNURL:            server.URL + "/asn.json",
		AllowInsecureHTTP: true,
	}

	ipResolution, err := resolver.ResolveIP(context.Background(), net.ParseIP("192.0.2.42"))
	if err != nil {
		t.Fatalf("ResolveIP: %v", err)
	}
	if !reflect.DeepEqual(ipResolution.BaseURLs, []string{"https://specific.example.test/rdap/", "http://specific.example.test/rdap/"}) {
		t.Fatalf("IP base URLs = %v", ipResolution.BaseURLs)
	}
	if !reflect.DeepEqual(ipResolution.AllowedAuthorities, []string{
		"broad.example.test", "other.example.test", "specific.example.test",
	}) {
		t.Fatalf("allowed authorities = %v", ipResolution.AllowedAuthorities)
	}
	if ipResolution.Publication.Format(time.RFC3339) != rdapBootstrapPublicationText {
		t.Fatalf("publication = %v", ipResolution.Publication)
	}

	if _, err := resolver.ResolveIP(context.Background(), net.ParseIP("192.0.2.99")); err != nil {
		t.Fatalf("cached ResolveIP: %v", err)
	}
	asnResolution, err := resolver.ResolveASN(context.Background(), 64500)
	if err != nil {
		t.Fatalf("ResolveASN: %v", err)
	}
	if !reflect.DeepEqual(asnResolution.BaseURLs, []string{"https://asn.example.test/rdap/"}) {
		t.Fatalf("ASN base URLs = %v", asnResolution.BaseURLs)
	}

	mu.Lock()
	defer mu.Unlock()
	if requestCounts["/ipv4.json"] != 1 || requestCounts["/asn.json"] != 1 {
		t.Fatalf("bootstrap request counts = %v, want one request per registry", requestCounts)
	}
	if identity := resolver.CacheIdentity(); !strings.Contains(identity, server.URL+"/ipv4.json") ||
		!strings.Contains(identity, server.URL+"/asn.json") {
		t.Fatalf("custom cache identity = %q", identity)
	}
}

func TestIANARDAPBootstrapHonorsExpiredResponse(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requestCount++
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Expires", time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat))
		_, _ = response.Write([]byte(`{
  "version":"1.0",
  "publication":"2026-07-29T12:00:00Z",
  "services":[[["192.0.2.0/24"],["https://rdap.example.test/"]]]
}`))
	}))
	defer server.Close()

	resolver := &IANARDAPBootstrapResolver{
		Client:            server.Client(),
		IPv4URL:           server.URL,
		AllowInsecureHTTP: true,
		FallbackTTL:       time.Hour,
	}
	for lookup := 0; lookup < 2; lookup++ {
		if _, err := resolver.ResolveIP(context.Background(), net.ParseIP("192.0.2.42")); err != nil {
			t.Fatalf("ResolveIP %d: %v", lookup+1, err)
		}
	}
	if requestCount != 2 {
		t.Fatalf("expired bootstrap request count = %d, want 2", requestCount)
	}
}

func TestIANARDAPBootstrapNoMatchAndValidation(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		queryIP   string
		wantError error
	}{
		{
			name: "no match",
			body: `{
  "version":"1.0",
  "publication":"2026-07-29T12:00:00Z",
  "services":[[["198.51.100.0/24"],["https://rdap.example.test/"]]]
}`,
			queryIP:   "192.0.2.42",
			wantError: ErrNoRecords,
		},
		{
			name: "unsupported version",
			body: `{
  "version":"2.0",
  "publication":"2026-07-29T12:00:00Z",
  "services":[[["192.0.2.0/24"],["https://rdap.example.test/"]]]
}`,
			queryIP:   "192.0.2.42",
			wantError: ErrMalformedResponse,
		},
		{
			name: "ambiguous longest match",
			body: `{
  "version":"1.0",
  "publication":"2026-07-29T12:00:00Z",
  "services":[
    [["192.0.2.0/24"],["https://one.example.test/"]],
    [["192.0.2.0/24"],["https://two.example.test/"]]
  ]
}`,
			queryIP:   "192.0.2.42",
			wantError: ErrMalformedResponse,
		},
		{
			name: "service URL lacks trailing slash",
			body: `{
  "version":"1.0",
  "publication":"2026-07-29T12:00:00Z",
  "services":[[["192.0.2.0/24"],["https://rdap.example.test/rdap"]]]
}`,
			queryIP:   "192.0.2.42",
			wantError: ErrMalformedResponse,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				response.Header().Set("Content-Type", "application/json")
				_, _ = response.Write([]byte(test.body))
			}))
			defer server.Close()
			resolver := &IANARDAPBootstrapResolver{
				Client:            server.Client(),
				IPv4URL:           server.URL,
				AllowInsecureHTTP: true,
			}

			_, err := resolver.ResolveIP(context.Background(), net.ParseIP(test.queryIP))
			if !errors.Is(err, test.wantError) {
				t.Fatalf("ResolveIP error = %v, want %v", err, test.wantError)
			}
		})
	}
}

func TestIANARDAPBootstrapHTTPFailures(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		content   string
		body      string
		limit     int64
		wantError error
	}{
		{name: "rate limited", status: http.StatusTooManyRequests, wantError: ErrRateLimited},
		{name: "server failure", status: http.StatusServiceUnavailable, wantError: ErrConnection},
		{
			name:      "wrong content type",
			status:    http.StatusOK,
			content:   "text/plain",
			body:      `{}`,
			wantError: ErrMalformedResponse,
		},
		{
			name:      "oversized",
			status:    http.StatusOK,
			content:   "application/json",
			body:      strings.Repeat("x", 100),
			limit:     16,
			wantError: ErrResponseTooLarge,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if test.content != "" {
					response.Header().Set("Content-Type", test.content)
				}
				response.WriteHeader(test.status)
				_, _ = response.Write([]byte(test.body))
			}))
			defer server.Close()
			resolver := &IANARDAPBootstrapResolver{
				Client:            server.Client(),
				IPv4URL:           server.URL,
				MaxResponseBytes:  test.limit,
				AllowInsecureHTTP: true,
			}

			_, err := resolver.ResolveIP(context.Background(), net.ParseIP("192.0.2.42"))
			if !errors.Is(err, test.wantError) {
				t.Fatalf("ResolveIP error = %v, want %v", err, test.wantError)
			}
		})
	}
}

func TestIANARDAPBootstrapCoalescedWaitHonorsContext(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		close(started)
		<-release
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{
  "version":"1.0",
  "publication":"2026-07-29T12:00:00Z",
  "services":[[["192.0.2.0/24"],["https://rdap.example.test/"]]]
}`))
	}))
	defer server.Close()
	resolver := &IANARDAPBootstrapResolver{
		Client:            server.Client(),
		IPv4URL:           server.URL,
		AllowInsecureHTTP: true,
	}

	firstResult := make(chan error, 1)
	go func() {
		_, err := resolver.ResolveIP(context.Background(), net.ParseIP("192.0.2.42"))
		firstResult <- err
	}()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := resolver.ResolveIP(ctx, net.ParseIP("192.0.2.43"))
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("coalesced wait error = %v, want ErrTimeout", err)
	}
	close(release)
	if err := <-firstResult; err != nil {
		t.Fatalf("first bootstrap resolution: %v", err)
	}
}

func TestParseRDAPASNBootstrapRange(t *testing.T) {
	start, end, err := parseRDAPASNBootstrapRange("64496-64510")
	if err != nil || start != 64496 || end != 64510 {
		t.Fatalf("range = %d-%d, %v", start, end, err)
	}
	for _, value := range []string{"", "64510-64496", "AS64500-AS64510", "1-4294967296"} {
		if _, _, err := parseRDAPASNBootstrapRange(value); err == nil {
			t.Errorf("range %q unexpectedly accepted", value)
		}
	}
}
