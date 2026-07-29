package pwhois

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	rdapBootstrapPublicationText = "2026-07-29T12:00:00Z"
	rdapIPResponse               = `{
  "rdapConformance": ["rdap_level_0", "redacted"],
  "objectClassName": "ip network",
  "handle": "NET-192-0-2-32-1",
  "startAddress": "192.0.2.32",
  "endAddress": "192.0.2.63",
  "ipVersion": "v4",
  "name": "EXAMPLE-NET",
  "type": "DIRECT ALLOCATION",
  "country": "us",
  "parentHandle": "NET-192-0-2-0-1",
  "status": ["active"],
  "events": [{
    "eventAction": "registration",
    "eventDate": "2020-01-02T03:04:05Z",
    "eventActor": "private-actor@example.test"
  }],
  "entities": [
    {
      "objectClassName": "entity",
      "handle": "ORG-EXAMPLE",
      "roles": ["registrant"],
      "vcardArray": ["vcard", [
        ["version", {}, "text", "4.0"],
        ["fn", {}, "text", "Private Person"],
        ["org", {}, "text", "Example Organization"],
        ["email", {}, "text", "private@example.test"],
        ["adr", {}, "text", ["", "", "123 Private Street", "Example", "", "", "ZZ"]]
      ]]
    },
    {
      "objectClassName": "entity",
      "handle": "ABUSE-EXAMPLE",
      "roles": ["abuse"],
      "status": ["redacted"],
      "vcardArray": ["vcard", [
        ["version", {}, "text", "4.0"],
        ["fn", {}, "text", "Private Abuse Contact"],
        ["email", {}, "text", "abuse@example.test"]
      ]]
    }
  ],
  "redacted": [{
    "name": {"description": "Abuse Contact Email"},
    "postPath": "$.entities[1].vcardArray[1][2][3]",
    "method": "emptyValue",
    "reason": {"description": "Server policy"}
  }]
}`
	rdapASNResponse = `{
  "rdapConformance": ["rdap_level_0"],
  "objectClassName": "autnum",
  "handle": "AS64500",
  "startAutnum": 64500,
  "endAutnum": 64510,
  "name": "EXAMPLE-AS-RANGE",
  "type": "DIRECT ALLOCATION",
  "country": "ZZ",
  "status": ["active"],
  "events": [{
    "eventAction": "last changed",
    "eventDate": "2026-07-01T01:02:03Z"
  }],
  "entities": [{
    "objectClassName": "entity",
    "handle": "ORG-ASN-EXAMPLE",
    "roles": ["registrant"],
    "vcardArray": ["vcard", [
      ["version", {}, "text", "4.0"],
      ["fn", {}, "text", "ASN Example Organization"],
      ["kind", {}, "text", "org"]
    ]]
  }]
}`
)

type staticRDAPBootstrapResolver struct {
	mu        sync.Mutex
	identity  string
	ipResult  RDAPBootstrapResolution
	asnResult RDAPBootstrapResolution
	ipError   error
	asnError  error
	ipCalls   int
	asnCalls  int
}

func (resolver *staticRDAPBootstrapResolver) ResolveIP(context.Context, net.IP) (RDAPBootstrapResolution, error) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.ipCalls++
	return resolver.ipResult, resolver.ipError
}

func (resolver *staticRDAPBootstrapResolver) ResolveASN(context.Context, uint32) (RDAPBootstrapResolution, error) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.asnCalls++
	return resolver.asnResult, resolver.asnError
}

func (resolver *staticRDAPBootstrapResolver) CacheIdentity() string {
	if resolver.identity != "" {
		return resolver.identity
	}
	return "test-rdap-bootstrap"
}

func testRDAPResolution(t *testing.T, serverURL string) RDAPBootstrapResolution {
	t.Helper()
	parsed, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	publication, _ := time.Parse(time.RFC3339, rdapBootstrapPublicationText)
	return RDAPBootstrapResolution{
		BaseURLs:           []string{serverURL + "/rdap/"},
		AllowedAuthorities: []string{parsed.Host},
		Publication:        publication,
	}
}

func testRDAPProvider(server *httptest.Server, resolver *staticRDAPBootstrapResolver) RDAPProvider {
	return RDAPProvider{
		Client:                     server.Client(),
		Bootstrap:                  resolver,
		Timeout:                    time.Second,
		MaxResponseBytes:           DefaultMaxResponseBytes,
		MaxReferrals:               DefaultRDAPMaxReferrals,
		AllowInsecureHTTP:          true,
		AllowPrivateNetworkTargets: true,
	}
}

func writeRDAPJSON(response http.ResponseWriter, body string) {
	response.Header().Set("Content-Type", "application/rdap+json; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write([]byte(body))
}

func TestRDAPDirectIPLookupPrivacyAndProvenance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/rdap/ip/192.0.2.42" {
			t.Errorf("request path = %q", request.URL.Path)
		}
		if request.Header.Get("Accept") != "application/rdap+json" || request.Header.Get("User-Agent") != AppName {
			t.Errorf("request headers = %v", request.Header)
		}
		writeRDAPJSON(response, rdapIPResponse)
	}))
	defer server.Close()

	resolver := &staticRDAPBootstrapResolver{}
	resolver.ipResult = testRDAPResolution(t, server.URL)
	provider := testRDAPProvider(server, resolver)
	started := time.Now().UTC()

	result, err := provider.LookupIPContext(context.Background(), " 192.0.2.42 ")
	if err != nil {
		t.Fatalf("LookupIPContext: %v", err)
	}
	finished := time.Now().UTC()
	if result.Query != "192.0.2.42" || result.StartAddress != "192.0.2.32" ||
		result.EndAddress != "192.0.2.63" || result.IPVersion != "v4" {
		t.Fatalf("IP range = %+v", result)
	}
	if result.Handle != "NET-192-0-2-32-1" || result.Name != "EXAMPLE-NET" ||
		result.CountryCode != "US" || result.ParentHandle != "NET-192-0-2-0-1" {
		t.Fatalf("registration fields = %+v", result)
	}
	if len(result.RegisteredOrganizations) != 1 || result.RegisteredOrganizations[0] != "Example Organization" {
		t.Fatalf("registered organizations = %v", result.RegisteredOrganizations)
	}
	if len(result.AbuseContacts) != 1 || result.AbuseContacts[0].Handle != "ABUSE-EXAMPLE" {
		t.Fatalf("abuse contacts = %+v", result.AbuseContacts)
	}
	if !result.Redacted || len(result.Redactions) != 1 ||
		result.Redactions[0].Name != "Abuse Contact Email" {
		t.Fatalf("redaction = %+v", result)
	}
	if result.Source != RDAPSource || result.Registry != "127.0.0.1" ||
		result.Endpoint != server.URL || result.ReferralCount != 0 {
		t.Fatalf("provenance = %+v", result)
	}
	if result.BootstrapPublication.Format(time.RFC3339) != rdapBootstrapPublicationText ||
		result.FetchedAt.Before(started) || result.FetchedAt.After(finished) {
		t.Fatalf("timestamps = %+v", result)
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	for _, privateValue := range []string{
		"Private Person", "private@example.test", "123 Private Street",
		"Private Abuse Contact", "abuse@example.test", "private-actor@example.test",
		"$.entities",
	} {
		if strings.Contains(string(encoded), privateValue) {
			t.Errorf("normalized result retained private value %q", privateValue)
		}
	}
}

func TestRDAPDirectASNLookup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/rdap/autnum/64505" {
			t.Errorf("request path = %q", request.URL.Path)
		}
		writeRDAPJSON(response, rdapASNResponse)
	}))
	defer server.Close()

	resolver := &staticRDAPBootstrapResolver{}
	resolver.asnResult = testRDAPResolution(t, server.URL)
	provider := testRDAPProvider(server, resolver)

	result, err := provider.LookupASNContext(context.Background(), "AS64505")
	if err != nil {
		t.Fatalf("LookupASNContext: %v", err)
	}
	if result.Query != 64505 || result.StartAutnum != 64500 || result.EndAutnum != 64510 ||
		result.Handle != "AS64500" || result.Name != "EXAMPLE-AS-RANGE" {
		t.Fatalf("ASN result = %+v", result)
	}
	if !reflect.DeepEqual(result.RegisteredOrganizations, []string{"ASN Example Organization"}) {
		t.Fatalf("ASN registered organizations = %v", result.RegisteredOrganizations)
	}
	if result.Source != RDAPSource || result.Registry != "127.0.0.1" {
		t.Fatalf("ASN provenance = %+v", result)
	}
}

func TestRDAPNestedEntitiesAndDepthBound(t *testing.T) {
	nestedEntity := `{
	  "objectClassName": "entity",
	  "handle": "PARENT-EXAMPLE",
	  "entities": [
	    {
	      "objectClassName": "entity",
	      "handle": "ORG-NESTED",
	      "roles": ["registrant"],
	      "vcardArray": ["vcard", [
	        ["version", {}, "text", "4.0"],
	        ["org", {}, "text", "Nested Example Organization"]
	      ]]
	    },
	    {
	      "objectClassName": "entity",
	      "handle": "ABUSE-NESTED",
	      "roles": ["abuse"],
	      "status": ["redacted"]
	    }
	  ]
	}`
	body := strings.Replace(rdapIPResponse, `"entities": [`, `"entities": [`+nestedEntity+`,`, 1)
	responseURL, _ := url.Parse("https://rdap.example.test/rdap/ip/192.0.2.42")
	result, err := parseRDAPIPResult("192.0.2.42", rdapHTTPResult{
		body:     []byte(body),
		finalURL: responseURL,
	}, time.Now())
	if err != nil {
		t.Fatalf("parse nested entities: %v", err)
	}
	if !containsFold(result.RegisteredOrganizations, "Nested Example Organization") {
		t.Fatalf("nested registered organizations = %v", result.RegisteredOrganizations)
	}
	foundNestedAbuse := false
	for _, contact := range result.AbuseContacts {
		if contact.Handle == "ABUSE-NESTED" {
			foundNestedAbuse = true
		}
	}
	if !foundNestedAbuse || !result.Redacted {
		t.Fatalf("nested abuse/redaction = %+v", result)
	}

	deepest := `{"objectClassName":"entity"}`
	for depth := 0; depth <= maxRDAPEntityDepth; depth++ {
		deepest = `{"objectClassName":"entity","entities":[` + deepest + `]}`
	}
	tooDeepBody := strings.Replace(rdapIPResponse, `"entities": [`, `"entities": [`+deepest+`,`, 1)
	_, err = parseRDAPIPResult("192.0.2.42", rdapHTTPResult{
		body:     []byte(tooDeepBody),
		finalURL: responseURL,
	}, time.Now())
	if !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("deep entity error = %v, want ErrMalformedResponse", err)
	}
}

func TestRDAPEntityDeduplicationPreservesDelimiterValues(t *testing.T) {
	_, contacts, _, err := normalizeRDAPEntities([]rawRDAPEntity{
		{
			ObjectClassName: "entity",
			Handle:          "a",
			Roles:           []string{"x", "abuse"},
		},
		{
			ObjectClassName: "entity",
			Handle:          "a\x00x",
			Roles:           []string{"abuse"},
		},
		{
			ObjectClassName: "entity",
			Handle:          "a",
			Roles:           []string{"x", "abuse"},
		},
	})
	if err != nil {
		t.Fatalf("normalize entities: %v", err)
	}
	if len(contacts) != 2 {
		t.Fatalf("abuse contacts = %+v, want both delimiter-containing references", contacts)
	}
}

func TestRDAPBoundedBootstrapAuthorizedReferral(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		writeRDAPJSON(response, rdapIPResponse)
	}))
	defer final.Close()
	finalURL, _ := url.Parse(final.URL)

	initial := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, final.URL+"/rdap/ip/192.0.2.42", http.StatusMovedPermanently)
	}))
	defer initial.Close()
	initialURL, _ := url.Parse(initial.URL)

	resolver := &staticRDAPBootstrapResolver{}
	resolver.ipResult = testRDAPResolution(t, initial.URL)
	resolver.ipResult.AllowedAuthorities = []string{initialURL.Host, finalURL.Host}
	provider := testRDAPProvider(initial, resolver)
	provider.Client = &http.Client{}

	result, err := provider.LookupIPContext(context.Background(), "192.0.2.42")
	if err != nil {
		t.Fatalf("LookupIPContext referral: %v", err)
	}
	if result.ReferralCount != 1 || result.Endpoint != final.URL {
		t.Fatalf("referral provenance = %+v", result)
	}
}

func TestRDAPInitialBaseDoesNotRequireReferralAllowlist(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		writeRDAPJSON(response, rdapIPResponse)
	}))
	defer server.Close()

	resolver := &staticRDAPBootstrapResolver{}
	resolver.ipResult = testRDAPResolution(t, server.URL)
	resolver.ipResult.AllowedAuthorities = nil
	provider := testRDAPProvider(server, resolver)

	if _, err := provider.LookupIPContext(context.Background(), "192.0.2.42"); err != nil {
		t.Fatalf("LookupIPContext without referral allowlist: %v", err)
	}
}

func TestRDAPReferralFailurePreservesAuthoritativeEndpoint(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusTooManyRequests)
	}))
	defer final.Close()
	finalURL, _ := url.Parse(final.URL)

	initial := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, final.URL+"/rdap/ip/192.0.2.42", http.StatusTemporaryRedirect)
	}))
	defer initial.Close()
	initialURL, _ := url.Parse(initial.URL)

	resolver := &staticRDAPBootstrapResolver{}
	resolver.ipResult = testRDAPResolution(t, initial.URL)
	resolver.ipResult.AllowedAuthorities = []string{initialURL.Host, finalURL.Host}
	provider := testRDAPProvider(initial, resolver)
	provider.Client = &http.Client{}

	_, err := provider.LookupIPContext(context.Background(), "192.0.2.42")
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("lookup error = %v, want ErrRateLimited", err)
	}
	var operationError *OperationError
	if !errors.As(err, &operationError) || operationError.Server != final.URL {
		t.Fatalf("operation endpoint = %+v, want %q", operationError, final.URL)
	}
}

func TestRDAPUnsafeReferrals(t *testing.T) {
	tests := []struct {
		name       string
		location   func(string) string
		allowFinal bool
	}{
		{
			name:       "cross-origin authority absent from bootstrap",
			location:   func(finalURL string) string { return finalURL + "/rdap/ip/192.0.2.42" },
			allowFinal: false,
		},
		{
			name:       "referral changes resource",
			location:   func(finalURL string) string { return finalURL + "/rdap/ip/198.51.100.1" },
			allowFinal: true,
		},
		{
			name:       "referral loop",
			location:   func(string) string { return "/rdap/ip/192.0.2.42" },
			allowFinal: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			final := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				writeRDAPJSON(response, rdapIPResponse)
			}))
			defer final.Close()
			finalURL, _ := url.Parse(final.URL)

			initial := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				http.Redirect(response, request, test.location(final.URL), http.StatusFound)
			}))
			defer initial.Close()
			initialURL, _ := url.Parse(initial.URL)

			resolver := &staticRDAPBootstrapResolver{}
			resolver.ipResult = testRDAPResolution(t, initial.URL)
			resolver.ipResult.AllowedAuthorities = []string{initialURL.Host}
			if test.allowFinal {
				resolver.ipResult.AllowedAuthorities = append(resolver.ipResult.AllowedAuthorities, finalURL.Host)
			}
			provider := testRDAPProvider(initial, resolver)
			provider.Client = &http.Client{}

			_, err := provider.LookupIPContext(context.Background(), "192.0.2.42")
			if !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("lookup error = %v, want ErrMalformedResponse", err)
			}
		})
	}
}

func TestRDAPHTTPFailures(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		content   string
		body      string
		limit     int64
		wantError error
	}{
		{name: "not found", status: http.StatusNotFound, wantError: ErrNoRecords},
		{name: "rate limited", status: http.StatusTooManyRequests, wantError: ErrRateLimited},
		{name: "rejected", status: http.StatusForbidden, wantError: ErrProviderRejected},
		{name: "server failure", status: http.StatusServiceUnavailable, wantError: ErrConnection},
		{
			name:      "wrong content type",
			status:    http.StatusOK,
			content:   "text/html",
			body:      rdapIPResponse,
			wantError: ErrMalformedResponse,
		},
		{
			name:      "malformed JSON",
			status:    http.StatusOK,
			content:   "application/rdap+json",
			body:      "{",
			wantError: ErrMalformedResponse,
		},
		{
			name:      "oversized body",
			status:    http.StatusOK,
			content:   "application/rdap+json",
			body:      rdapIPResponse,
			limit:     32,
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

			resolver := &staticRDAPBootstrapResolver{}
			resolver.ipResult = testRDAPResolution(t, server.URL)
			provider := testRDAPProvider(server, resolver)
			if test.limit > 0 {
				provider.MaxResponseBytes = test.limit
			}

			_, err := provider.LookupIPContext(context.Background(), "192.0.2.42")
			if !errors.Is(err, test.wantError) {
				t.Fatalf("lookup error = %v, want %v", err, test.wantError)
			}
			var operationError *OperationError
			if !errors.As(err, &operationError) || operationError.Server != server.URL {
				t.Fatalf("operation endpoint = %+v, want %q", operationError, server.URL)
			}
		})
	}
}

func TestRDAPResponseValidation(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "range omits query",
			body: strings.Replace(rdapIPResponse, `"startAddress": "192.0.2.32"`, `"startAddress": "198.51.100.1"`, 1),
		},
		{
			name: "wrong object class",
			body: strings.Replace(rdapIPResponse, `"objectClassName": "ip network"`, `"objectClassName": "autnum"`, 1),
		},
		{
			name: "missing conformance",
			body: strings.Replace(rdapIPResponse, `"rdapConformance": ["rdap_level_0", "redacted"],`, "", 1),
		},
		{
			name: "invalid event date",
			body: strings.Replace(rdapIPResponse, `"2020-01-02T03:04:05Z"`, `"yesterday"`, 1),
		},
		{
			name: "trailing JSON",
			body: rdapIPResponse + `{}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			responseURL, _ := url.Parse("https://rdap.example.test/rdap/ip/192.0.2.42")
			_, err := parseRDAPIPResult("192.0.2.42", rdapHTTPResult{
				body:     []byte(test.body),
				finalURL: responseURL,
			}, time.Now())
			if !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("parse error = %v, want ErrMalformedResponse", err)
			}
		})
	}
}

func TestRDAPInputAndCacheKeys(t *testing.T) {
	resolver := &staticRDAPBootstrapResolver{identity: "https://bootstrap.example.test/rdap"}
	provider := RDAPProvider{Bootstrap: resolver}
	for _, value := range []string{"", "not-an-ip"} {
		if _, err := provider.LookupIPContext(context.Background(), value); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("IP %q error = %v, want ErrInvalidInput", value, err)
		}
	}
	for _, value := range []string{"", "not-an-asn", "AS4294967296"} {
		if _, err := provider.LookupASNContext(context.Background(), value); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("ASN %q error = %v, want ErrInvalidInput", value, err)
		}
	}
	if _, err := provider.LookupIPContext(nil, "192.0.2.42"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil IP context error = %v", err)
	}
	if _, err := provider.LookupASNContext(nil, "64500"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil ASN context error = %v", err)
	}

	ipSpec, err := provider.IPCacheKeySpec("192.0.2.42")
	if err != nil {
		t.Fatalf("IPCacheKeySpec: %v", err)
	}
	asnSpec, err := provider.ASNCacheKeySpec("AS64500")
	if err != nil {
		t.Fatalf("ASNCacheKeySpec: %v", err)
	}
	if ipSpec.Source != RDAPSource || ipSpec.Endpoint != resolver.identity ||
		ipSpec.Options["object"] != "ip" || ipSpec.NormalizedQuery != "192.0.2.42" {
		t.Fatalf("IP cache spec = %+v", ipSpec)
	}
	if asnSpec.Options["object"] != "autnum" || asnSpec.NormalizedQuery != "64500" {
		t.Fatalf("ASN cache spec = %+v", asnSpec)
	}
	ipKey, _ := CanonicalCacheKey(ipSpec)
	asnKey, _ := CanonicalCacheKey(asnSpec)
	if ipKey == asnKey {
		t.Fatalf("IP and ASN keys must differ: %q", ipKey)
	}

	client := &http.Client{}
	constructed := NewRDAPProvider(client)
	bootstrap, ok := constructed.Bootstrap.(*IANARDAPBootstrapResolver)
	if !ok || constructed.Client != client || bootstrap.Client != client {
		t.Fatalf("NewRDAPProvider did not share the supplied HTTP client")
	}
}

func TestRDAPRejectsPrivateTargetsByDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		writeRDAPJSON(response, rdapIPResponse)
	}))
	defer server.Close()
	resolver := &staticRDAPBootstrapResolver{}
	resolver.ipResult = testRDAPResolution(t, server.URL)
	provider := RDAPProvider{
		Client:            server.Client(),
		Bootstrap:         resolver,
		AllowInsecureHTTP: true,
	}

	_, err := provider.LookupIPContext(context.Background(), "192.0.2.42")
	if !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("private target error = %v, want ErrMalformedResponse", err)
	}
}

func TestRDAPRejectsSpecialUseTargetsAndResolvedAddresses(t *testing.T) {
	for _, address := range []string{
		"100.64.0.1",
		"192.0.0.9",
		"198.18.0.1",
		"2001:db8::1",
		"3fff::1",
	} {
		if !unsafeRDAPHostname(address) {
			t.Errorf("unsafeRDAPHostname(%q) = false", address)
		}
	}

	connection, err := publicRDAPDialer().DialContext(
		context.Background(),
		"tcp",
		net.JoinHostPort("localhost", "443"),
	)
	if connection != nil {
		connection.Close()
	}
	if !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("resolved loopback error = %v, want ErrMalformedResponse", err)
	}
}

func TestRDAPRequiresHTTPSByDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		writeRDAPJSON(response, rdapIPResponse)
	}))
	defer server.Close()
	resolver := &staticRDAPBootstrapResolver{}
	resolver.ipResult = testRDAPResolution(t, server.URL)
	provider := RDAPProvider{
		Client:                     server.Client(),
		Bootstrap:                  resolver,
		AllowPrivateNetworkTargets: true,
	}

	_, err := provider.LookupIPContext(context.Background(), "192.0.2.42")
	if !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("insecure target error = %v, want ErrMalformedResponse", err)
	}
}

func TestRDAPContextDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()
	resolver := &staticRDAPBootstrapResolver{}
	resolver.ipResult = testRDAPResolution(t, server.URL)
	provider := testRDAPProvider(server, resolver)
	provider.Timeout = 10 * time.Millisecond

	_, err := provider.LookupIPContext(context.Background(), "192.0.2.42")
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("deadline error = %v, want ErrTimeout", err)
	}
}

func TestRDAPBootstrapErrorsPropagate(t *testing.T) {
	resolver := &staticRDAPBootstrapResolver{ipError: fmt.Errorf("bootstrap: %w", ErrRateLimited)}
	provider := RDAPProvider{Bootstrap: resolver}
	_, err := provider.LookupIPContext(context.Background(), "192.0.2.42")
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("bootstrap error = %v, want ErrRateLimited", err)
	}
}
