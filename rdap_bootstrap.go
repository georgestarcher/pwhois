package pwhois

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// IANARDAPIPv4BootstrapURL is the authoritative IANA IPv4 RDAP bootstrap
	// registry defined by RFC 9224.
	IANARDAPIPv4BootstrapURL = "https://data.iana.org/rdap/ipv4.json"
	// IANARDAPIPv6BootstrapURL is the authoritative IANA IPv6 RDAP bootstrap
	// registry defined by RFC 9224.
	IANARDAPIPv6BootstrapURL = "https://data.iana.org/rdap/ipv6.json"
	// IANARDAPASNBootstrapURL is the authoritative IANA ASN RDAP bootstrap
	// registry defined by RFC 9224.
	IANARDAPASNBootstrapURL = "https://data.iana.org/rdap/asn.json"

	// DefaultRDAPBootstrapMaxResponseBytes bounds one IANA bootstrap document.
	DefaultRDAPBootstrapMaxResponseBytes int64 = 2 * 1024 * 1024
	// DefaultRDAPBootstrapTTL is used only when the bootstrap HTTP response
	// supplies no usable Expires header.
	DefaultRDAPBootstrapTTL = 24 * time.Hour
)

// RDAPBootstrapResolution identifies the authoritative base URLs for a query
// and the authorities that may receive a cross-origin RDAP referral. Allowed
// authorities are derived from the same trusted bootstrap document.
type RDAPBootstrapResolution struct {
	BaseURLs           []string
	AllowedAuthorities []string
	Publication        time.Time
}

// RDAPBootstrapResolver resolves IP and ASN queries to authoritative RDAP base
// URLs without exposing provider-specific bootstrap mechanics to RDAPProvider.
// Implementations must be safe for concurrent use.
type RDAPBootstrapResolver interface {
	ResolveIP(ctx context.Context, ip net.IP) (RDAPBootstrapResolution, error)
	ResolveASN(ctx context.Context, asn uint32) (RDAPBootstrapResolution, error)
	CacheIdentity() string
}

// IANARDAPBootstrapResolver fetches and caches the RFC 9224 IANA bootstrap
// registries. It honors the HTTP Expires header and does not refetch a fresh
// registry for every RDAP lookup. Do not copy or mutate a resolver after its
// first use.
type IANARDAPBootstrapResolver struct {
	Client           *http.Client
	IPv4URL          string
	IPv6URL          string
	ASNURL           string
	MaxResponseBytes int64
	FallbackTTL      time.Duration
	// AllowInsecureHTTP exists for controlled local test infrastructure. Do
	// not enable it for public bootstrap or RDAP traffic.
	AllowInsecureHTTP bool

	mu       sync.Mutex
	cache    map[string]rdapBootstrapCacheEntry
	inflight map[string]chan struct{}
}

type rdapBootstrapCacheEntry struct {
	document  rdapBootstrapDocument
	expiresAt time.Time
}

type rdapBootstrapDocument struct {
	Version     string
	Publication time.Time
	Services    []rdapBootstrapService
}

type rdapBootstrapService struct {
	Entries []string
	URLs    []string
}

type rawRDAPBootstrapDocument struct {
	Version     string       `json:"version"`
	Publication string       `json:"publication"`
	Services    [][][]string `json:"services"`
}

var defaultIANARDAPBootstrapResolver = &IANARDAPBootstrapResolver{}

// CacheIdentity identifies the IANA bootstrap contract in source-aware cache
// keys.
func (resolver *IANARDAPBootstrapResolver) CacheIdentity() string {
	ipv4URL, ipv6URL, asnURL := resolver.configuredURLs()
	return strings.Join([]string{ipv4URL, ipv6URL, asnURL}, "|")
}

func (resolver *IANARDAPBootstrapResolver) configuredURLs() (string, string, string) {
	ipv4URL := resolver.IPv4URL
	if ipv4URL == "" {
		ipv4URL = IANARDAPIPv4BootstrapURL
	}
	ipv6URL := resolver.IPv6URL
	if ipv6URL == "" {
		ipv6URL = IANARDAPIPv6BootstrapURL
	}
	asnURL := resolver.ASNURL
	if asnURL == "" {
		asnURL = IANARDAPASNBootstrapURL
	}
	return ipv4URL, ipv6URL, asnURL
}

func (resolver *IANARDAPBootstrapResolver) maxResponseBytes() int64 {
	if resolver.MaxResponseBytes > 0 {
		return resolver.MaxResponseBytes
	}
	return DefaultRDAPBootstrapMaxResponseBytes
}

func (resolver *IANARDAPBootstrapResolver) fallbackTTL() time.Duration {
	if resolver.FallbackTTL > 0 {
		return resolver.FallbackTTL
	}
	return DefaultRDAPBootstrapTTL
}

// ResolveIP performs the RFC 9224 longest-prefix match against the cached
// IPv4 or IPv6 IANA bootstrap registry.
func (resolver *IANARDAPBootstrapResolver) ResolveIP(ctx context.Context, ip net.IP) (RDAPBootstrapResolution, error) {
	if ctx == nil {
		return RDAPBootstrapResolution{}, invalidInputError("context must not be nil")
	}
	if ip == nil {
		return RDAPBootstrapResolution{}, invalidInputError("IP address is required")
	}

	ipv4URL, ipv6URL, _ := resolver.configuredURLs()
	bootstrapURL := ipv6URL
	wantIPv4 := false
	if ip.To4() != nil {
		bootstrapURL = ipv4URL
		wantIPv4 = true
	}
	document, err := resolver.load(ctx, bootstrapURL)
	if err != nil {
		return RDAPBootstrapResolution{}, err
	}

	bestPrefixLength := -1
	var matchedURLs []string
	for _, service := range document.Services {
		serviceMatchedLength := -1
		for _, entry := range service.Entries {
			entryIP, prefix, err := net.ParseCIDR(entry)
			if err != nil || !entryIP.Equal(prefix.IP) || (prefix.IP.To4() != nil) != wantIPv4 {
				return RDAPBootstrapResolution{}, malformedResponseError(fmt.Errorf("invalid IP bootstrap entry"))
			}
			if prefix.Contains(ip) {
				ones, _ := prefix.Mask.Size()
				if ones > serviceMatchedLength {
					serviceMatchedLength = ones
				}
			}
		}
		if serviceMatchedLength < bestPrefixLength {
			continue
		}
		if serviceMatchedLength == bestPrefixLength && serviceMatchedLength >= 0 {
			return RDAPBootstrapResolution{}, malformedResponseError(fmt.Errorf("ambiguous IP bootstrap match"))
		}
		if serviceMatchedLength >= 0 {
			bestPrefixLength = serviceMatchedLength
			matchedURLs = service.URLs
		}
	}
	if bestPrefixLength < 0 {
		return RDAPBootstrapResolution{}, noRecordsError("IANA RDAP IP bootstrap")
	}

	return resolver.resolution(document, matchedURLs)
}

// ResolveASN performs the RFC 9224 inclusive AS-number range match against the
// cached IANA bootstrap registry.
func (resolver *IANARDAPBootstrapResolver) ResolveASN(ctx context.Context, asn uint32) (RDAPBootstrapResolution, error) {
	if ctx == nil {
		return RDAPBootstrapResolution{}, invalidInputError("context must not be nil")
	}

	_, _, asnURL := resolver.configuredURLs()
	document, err := resolver.load(ctx, asnURL)
	if err != nil {
		return RDAPBootstrapResolution{}, err
	}

	var matchedURLs []string
	found := false
	for _, service := range document.Services {
		serviceMatched := false
		for _, entry := range service.Entries {
			start, end, err := parseRDAPASNBootstrapRange(entry)
			if err != nil {
				return RDAPBootstrapResolution{}, malformedResponseError(err)
			}
			if asn >= start && asn <= end {
				serviceMatched = true
			}
		}
		if !serviceMatched {
			continue
		}
		if found {
			return RDAPBootstrapResolution{}, malformedResponseError(fmt.Errorf("ambiguous ASN bootstrap match"))
		}
		found = true
		matchedURLs = service.URLs
	}
	if !found {
		return RDAPBootstrapResolution{}, noRecordsError("IANA RDAP ASN bootstrap")
	}

	return resolver.resolution(document, matchedURLs)
}

func (resolver *IANARDAPBootstrapResolver) resolution(document rdapBootstrapDocument, matchedURLs []string) (RDAPBootstrapResolution, error) {
	baseURLs, err := resolver.acceptedURLs(matchedURLs)
	if err != nil {
		return RDAPBootstrapResolution{}, err
	}
	if len(baseURLs) == 0 {
		return RDAPBootstrapResolution{}, malformedResponseError(fmt.Errorf("bootstrap match has no secure RDAP URL"))
	}

	authoritySet := make(map[string]struct{})
	for _, service := range document.Services {
		urls, err := resolver.acceptedURLs(service.URLs)
		if err != nil {
			return RDAPBootstrapResolution{}, err
		}
		for _, value := range urls {
			parsed, _ := url.Parse(value)
			authoritySet[strings.ToLower(parsed.Host)] = struct{}{}
		}
	}
	authorities := make([]string, 0, len(authoritySet))
	for authority := range authoritySet {
		authorities = append(authorities, authority)
	}
	sort.Strings(authorities)

	return RDAPBootstrapResolution{
		BaseURLs:           baseURLs,
		AllowedAuthorities: authorities,
		Publication:        document.Publication,
	}, nil
}

func (resolver *IANARDAPBootstrapResolver) acceptedURLs(values []string) ([]string, error) {
	secure := make([]string, 0, len(values))
	insecure := make([]string, 0, len(values))
	for _, value := range values {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
			parsed.Fragment != "" || !strings.HasSuffix(parsed.Path, "/") {
			return nil, malformedResponseError(fmt.Errorf("invalid RDAP bootstrap service URL"))
		}
		switch strings.ToLower(parsed.Scheme) {
		case "https":
			secure = append(secure, parsed.String())
		case "http":
			if resolver.AllowInsecureHTTP {
				insecure = append(insecure, parsed.String())
			}
		default:
			return nil, malformedResponseError(fmt.Errorf("unsupported RDAP bootstrap service URL scheme"))
		}
	}
	return append(secure, insecure...), nil
}

func (resolver *IANARDAPBootstrapResolver) load(ctx context.Context, bootstrapURL string) (rdapBootstrapDocument, error) {
	for {
		resolver.mu.Lock()
		if resolver.cache != nil {
			if cached, found := resolver.cache[bootstrapURL]; found && time.Now().Before(cached.expiresAt) {
				resolver.mu.Unlock()
				return cached.document, nil
			}
		}
		if waiting, found := resolver.inflight[bootstrapURL]; found {
			resolver.mu.Unlock()
			select {
			case <-waiting:
				continue
			case <-ctx.Done():
				return rdapBootstrapDocument{}, classifyTransportError(ctx.Err())
			}
		}
		if resolver.inflight == nil {
			resolver.inflight = make(map[string]chan struct{})
		}
		waiting := make(chan struct{})
		resolver.inflight[bootstrapURL] = waiting
		resolver.mu.Unlock()

		document, expiresAt, err := resolver.fetch(ctx, bootstrapURL)

		resolver.mu.Lock()
		if err == nil {
			if resolver.cache == nil {
				resolver.cache = make(map[string]rdapBootstrapCacheEntry)
			}
			resolver.cache[bootstrapURL] = rdapBootstrapCacheEntry{document: document, expiresAt: expiresAt}
		}
		delete(resolver.inflight, bootstrapURL)
		close(waiting)
		resolver.mu.Unlock()
		return document, err
	}
}

func (resolver *IANARDAPBootstrapResolver) fetch(ctx context.Context, bootstrapURL string) (rdapBootstrapDocument, time.Time, error) {
	parsedURL, err := url.Parse(bootstrapURL)
	if err != nil || parsedURL.Host == "" || parsedURL.User != nil ||
		parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return rdapBootstrapDocument{}, time.Time{}, invalidInputError("invalid RDAP bootstrap URL")
	}
	if parsedURL.Scheme != "https" && !(resolver.AllowInsecureHTTP && parsedURL.Scheme == "http") {
		return rdapBootstrapDocument{}, time.Time{}, invalidInputError("RDAP bootstrap URL must use HTTPS")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return rdapBootstrapDocument{}, time.Time{}, invalidInputError("invalid RDAP bootstrap request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", AppName)

	response, err := rdapNoRedirectClient(resolver.Client).Do(request)
	if err != nil {
		return rdapBootstrapDocument{}, time.Time{}, classifyContextTransportError(ctx, err)
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusTooManyRequests:
		return rdapBootstrapDocument{}, time.Time{}, ErrRateLimited
	case http.StatusNotFound:
		return rdapBootstrapDocument{}, time.Time{}, noRecordsError("IANA RDAP bootstrap")
	default:
		if response.StatusCode >= 500 {
			return rdapBootstrapDocument{}, time.Time{}, fmt.Errorf("%w: bootstrap HTTP status %d", ErrConnection, response.StatusCode)
		}
		return rdapBootstrapDocument{}, time.Time{}, fmt.Errorf("%w: bootstrap HTTP status %d", ErrProviderRejected, response.StatusCode)
	}
	if !isRDAPJSONContentType(response.Header.Get("Content-Type"), "application/json") {
		return rdapBootstrapDocument{}, time.Time{}, malformedResponseError(fmt.Errorf("unexpected RDAP bootstrap content type"))
	}

	body, err := readBoundedHTTPBody(response.Body, resolver.maxResponseBytes())
	if err != nil {
		if errors.Is(err, ErrResponseTooLarge) {
			return rdapBootstrapDocument{}, time.Time{}, err
		}
		return rdapBootstrapDocument{}, time.Time{}, classifyContextTransportError(ctx, err)
	}
	document, err := parseRDAPBootstrapDocument(body)
	if err != nil {
		return rdapBootstrapDocument{}, time.Time{}, err
	}

	now := time.Now()
	expiresAt := now.Add(resolver.fallbackTTL())
	if expires := response.Header.Get("Expires"); expires != "" {
		if parsed, err := http.ParseTime(expires); err == nil {
			expiresAt = parsed
		}
	}
	return document, expiresAt, nil
}

func parseRDAPBootstrapDocument(body []byte) (rdapBootstrapDocument, error) {
	var raw rawRDAPBootstrapDocument
	if err := decodeSingleJSON(body, &raw); err != nil {
		return rdapBootstrapDocument{}, malformedResponseError(fmt.Errorf("decode RDAP bootstrap: %w", err))
	}
	if raw.Version != "1.0" {
		return rdapBootstrapDocument{}, malformedResponseError(fmt.Errorf("unsupported RDAP bootstrap version"))
	}
	publication, err := time.Parse(time.RFC3339, raw.Publication)
	if err != nil {
		return rdapBootstrapDocument{}, malformedResponseError(fmt.Errorf("invalid RDAP bootstrap publication time"))
	}
	if len(raw.Services) == 0 {
		return rdapBootstrapDocument{}, malformedResponseError(fmt.Errorf("RDAP bootstrap contains no services"))
	}

	document := rdapBootstrapDocument{
		Version:     raw.Version,
		Publication: publication,
		Services:    make([]rdapBootstrapService, 0, len(raw.Services)),
	}
	for _, service := range raw.Services {
		if len(service) != 2 || len(service[0]) == 0 || len(service[1]) == 0 {
			return rdapBootstrapDocument{}, malformedResponseError(fmt.Errorf("invalid RDAP bootstrap service"))
		}
		document.Services = append(document.Services, rdapBootstrapService{
			Entries: append([]string(nil), service[0]...),
			URLs:    append([]string(nil), service[1]...),
		})
	}
	return document, nil
}

func parseRDAPASNBootstrapRange(value string) (uint32, uint32, error) {
	startText, endText, found := strings.Cut(strings.TrimSpace(value), "-")
	if !found {
		return 0, 0, fmt.Errorf("invalid ASN bootstrap range")
	}
	start, err := strconv.ParseUint(startText, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid ASN bootstrap range")
	}
	end, err := strconv.ParseUint(endText, 10, 32)
	if err != nil || start > end {
		return 0, 0, fmt.Errorf("invalid ASN bootstrap range")
	}
	return uint32(start), uint32(end), nil
}

func rdapNoRedirectClient(client *http.Client) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	cloned := *client
	cloned.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &cloned
}

func isRDAPJSONContentType(value, expected string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && strings.EqualFold(mediaType, expected)
}

func readBoundedHTTPBody(reader io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = DefaultMaxResponseBytes
	}
	limited := io.LimitReader(reader, limit+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, &ResponseTooLargeError{Limit: limit}
	}
	return body, nil
}

func decodeSingleJSON(body []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}
