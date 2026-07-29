package pwhois

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// DefaultRDAPMaxReferrals bounds manually followed HTTP redirects.
	DefaultRDAPMaxReferrals = 3
	// maxRDAPEntityDepth bounds recursive entity traversal in untrusted RDAP
	// responses.
	maxRDAPEntityDepth = 8

	// RDAPSource identifies normalized RDAP registration results.
	RDAPSource = "rdap"
	// RDAPProtocolVersion identifies the RDAP HTTP/JSON contract in cache keys.
	RDAPProtocolVersion = "rdap-http-rfc9082-rfc9083"
	// RDAPParserVersion identifies the privacy-minimized parser contract.
	RDAPParserVersion = "rdap-registration-v1"
	// RDAPIPResultSchemaVersion identifies the normalized IP result shape.
	RDAPIPResultSchemaVersion = "rdap-ip-result-v1"
	// RDAPASNResultSchemaVersion identifies the normalized ASN result shape.
	RDAPASNResultSchemaVersion = "rdap-asn-result-v1"
)

// RDAPProvider configures explicit IP and ASN registration lookups. It uses
// IANA bootstrap data by default and follows only bounded, bootstrap-authorized
// referrals. It does not expose complete RDAP entity or jCard contact data.
type RDAPProvider struct {
	Client    *http.Client
	Bootstrap RDAPBootstrapResolver
	Timeout   time.Duration
	// MaxResponseBytes bounds one final RDAP response before JSON parsing.
	MaxResponseBytes int64
	// MaxReferrals bounds manually followed HTTP redirects. A value less than
	// or equal to zero uses DefaultRDAPMaxReferrals.
	MaxReferrals int
	// AllowInsecureHTTP and AllowPrivateNetworkTargets exist for controlled
	// local test infrastructure. Do not enable them for public RDAP traffic.
	AllowInsecureHTTP          bool
	AllowPrivateNetworkTargets bool
}

// NewRDAPProvider returns a provider whose IANA bootstrap and authoritative
// RDAP requests share one HTTP client while retaining a provider-owned
// bootstrap cache. A nil client uses http.DefaultClient.
func NewRDAPProvider(client *http.Client) RDAPProvider {
	return RDAPProvider{
		Client: client,
		Bootstrap: &IANARDAPBootstrapResolver{
			Client: client,
		},
	}
}

// RDAPEvent is a public provider event without the optional eventActor contact
// field.
type RDAPEvent struct {
	Action string    `json:"action"`
	Date   time.Time `json:"date"`
}

// RDAPEntityReference retains a public entity handle and its roles without
// copying email, telephone, postal-address, or personal-name fields.
type RDAPEntityReference struct {
	Handle string   `json:"handle"`
	Roles  []string `json:"roles"`
}

// RDAPRedactionIndicator reports a provider-declared redaction without
// retaining JSON paths that might describe omitted contact fields.
type RDAPRedactionIndicator struct {
	Name   string `json:"name"`
	Method string `json:"method"`
	Reason string `json:"reason"`
}

// RDAPIPResult is privacy-minimized IP allocation or assignment context. It is
// registration data, not observed routing, geolocation, or sender attribution.
type RDAPIPResult struct {
	Query                   string                   `json:"query"`
	StartAddress            string                   `json:"start_address"`
	EndAddress              string                   `json:"end_address"`
	IPVersion               string                   `json:"ip_version"`
	Handle                  string                   `json:"handle"`
	Name                    string                   `json:"name"`
	Type                    string                   `json:"type"`
	CountryCode             string                   `json:"country_code"`
	ParentHandle            string                   `json:"parent_handle"`
	Status                  []string                 `json:"status"`
	Events                  []RDAPEvent              `json:"events"`
	RegisteredOrganizations []string                 `json:"registered_organizations"`
	AbuseContacts           []RDAPEntityReference    `json:"abuse_contacts"`
	Redacted                bool                     `json:"redacted"`
	Redactions              []RDAPRedactionIndicator `json:"redactions"`
	Registry                string                   `json:"registry"`
	Endpoint                string                   `json:"endpoint"`
	ReferralCount           int                      `json:"referral_count"`
	BootstrapPublication    time.Time                `json:"bootstrap_publication"`
	Source                  string                   `json:"source"`
	FetchedAt               time.Time                `json:"fetched_at"`
}

// RDAPASNResult is privacy-minimized autonomous-system registration context.
// It is registration data and does not assert that the ASN currently
// originates a route.
type RDAPASNResult struct {
	Query                   uint32                   `json:"query"`
	StartAutnum             uint32                   `json:"start_autnum"`
	EndAutnum               uint32                   `json:"end_autnum"`
	Handle                  string                   `json:"handle"`
	Name                    string                   `json:"name"`
	Type                    string                   `json:"type"`
	CountryCode             string                   `json:"country_code"`
	Status                  []string                 `json:"status"`
	Events                  []RDAPEvent              `json:"events"`
	RegisteredOrganizations []string                 `json:"registered_organizations"`
	AbuseContacts           []RDAPEntityReference    `json:"abuse_contacts"`
	Redacted                bool                     `json:"redacted"`
	Redactions              []RDAPRedactionIndicator `json:"redactions"`
	Registry                string                   `json:"registry"`
	Endpoint                string                   `json:"endpoint"`
	ReferralCount           int                      `json:"referral_count"`
	BootstrapPublication    time.Time                `json:"bootstrap_publication"`
	Source                  string                   `json:"source"`
	FetchedAt               time.Time                `json:"fetched_at"`
}

type rdapHTTPResult struct {
	body                 []byte
	finalURL             *url.URL
	referralCount        int
	bootstrapPublication time.Time
}

type rawRDAPObject struct {
	RDAPConformance []string           `json:"rdapConformance"`
	ObjectClassName string             `json:"objectClassName"`
	Handle          string             `json:"handle"`
	StartAddress    string             `json:"startAddress"`
	EndAddress      string             `json:"endAddress"`
	IPVersion       string             `json:"ipVersion"`
	StartAutnum     *uint64            `json:"startAutnum"`
	EndAutnum       *uint64            `json:"endAutnum"`
	Name            string             `json:"name"`
	Type            string             `json:"type"`
	Country         string             `json:"country"`
	ParentHandle    string             `json:"parentHandle"`
	Status          []string           `json:"status"`
	Events          []rawRDAPEvent     `json:"events"`
	Entities        []rawRDAPEntity    `json:"entities"`
	Redacted        []rawRDAPRedaction `json:"redacted"`
}

type rawRDAPEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rawRDAPEntity struct {
	ObjectClassName string          `json:"objectClassName"`
	Handle          string          `json:"handle"`
	Roles           []string        `json:"roles"`
	Status          []string        `json:"status"`
	VCardArray      json.RawMessage `json:"vcardArray"`
	Entities        []rawRDAPEntity `json:"entities"`
}

type rawRDAPRedaction struct {
	Name struct {
		Type        string `json:"type"`
		Description string `json:"description"`
	} `json:"name"`
	Method string `json:"method"`
	Reason struct {
		Type        string `json:"type"`
		Description string `json:"description"`
	} `json:"reason"`
}

type normalizedRDAPCommon struct {
	handle                  string
	name                    string
	recordType              string
	countryCode             string
	status                  []string
	events                  []RDAPEvent
	registeredOrganizations []string
	abuseContacts           []RDAPEntityReference
	redacted                bool
	redactions              []RDAPRedactionIndicator
}

func (provider RDAPProvider) configured() RDAPProvider {
	if provider.Bootstrap == nil {
		provider.Bootstrap = defaultIANARDAPBootstrapResolver
	}
	if provider.Timeout <= 0 {
		provider.Timeout = time.Second * time.Duration(SocketTimeout)
	}
	if provider.MaxResponseBytes <= 0 {
		provider.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if provider.MaxReferrals <= 0 {
		provider.MaxReferrals = DefaultRDAPMaxReferrals
	}
	return provider
}

func (provider RDAPProvider) operationError(operation, endpoint string, err error) error {
	return &OperationError{Operation: operation, Server: endpoint, Err: err}
}

// IPCacheKeySpec returns the source-aware identity for an RDAP IP lookup.
func (provider RDAPProvider) IPCacheKeySpec(value string) (CacheKeySpec, error) {
	provider = provider.configured()
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return CacheKeySpec{}, invalidInputError("invalid IP address")
	}
	return provider.cacheKeySpec("ip", ip.String(), RDAPIPResultSchemaVersion)
}

// ASNCacheKeySpec returns the source-aware identity for an RDAP ASN lookup.
func (provider RDAPProvider) ASNCacheKeySpec(value string) (CacheKeySpec, error) {
	provider = provider.configured()
	asn, err := normalizeRDAPASN(value)
	if err != nil {
		return CacheKeySpec{}, err
	}
	return provider.cacheKeySpec("autnum", strconv.FormatUint(uint64(asn), 10), RDAPASNResultSchemaVersion)
}

func (provider RDAPProvider) cacheKeySpec(objectType, query, schema string) (CacheKeySpec, error) {
	identity := strings.TrimSpace(provider.Bootstrap.CacheIdentity())
	if identity == "" {
		return CacheKeySpec{}, invalidInputError("RDAP bootstrap cache identity is required")
	}
	transport := "https-only"
	if provider.AllowInsecureHTTP {
		transport = "http-allowed"
	}
	targetScope := "public-only"
	if provider.AllowPrivateNetworkTargets {
		targetScope = "private-allowed"
	}
	return CacheKeySpec{
		Source:          RDAPSource,
		Endpoint:        identity,
		Protocol:        RDAPProtocolVersion,
		NormalizedQuery: query,
		Options: map[string]string{
			"object":        objectType,
			"max_referrals": strconv.Itoa(provider.MaxReferrals),
			"privacy":       "organization-and-references-only",
			"target_scope":  targetScope,
			"transport":     transport,
		},
		ParserVersion:       RDAPParserVersion,
		ResultSchemaVersion: schema,
	}, nil
}

// LookupIPContext returns authoritative RDAP allocation or assignment context
// for one IP address. Contact data is privacy-minimized to organization names
// and abuse entity handles.
func (provider RDAPProvider) LookupIPContext(ctx context.Context, value string) (RDAPIPResult, error) {
	const operation = "lookup RDAP IP registration"

	provider = provider.configured()
	if ctx == nil {
		return RDAPIPResult{}, provider.operationError(operation, provider.Bootstrap.CacheIdentity(), invalidInputError("context must not be nil"))
	}
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return RDAPIPResult{}, provider.operationError(operation, provider.Bootstrap.CacheIdentity(), invalidInputError("invalid IP address"))
	}
	query := ip.String()

	lookupCtx, cancel := context.WithTimeout(ctx, provider.Timeout)
	defer cancel()
	resolution, err := provider.Bootstrap.ResolveIP(lookupCtx, ip)
	if err != nil {
		return RDAPIPResult{}, provider.operationError(operation, provider.Bootstrap.CacheIdentity(), err)
	}
	httpResult, err := provider.fetch(lookupCtx, resolution, "ip", query)
	if err != nil {
		endpoint := rdapOrigin(httpResult.finalURL)
		if endpoint == "" {
			endpoint = provider.Bootstrap.CacheIdentity()
		}
		return RDAPIPResult{}, provider.operationError(operation, endpoint, err)
	}
	result, err := parseRDAPIPResult(query, httpResult, time.Now().UTC())
	if err != nil {
		return RDAPIPResult{}, provider.operationError(operation, rdapOrigin(httpResult.finalURL), err)
	}
	if err := lookupCtx.Err(); err != nil {
		return RDAPIPResult{}, provider.operationError(operation, rdapOrigin(httpResult.finalURL), classifyTransportError(err))
	}
	return result, nil
}

// LookupASNContext returns authoritative RDAP registration context for one
// autonomous system number.
func (provider RDAPProvider) LookupASNContext(ctx context.Context, value string) (RDAPASNResult, error) {
	const operation = "lookup RDAP ASN registration"

	provider = provider.configured()
	if ctx == nil {
		return RDAPASNResult{}, provider.operationError(operation, provider.Bootstrap.CacheIdentity(), invalidInputError("context must not be nil"))
	}
	asn, err := normalizeRDAPASN(value)
	if err != nil {
		return RDAPASNResult{}, provider.operationError(operation, provider.Bootstrap.CacheIdentity(), err)
	}
	query := strconv.FormatUint(uint64(asn), 10)

	lookupCtx, cancel := context.WithTimeout(ctx, provider.Timeout)
	defer cancel()
	resolution, err := provider.Bootstrap.ResolveASN(lookupCtx, asn)
	if err != nil {
		return RDAPASNResult{}, provider.operationError(operation, provider.Bootstrap.CacheIdentity(), err)
	}
	httpResult, err := provider.fetch(lookupCtx, resolution, "autnum", query)
	if err != nil {
		endpoint := rdapOrigin(httpResult.finalURL)
		if endpoint == "" {
			endpoint = provider.Bootstrap.CacheIdentity()
		}
		return RDAPASNResult{}, provider.operationError(operation, endpoint, err)
	}
	result, err := parseRDAPASNResult(asn, httpResult, time.Now().UTC())
	if err != nil {
		return RDAPASNResult{}, provider.operationError(operation, rdapOrigin(httpResult.finalURL), err)
	}
	if err := lookupCtx.Err(); err != nil {
		return RDAPASNResult{}, provider.operationError(operation, rdapOrigin(httpResult.finalURL), classifyTransportError(err))
	}
	return result, nil
}

func normalizeRDAPASN(value string) (uint32, error) {
	normalized, err := normalizeASN(value)
	if err != nil {
		return 0, err
	}
	asn, err := strconv.ParseUint(normalized, 10, 32)
	if err != nil {
		return 0, invalidInputError("ASN must fit in 32 bits")
	}
	return uint32(asn), nil
}

func (provider RDAPProvider) fetch(ctx context.Context, resolution RDAPBootstrapResolution, objectType, resource string) (rdapHTTPResult, error) {
	if len(resolution.BaseURLs) == 0 {
		return rdapHTTPResult{}, noRecordsError("RDAP bootstrap resolution")
	}
	if resolution.Publication.IsZero() {
		return rdapHTTPResult{}, malformedResponseError(fmt.Errorf("RDAP bootstrap publication time is required"))
	}

	allowed := make(map[string]struct{}, len(resolution.AllowedAuthorities))
	for _, authority := range resolution.AllowedAuthorities {
		authority = strings.ToLower(strings.TrimSpace(authority))
		if authority == "" {
			return rdapHTTPResult{}, malformedResponseError(fmt.Errorf("empty bootstrap referral authority"))
		}
		allowed[authority] = struct{}{}
	}

	current, err := buildRDAPQueryURL(resolution.BaseURLs[0], objectType, resource)
	if err != nil {
		return rdapHTTPResult{}, err
	}
	if err := provider.validateTarget(current, objectType, resource); err != nil {
		return rdapHTTPResult{finalURL: current}, err
	}
	client, err := provider.authoritativeClient()
	if err != nil {
		return rdapHTTPResult{finalURL: current}, err
	}

	visited := make(map[string]struct{})
	for referralCount := 0; ; referralCount++ {
		failure := rdapHTTPResult{
			finalURL:             current,
			referralCount:        referralCount,
			bootstrapPublication: resolution.Publication,
		}
		currentKey := current.String()
		if _, found := visited[currentKey]; found {
			return failure, malformedResponseError(fmt.Errorf("RDAP referral loop"))
		}
		visited[currentKey] = struct{}{}

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			return failure, invalidInputError("invalid RDAP request URL")
		}
		request.Header.Set("Accept", "application/rdap+json")
		request.Header.Set("User-Agent", AppName)

		response, err := client.Do(request)
		if err != nil {
			if errors.Is(err, ErrMalformedResponse) {
				return failure, err
			}
			return failure, classifyContextTransportError(ctx, err)
		}

		switch response.StatusCode {
		case http.StatusOK:
			if !isRDAPJSONContentType(response.Header.Get("Content-Type"), "application/rdap+json") {
				response.Body.Close()
				return failure, malformedResponseError(fmt.Errorf("unexpected RDAP content type"))
			}
			body, readErr := readBoundedHTTPBody(response.Body, provider.MaxResponseBytes)
			response.Body.Close()
			if readErr != nil {
				if errors.Is(readErr, ErrResponseTooLarge) {
					return failure, readErr
				}
				return failure, classifyContextTransportError(ctx, readErr)
			}
			return rdapHTTPResult{
				body:                 body,
				finalURL:             current,
				referralCount:        referralCount,
				bootstrapPublication: resolution.Publication,
			}, nil
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
			http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
			location := response.Header.Get("Location")
			response.Body.Close()
			if referralCount >= provider.MaxReferrals {
				return failure, malformedResponseError(fmt.Errorf("RDAP referral limit exceeded"))
			}
			next, err := current.Parse(location)
			if err != nil {
				return failure, malformedResponseError(fmt.Errorf("invalid RDAP referral URL"))
			}
			if err := provider.validateTarget(next, objectType, resource); err != nil {
				return failure, err
			}
			if !strings.EqualFold(current.Host, next.Host) {
				if _, found := allowed[strings.ToLower(next.Host)]; !found {
					return failure, malformedResponseError(fmt.Errorf("RDAP referral authority is not bootstrap-authorized"))
				}
			}
			current = next
		case http.StatusNotFound:
			response.Body.Close()
			return failure, noRecordsError("RDAP registration lookup")
		case http.StatusTooManyRequests:
			response.Body.Close()
			return failure, ErrRateLimited
		default:
			status := response.StatusCode
			response.Body.Close()
			if status >= 500 {
				return failure, fmt.Errorf("%w: RDAP HTTP status %d", ErrConnection, status)
			}
			return failure, fmt.Errorf("%w: RDAP HTTP status %d", ErrProviderRejected, status)
		}
	}
}

func (provider RDAPProvider) authoritativeClient() (*http.Client, error) {
	client := rdapNoRedirectClient(provider.Client)
	if provider.AllowPrivateNetworkTargets {
		return client, nil
	}

	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	httpTransport, ok := transport.(*http.Transport)
	if !ok {
		return nil, invalidInputError("public-only RDAP requires an HTTP transport with dial-time address validation")
	}
	clonedTransport := httpTransport.Clone()
	// A proxy may resolve the target remotely, outside this process's
	// dial-time address policy. Public-only mode therefore connects directly.
	clonedTransport.Proxy = nil
	clonedTransport.DialContext = publicRDAPDialer().DialContext
	clonedTransport.DialTLSContext = nil
	clonedTransport.DialTLS = nil
	client.Transport = clonedTransport
	return client, nil
}

func publicRDAPDialer() *net.Dialer {
	return &net.Dialer{
		KeepAlive: time.Second * time.Duration(SocketKeepAlive),
		ControlContext: func(_ context.Context, _, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return malformedResponseError(fmt.Errorf("invalid resolved RDAP target"))
			}
			ip := net.ParseIP(strings.Trim(host, "[]"))
			if ip == nil || unsafeRDAPIPAddress(ip) {
				return malformedResponseError(fmt.Errorf("RDAP target resolved to a non-public or special-use address"))
			}
			return nil
		},
	}
}

func buildRDAPQueryURL(baseURL, objectType, resource string) (*url.URL, error) {
	base, err := url.Parse(baseURL)
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" ||
		base.Fragment != "" || !strings.HasSuffix(base.Path, "/") {
		return nil, malformedResponseError(fmt.Errorf("invalid RDAP bootstrap base URL"))
	}
	base.Path += objectType + "/" + resource
	return base, nil
}

func (provider RDAPProvider) validateTarget(target *url.URL, objectType, resource string) error {
	if target == nil || target.Host == "" || target.User != nil || target.RawQuery != "" || target.Fragment != "" {
		return malformedResponseError(fmt.Errorf("unsafe RDAP referral URL"))
	}
	scheme := strings.ToLower(target.Scheme)
	if scheme != "https" && !(provider.AllowInsecureHTTP && scheme == "http") {
		return malformedResponseError(fmt.Errorf("RDAP target must use HTTPS"))
	}
	if !provider.AllowPrivateNetworkTargets && unsafeRDAPHostname(target.Hostname()) {
		return malformedResponseError(fmt.Errorf("RDAP target is not a public network host"))
	}

	path := strings.TrimSuffix(target.Path, "/")
	if !strings.HasSuffix(path, "/"+objectType+"/"+resource) {
		return malformedResponseError(fmt.Errorf("RDAP referral changed the requested resource"))
	}
	return nil
}

func unsafeRDAPHostname(hostname string) bool {
	hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	if hostname == "" || hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") ||
		strings.HasSuffix(hostname, ".local") {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && unsafeRDAPIPAddress(ip)
}

var rdapSpecialUsePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

func unsafeRDAPIPAddress(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() {
		return true
	}
	for _, prefix := range rdapSpecialUsePrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func parseRDAPIPResult(query string, response rdapHTTPResult, fetchedAt time.Time) (RDAPIPResult, error) {
	raw, common, err := parseRDAPObject(response.body, "ip network")
	if err != nil {
		return RDAPIPResult{}, err
	}

	queryIP := net.ParseIP(query)
	startIP := net.ParseIP(strings.TrimSpace(raw.StartAddress))
	endIP := net.ParseIP(strings.TrimSpace(raw.EndAddress))
	if queryIP == nil || startIP == nil || endIP == nil {
		return RDAPIPResult{}, malformedResponseError(fmt.Errorf("invalid RDAP IP range"))
	}
	wantV4 := queryIP.To4() != nil
	if (startIP.To4() != nil) != wantV4 || (endIP.To4() != nil) != wantV4 {
		return RDAPIPResult{}, malformedResponseError(fmt.Errorf("RDAP IP range address family mismatch"))
	}
	if compareIP(startIP, endIP) > 0 || compareIP(queryIP, startIP) < 0 || compareIP(queryIP, endIP) > 0 {
		return RDAPIPResult{}, malformedResponseError(fmt.Errorf("RDAP IP range does not contain the query"))
	}
	ipVersion := strings.ToLower(strings.TrimSpace(raw.IPVersion))
	if (wantV4 && ipVersion != "v4") || (!wantV4 && ipVersion != "v6") {
		return RDAPIPResult{}, malformedResponseError(fmt.Errorf("invalid RDAP IP version"))
	}

	return RDAPIPResult{
		Query:                   query,
		StartAddress:            canonicalIP(startIP),
		EndAddress:              canonicalIP(endIP),
		IPVersion:               ipVersion,
		Handle:                  common.handle,
		Name:                    common.name,
		Type:                    common.recordType,
		CountryCode:             common.countryCode,
		ParentHandle:            strings.TrimSpace(raw.ParentHandle),
		Status:                  common.status,
		Events:                  common.events,
		RegisteredOrganizations: common.registeredOrganizations,
		AbuseContacts:           common.abuseContacts,
		Redacted:                common.redacted,
		Redactions:              common.redactions,
		Registry:                strings.ToLower(response.finalURL.Hostname()),
		Endpoint:                rdapOrigin(response.finalURL),
		ReferralCount:           response.referralCount,
		BootstrapPublication:    response.bootstrapPublication,
		Source:                  RDAPSource,
		FetchedAt:               fetchedAt,
	}, nil
}

func parseRDAPASNResult(query uint32, response rdapHTTPResult, fetchedAt time.Time) (RDAPASNResult, error) {
	raw, common, err := parseRDAPObject(response.body, "autnum")
	if err != nil {
		return RDAPASNResult{}, err
	}
	if raw.StartAutnum == nil || raw.EndAutnum == nil || *raw.StartAutnum > uint64(^uint32(0)) ||
		*raw.EndAutnum > uint64(^uint32(0)) || *raw.StartAutnum > *raw.EndAutnum ||
		uint64(query) < *raw.StartAutnum || uint64(query) > *raw.EndAutnum {
		return RDAPASNResult{}, malformedResponseError(fmt.Errorf("invalid RDAP ASN range"))
	}

	return RDAPASNResult{
		Query:                   query,
		StartAutnum:             uint32(*raw.StartAutnum),
		EndAutnum:               uint32(*raw.EndAutnum),
		Handle:                  common.handle,
		Name:                    common.name,
		Type:                    common.recordType,
		CountryCode:             common.countryCode,
		Status:                  common.status,
		Events:                  common.events,
		RegisteredOrganizations: common.registeredOrganizations,
		AbuseContacts:           common.abuseContacts,
		Redacted:                common.redacted,
		Redactions:              common.redactions,
		Registry:                strings.ToLower(response.finalURL.Hostname()),
		Endpoint:                rdapOrigin(response.finalURL),
		ReferralCount:           response.referralCount,
		BootstrapPublication:    response.bootstrapPublication,
		Source:                  RDAPSource,
		FetchedAt:               fetchedAt,
	}, nil
}

func parseRDAPObject(body []byte, objectClass string) (rawRDAPObject, normalizedRDAPCommon, error) {
	var raw rawRDAPObject
	if err := decodeSingleJSON(body, &raw); err != nil {
		return rawRDAPObject{}, normalizedRDAPCommon{}, malformedResponseError(fmt.Errorf("decode RDAP response: %w", err))
	}
	if !strings.EqualFold(strings.TrimSpace(raw.ObjectClassName), objectClass) {
		return rawRDAPObject{}, normalizedRDAPCommon{}, malformedResponseError(fmt.Errorf("unexpected RDAP object class"))
	}
	if !containsFold(raw.RDAPConformance, "rdap_level_0") {
		return rawRDAPObject{}, normalizedRDAPCommon{}, malformedResponseError(fmt.Errorf("missing RDAP level 0 conformance"))
	}

	countryCode := strings.ToUpper(strings.TrimSpace(raw.Country))
	if countryCode != "" && (len(countryCode) != 2 ||
		countryCode[0] < 'A' || countryCode[0] > 'Z' ||
		countryCode[1] < 'A' || countryCode[1] > 'Z') {
		return rawRDAPObject{}, normalizedRDAPCommon{}, malformedResponseError(fmt.Errorf("invalid RDAP country code"))
	}
	events, err := normalizeRDAPEvents(raw.Events)
	if err != nil {
		return rawRDAPObject{}, normalizedRDAPCommon{}, err
	}
	organizations, abuseContacts, entityRedacted, err := normalizeRDAPEntities(raw.Entities)
	if err != nil {
		return rawRDAPObject{}, normalizedRDAPCommon{}, err
	}
	redactions, err := normalizeRDAPRedactions(raw.Redacted)
	if err != nil {
		return rawRDAPObject{}, normalizedRDAPCommon{}, err
	}

	status := normalizeRDAPStrings(raw.Status)
	return raw, normalizedRDAPCommon{
		handle:                  strings.TrimSpace(raw.Handle),
		name:                    strings.TrimSpace(raw.Name),
		recordType:              strings.TrimSpace(raw.Type),
		countryCode:             countryCode,
		status:                  status,
		events:                  events,
		registeredOrganizations: organizations,
		abuseContacts:           abuseContacts,
		redacted:                len(redactions) != 0 || entityRedacted || hasPrivacyStatus(status),
		redactions:              redactions,
	}, nil
}

func normalizeRDAPEvents(values []rawRDAPEvent) ([]RDAPEvent, error) {
	events := make([]RDAPEvent, 0, len(values))
	for _, value := range values {
		action := strings.TrimSpace(value.Action)
		if action == "" {
			return nil, malformedResponseError(fmt.Errorf("RDAP event is missing an action"))
		}
		date, err := time.Parse(time.RFC3339, strings.TrimSpace(value.Date))
		if err != nil {
			return nil, malformedResponseError(fmt.Errorf("invalid RDAP event date"))
		}
		events = append(events, RDAPEvent{Action: action, Date: date})
	}
	return events, nil
}

func normalizeRDAPEntities(values []rawRDAPEntity) ([]string, []RDAPEntityReference, bool, error) {
	return normalizeRDAPEntitiesAtDepth(values, 0)
}

func normalizeRDAPEntitiesAtDepth(values []rawRDAPEntity, depth int) ([]string, []RDAPEntityReference, bool, error) {
	if len(values) == 0 {
		return nil, nil, false, nil
	}
	if depth > maxRDAPEntityDepth {
		return nil, nil, false, malformedResponseError(fmt.Errorf("RDAP entity nesting exceeds the supported depth"))
	}
	var organizations []string
	var abuseContacts []RDAPEntityReference
	redacted := false

	for _, entity := range values {
		if !strings.EqualFold(strings.TrimSpace(entity.ObjectClassName), "entity") {
			return nil, nil, false, malformedResponseError(fmt.Errorf("unexpected RDAP entity object class"))
		}
		roles := normalizeRDAPStrings(entity.Roles)
		status := normalizeRDAPStrings(entity.Status)
		if hasPrivacyStatus(status) {
			redacted = true
		}
		if containsFold(roles, "abuse") {
			handle := strings.TrimSpace(entity.Handle)
			if handle != "" {
				abuseContacts = append(abuseContacts, RDAPEntityReference{
					Handle: handle,
					Roles:  roles,
				})
			}
		}
		if containsFold(roles, "registrant") && len(entity.VCardArray) != 0 {
			entityOrganizations, err := extractRDAPOrganizations(entity.VCardArray)
			if err != nil {
				return nil, nil, false, err
			}
			organizations = append(organizations, entityOrganizations...)
		}
		nestedOrganizations, nestedAbuseContacts, nestedRedacted, err :=
			normalizeRDAPEntitiesAtDepth(entity.Entities, depth+1)
		if err != nil {
			return nil, nil, false, err
		}
		organizations = append(organizations, nestedOrganizations...)
		abuseContacts = append(abuseContacts, nestedAbuseContacts...)
		redacted = redacted || nestedRedacted
	}
	return deduplicateStrings(organizations), deduplicateRDAPEntityReferences(abuseContacts), redacted, nil
}

func deduplicateRDAPEntityReferences(values []RDAPEntityReference) []RDAPEntityReference {
	seen := make(map[string]struct{}, len(values))
	result := make([]RDAPEntityReference, 0, len(values))
	for _, value := range values {
		key := rdapEntityReferenceKey(value)
		if _, found := seen[key]; found {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}

func rdapEntityReferenceKey(value RDAPEntityReference) string {
	var key strings.Builder
	writeRDAPLengthPrefixedString(&key, value.Handle)
	key.WriteByte('#')
	key.WriteString(strconv.Itoa(len(value.Roles)))
	for _, role := range value.Roles {
		writeRDAPLengthPrefixedString(&key, role)
	}
	return key.String()
}

func writeRDAPLengthPrefixedString(key *strings.Builder, value string) {
	key.WriteString(strconv.Itoa(len(value)))
	key.WriteByte(':')
	key.WriteString(value)
}

func extractRDAPOrganizations(raw json.RawMessage) ([]string, error) {
	var card []json.RawMessage
	if err := json.Unmarshal(raw, &card); err != nil || len(card) != 2 {
		return nil, malformedResponseError(fmt.Errorf("invalid RDAP jCard"))
	}
	var cardType string
	if err := json.Unmarshal(card[0], &cardType); err != nil || !strings.EqualFold(cardType, "vcard") {
		return nil, malformedResponseError(fmt.Errorf("invalid RDAP jCard kind"))
	}
	var properties []json.RawMessage
	if err := json.Unmarshal(card[1], &properties); err != nil {
		return nil, malformedResponseError(fmt.Errorf("invalid RDAP jCard properties"))
	}

	var organizations []string
	var entityKind string
	var formattedName string
	for _, rawProperty := range properties {
		var property []json.RawMessage
		if err := json.Unmarshal(rawProperty, &property); err != nil || len(property) == 0 {
			continue
		}
		var name string
		if err := json.Unmarshal(property[0], &name); err != nil {
			continue
		}
		switch strings.ToLower(name) {
		case "kind", "fn":
			if len(property) < 4 {
				continue
			}
			var value string
			if err := json.Unmarshal(property[3], &value); err != nil {
				continue
			}
			if strings.EqualFold(name, "kind") {
				entityKind = strings.TrimSpace(value)
			} else {
				formattedName = strings.TrimSpace(value)
			}
		case "org":
			if len(property) < 4 {
				return nil, malformedResponseError(fmt.Errorf("invalid RDAP jCard organization property"))
			}
			var single string
			if err := json.Unmarshal(property[3], &single); err == nil {
				if single = strings.TrimSpace(single); single != "" {
					organizations = append(organizations, single)
				}
				continue
			}
			var multiple []string
			if err := json.Unmarshal(property[3], &multiple); err != nil {
				return nil, malformedResponseError(fmt.Errorf("invalid RDAP jCard organization"))
			}
			for _, value := range multiple {
				if value = strings.TrimSpace(value); value != "" {
					organizations = append(organizations, value)
				}
			}
		}
	}
	if len(organizations) == 0 && formattedName != "" &&
		(strings.EqualFold(entityKind, "org") || strings.EqualFold(entityKind, "organization")) {
		organizations = append(organizations, formattedName)
	}
	return organizations, nil
}

func normalizeRDAPRedactions(values []rawRDAPRedaction) ([]RDAPRedactionIndicator, error) {
	redactions := make([]RDAPRedactionIndicator, 0, len(values))
	for _, value := range values {
		name := strings.TrimSpace(value.Name.Type)
		if name == "" {
			name = strings.TrimSpace(value.Name.Description)
		}
		if name == "" {
			return nil, malformedResponseError(fmt.Errorf("RDAP redaction is missing its name"))
		}
		reason := strings.TrimSpace(value.Reason.Type)
		if reason == "" {
			reason = strings.TrimSpace(value.Reason.Description)
		}
		redactions = append(redactions, RDAPRedactionIndicator{
			Name:   name,
			Method: strings.TrimSpace(value.Method),
			Reason: reason,
		})
	}
	return redactions, nil
}

func normalizeRDAPStrings(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			normalized = append(normalized, value)
		}
	}
	return normalized
}

func hasPrivacyStatus(status []string) bool {
	for _, value := range status {
		switch strings.ToLower(value) {
		case "redacted", "private", "obscured":
			return true
		}
	}
	return false
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}

func deduplicateStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, found := seen[value]; found {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func compareIP(left, right net.IP) int {
	if left4, right4 := left.To4(), right.To4(); left4 != nil && right4 != nil {
		return bytes.Compare(left4, right4)
	}
	return bytes.Compare(left.To16(), right.To16())
}

func canonicalIP(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.String()
}

func rdapOrigin(value *url.URL) string {
	if value == nil {
		return ""
	}
	return strings.ToLower(value.Scheme) + "://" + strings.ToLower(value.Host)
}
