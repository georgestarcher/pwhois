package pwhois

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	// IRRSource identifies published Internet Routing Registry policy results
	// in provenance and cache keys.
	IRRSource = "irr-rpsl"
	// IRRProtocolVersion identifies the supported IRRd RIPE-style exact-route
	// query contract.
	IRRProtocolVersion = "irrd-ripe-exact-route-v1"
	// IRRParserVersion identifies the normalized RPSL parser contract.
	IRRParserVersion = "irr-rpsl-v1"
	// IRRResultSchemaVersion identifies the normalized published-policy result
	// shape.
	IRRResultSchemaVersion = "irr-route-policy-result-v1"

	// IRRQueryModeExactRoute identifies the only supported IRR query mode.
	IRRQueryModeExactRoute = "ripe-exact-route"
)

// IRREndpoint identifies one explicitly supported IRRd endpoint. It is not a
// hostname escape hatch: values outside the allowlist are rejected before any
// connection is opened.
type IRREndpoint string

const (
	// IRREndpointRADb queries the Merit RADb IRRd service.
	IRREndpointRADb IRREndpoint = "radb"
	// IRREndpointARIN queries the ARIN IRR service.
	IRREndpointARIN IRREndpoint = "arin"
	// IRREndpointNTT queries the NTT IRR service.
	IRREndpointNTT IRREndpoint = "ntt"
)

type irrEndpointConfig struct {
	id      IRREndpoint
	address string
}

var irrEndpointAllowlist = map[IRREndpoint]string{
	IRREndpointRADb: "whois.radb.net:43",
	IRREndpointARIN: "rr.arin.net:43",
	IRREndpointNTT:  "rr.ntt.net:43",
}

// IRRProvider configures exact route/route6 lookups against one allowlisted
// IRRd endpoint. The zero value selects RADb. It is separate from
// WhoisServer and RISWhoisProvider because it returns published routing
// policy, not registration data or observed BGP routing.
type IRRProvider struct {
	Endpoint IRREndpoint
	Timeout  time.Duration
	// MaxResponseBytes bounds the complete provider response before parsing. A
	// value less than or equal to zero uses DefaultMaxResponseBytes.
	MaxResponseBytes int64
	// Dialer optionally replaces the default TCP dialer. It must honor context
	// cancellation and be safe for concurrent use when the provider is shared.
	// The allowlisted destination is still passed to it.
	Dialer ContextDialer
}

// IRRRoutePolicyResult is a privacy-minimized route or route6 object published
// in an Internet Routing Registry. It describes declared routing policy, not
// live BGP propagation, resource ownership, geolocation, or sender identity.
type IRRRoutePolicyResult struct {
	Query        string      `json:"query"`
	Prefix       string      `json:"prefix"`
	OriginASN    uint32      `json:"origin_asn"`
	Descriptions []string    `json:"descriptions"`
	Maintainers  []string    `json:"maintainers"`
	MemberOf     []string    `json:"member_of"`
	RPKIState    string      `json:"rpki_state"`
	RPSLSource   string      `json:"rpsl_source"`
	Source       string      `json:"source"`
	EndpointID   IRREndpoint `json:"endpoint_id"`
	Endpoint     string      `json:"endpoint"`
	QueryMode    string      `json:"query_mode"`
	FetchedAt    time.Time   `json:"fetched_at"`
}

type irrQuery struct {
	normalized string
	wire       string
	prefix     *net.IPNet
}

func (provider IRRProvider) configured() (IRRProvider, irrEndpointConfig, error) {
	if provider.Endpoint == "" {
		provider.Endpoint = IRREndpointRADb
	}
	address, ok := irrEndpointAllowlist[provider.Endpoint]
	if !ok {
		return IRRProvider{}, irrEndpointConfig{}, invalidInputError("unsupported IRR endpoint")
	}
	if provider.Timeout <= 0 {
		provider.Timeout = time.Second * time.Duration(SocketTimeout)
	}
	if provider.MaxResponseBytes <= 0 {
		provider.MaxResponseBytes = DefaultMaxResponseBytes
	}
	return provider, irrEndpointConfig{id: provider.Endpoint, address: address}, nil
}

// EndpointAddressString returns the allowlisted TCP endpoint selected by the
// provider. An unsupported endpoint returns ErrInvalidInput.
func (provider IRRProvider) EndpointAddressString() (string, error) {
	_, endpoint, err := provider.configured()
	if err != nil {
		return "", err
	}
	return endpoint.address, nil
}

func (provider IRRProvider) operationError(operation, endpoint string, err error) error {
	return &OperationError{
		Operation: operation,
		Server:    endpoint,
		Err:       err,
	}
}

func (provider IRRProvider) dial(ctx context.Context, endpoint string) (net.Conn, error) {
	if provider.Dialer != nil {
		return provider.Dialer.DialContext(ctx, "tcp", endpoint)
	}
	dialer := &net.Dialer{
		KeepAlive: time.Second * time.Duration(SocketKeepAlive),
	}
	return dialer.DialContext(ctx, "tcp", endpoint)
}

func normalizeIRRQuery(value string) (irrQuery, error) {
	value = strings.TrimSpace(value)
	ip, prefix, err := net.ParseCIDR(value)
	if err != nil {
		return irrQuery{}, invalidInputError("IRR query must be a CIDR prefix")
	}
	if !prefix.IP.Equal(ip) {
		return irrQuery{}, invalidInputError("CIDR query must use its network address")
	}

	canonical := prefix.String()
	return irrQuery{
		normalized: canonical,
		wire:       "-T route,route6 -x " + canonical + "\n",
		prefix:     prefix,
	}, nil
}

// CacheKeySpec returns the source-aware key specification for an exact IRR
// route-policy lookup. It does not read or write a cache; the calling
// application still selects an explicit CacheCoordinator policy.
func (provider IRRProvider) CacheKeySpec(value string) (CacheKeySpec, error) {
	provider, endpoint, err := provider.configured()
	if err != nil {
		return CacheKeySpec{}, err
	}
	query, err := normalizeIRRQuery(value)
	if err != nil {
		return CacheKeySpec{}, err
	}

	return CacheKeySpec{
		Source:          IRRSource,
		Endpoint:        endpoint.address,
		Protocol:        IRRProtocolVersion,
		NormalizedQuery: query.normalized,
		Options: map[string]string{
			"endpoint_id":  string(provider.Endpoint),
			"match":        "exact",
			"object_types": "route,route6",
			"query_mode":   IRRQueryModeExactRoute,
		},
		ParserVersion:       IRRParserVersion,
		ResultSchemaVersion: IRRResultSchemaVersion,
	}, nil
}

// LookupRoutePolicyContext returns every exact route or route6 object
// published for one canonical CIDR prefix at the selected allowlisted IRRd
// endpoint. Multiple origins remain separate.
//
// The call owns its connection, honors the shorter of the context deadline
// and Timeout, applies MaxResponseBytes, and never retries or falls back to
// another provider. A provider may be shared by concurrent callers when its
// fields and custom Dialer are not mutated during use.
func (provider IRRProvider) LookupRoutePolicyContext(ctx context.Context, value string) ([]IRRRoutePolicyResult, error) {
	const operation = "lookup IRR route policy"

	provider, endpoint, err := provider.configured()
	if err != nil {
		return nil, provider.operationError(operation, "", err)
	}
	if ctx == nil {
		return nil, provider.operationError(operation, endpoint.address, invalidInputError("context must not be nil"))
	}
	query, err := normalizeIRRQuery(value)
	if err != nil {
		return nil, provider.operationError(operation, endpoint.address, err)
	}

	lookupCtx, cancel := context.WithTimeout(ctx, provider.Timeout)
	defer cancel()

	connection, err := provider.dial(lookupCtx, endpoint.address)
	if err != nil {
		return nil, provider.operationError(operation, endpoint.address, classifyContextTransportError(lookupCtx, err))
	}
	if connection == nil {
		return nil, provider.operationError(operation, endpoint.address, ErrConnection)
	}
	defer connection.Close()

	stopCancellationClose := context.AfterFunc(lookupCtx, func() {
		_ = connection.Close()
	})
	defer stopCancellationClose()

	deadline, _ := lookupCtx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, provider.operationError(operation, endpoint.address, classifyContextTransportError(lookupCtx, err))
	}
	written, err := io.WriteString(connection, query.wire)
	if err == nil && written != len(query.wire) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return nil, provider.operationError(operation, endpoint.address, classifyContextTransportError(lookupCtx, err))
	}

	rawResponse, err := readBoundedResponse(connection, provider.MaxResponseBytes)
	if err != nil {
		if errors.Is(err, ErrResponseTooLarge) {
			return nil, provider.operationError(operation, endpoint.address, err)
		}
		return nil, provider.operationError(operation, endpoint.address, classifyContextTransportError(lookupCtx, err))
	}
	if err := lookupCtx.Err(); err != nil {
		return nil, provider.operationError(operation, endpoint.address, classifyTransportError(err))
	}

	response := string(rawResponse)
	switch {
	case isIRRRateLimitedResponse(response):
		return nil, provider.operationError(operation, endpoint.address, ErrRateLimited)
	case isIRRRejectedResponse(response):
		return nil, provider.operationError(operation, endpoint.address, ErrProviderRejected)
	}

	results, err := parseIRRResponse(query, response, endpoint, time.Now().UTC())
	if err != nil {
		return nil, provider.operationError(operation, endpoint.address, err)
	}
	if err := lookupCtx.Err(); err != nil {
		return nil, provider.operationError(operation, endpoint.address, classifyTransportError(err))
	}
	return results, nil
}

func isIRRRateLimitedResponse(response string) bool {
	for _, line := range strings.Split(response, "\n") {
		message, ok := irrDiagnostic(line)
		if ok && (strings.Contains(message, "rate limit") ||
			strings.Contains(message, "query limit") ||
			strings.Contains(message, "too many queries")) {
			return true
		}
	}
	return false
}

func isIRRRejectedResponse(response string) bool {
	for _, line := range strings.Split(response, "\n") {
		message, ok := irrDiagnostic(line)
		if !ok || strings.Contains(message, "no entries found") ||
			strings.Contains(message, "no records found") {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "%%") ||
			strings.Contains(message, "error:") ||
			strings.Contains(message, "access denied") ||
			strings.Contains(message, "invalid query") {
			return true
		}
	}
	return false
}

func irrDiagnostic(line string) (string, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(line))
	if !strings.HasPrefix(trimmed, "%") {
		return "", false
	}
	return strings.TrimSpace(strings.TrimLeft(trimmed, "%")), true
}

func parseIRRResponse(query irrQuery, response string, endpoint irrEndpointConfig, fetchedAt time.Time) ([]IRRRoutePolicyResult, error) {
	if strings.TrimSpace(response) == "" {
		return nil, noRecordsError("IRR route-policy lookup")
	}

	objects, err := parseRPSLObjects(response)
	if err != nil {
		return nil, malformedResponseError(err)
	}
	if len(objects) == 0 {
		return nil, noRecordsError("IRR route-policy lookup")
	}

	results := make([]IRRRoutePolicyResult, 0, len(objects))
	seen := make(map[string]struct{}, len(objects))
	for index, attributes := range objects {
		result, err := normalizeIRRRoutePolicy(query, attributes, endpoint, fetchedAt)
		if err != nil {
			return nil, malformedResponseError(fmt.Errorf("normalize IRR object %d: %w", index+1, err))
		}
		key := fmt.Sprintf("%s|%d|%s", result.Prefix, result.OriginASN, strings.ToUpper(result.RPSLSource))
		if _, found := seen[key]; found {
			return nil, malformedResponseError(fmt.Errorf("IRR object %d duplicates an earlier route policy", index+1))
		}
		seen[key] = struct{}{}
		results = append(results, result)
	}
	return results, nil
}

func normalizeIRRRoutePolicy(query irrQuery, attributes map[string][]string, endpoint irrEndpointConfig, fetchedAt time.Time) (IRRRoutePolicyResult, error) {
	routeValues := attributes["route"]
	route6Values := attributes["route6"]
	if len(routeValues)+len(route6Values) != 1 {
		return IRRRoutePolicyResult{}, fmt.Errorf("expected exactly one route or route6 attribute")
	}

	routeAttribute := "route"
	prefixValue := ""
	if len(routeValues) == 1 {
		prefixValue = routeValues[0]
	} else {
		routeAttribute = "route6"
		prefixValue = route6Values[0]
	}
	parsedIP, prefix, err := net.ParseCIDR(strings.TrimSpace(prefixValue))
	if err != nil || !prefix.IP.Equal(parsedIP) {
		return IRRRoutePolicyResult{}, fmt.Errorf("invalid %s prefix", routeAttribute)
	}
	if (routeAttribute == "route") != (prefix.IP.To4() != nil) {
		return IRRRoutePolicyResult{}, fmt.Errorf("%s attribute has the wrong address family", routeAttribute)
	}
	if prefix.String() != query.prefix.String() {
		return IRRRoutePolicyResult{}, fmt.Errorf("route is not an exact match for the queried prefix")
	}

	originValues := attributes["origin"]
	if len(originValues) != 1 {
		return IRRRoutePolicyResult{}, fmt.Errorf("expected exactly one origin attribute")
	}
	originText := strings.TrimSpace(originValues[0])
	if len(originText) < 3 || !strings.EqualFold(originText[:2], "AS") {
		return IRRRoutePolicyResult{}, fmt.Errorf("invalid origin ASN")
	}
	origin, err := strconv.ParseUint(originText[2:], 10, 32)
	if err != nil {
		return IRRRoutePolicyResult{}, fmt.Errorf("invalid origin ASN")
	}

	sourceValues := attributes["source"]
	if len(sourceValues) != 1 {
		return IRRRoutePolicyResult{}, fmt.Errorf("expected exactly one source attribute")
	}
	rpslSource, err := parseIRRIdentifier(sourceValues[0], "source")
	if err != nil {
		return IRRRoutePolicyResult{}, err
	}

	descriptions, err := parseIRRDescriptions(attributes["descr"])
	if err != nil {
		return IRRRoutePolicyResult{}, err
	}
	maintainers, err := parseIRRIdentifierList(attributes["mnt-by"], "mnt-by")
	if err != nil {
		return IRRRoutePolicyResult{}, err
	}
	memberOf, err := parseIRRIdentifierList(attributes["member-of"], "member-of")
	if err != nil {
		return IRRRoutePolicyResult{}, err
	}
	rpkiState, err := parseIRRRPKIState(attributes["rpki-ov-state"])
	if err != nil {
		return IRRRoutePolicyResult{}, err
	}

	return IRRRoutePolicyResult{
		Query:        query.normalized,
		Prefix:       prefix.String(),
		OriginASN:    uint32(origin),
		Descriptions: descriptions,
		Maintainers:  maintainers,
		MemberOf:     memberOf,
		RPKIState:    rpkiState,
		RPSLSource:   rpslSource,
		Source:       IRRSource,
		EndpointID:   endpoint.id,
		Endpoint:     endpoint.address,
		QueryMode:    IRRQueryModeExactRoute,
		FetchedAt:    fetchedAt,
	}, nil
}

func parseIRRDescriptions(values []string) ([]string, error) {
	descriptions := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || !validIRRDescription(value) {
			return nil, fmt.Errorf("invalid descr attribute")
		}
		descriptions = append(descriptions, value)
	}
	return descriptions, nil
}

func validIRRDescription(value string) bool {
	for _, character := range value {
		if character == '\n' || character == '\t' {
			continue
		}
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func parseIRRIdentifierList(values []string, field string) ([]string, error) {
	identifiers := make([]string, 0, len(values))
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			identifier, err := parseIRRIdentifier(item, field)
			if err != nil {
				return nil, err
			}
			identifiers = append(identifiers, identifier)
		}
	}
	return identifiers, nil
}

func parseIRRIdentifier(value, field string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("invalid %s attribute", field)
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return "", fmt.Errorf("invalid %s attribute", field)
		}
	}
	return value, nil
}

func parseIRRRPKIState(values []string) (string, error) {
	if len(values) == 0 {
		return "", nil
	}
	if len(values) != 1 {
		return "", fmt.Errorf("expected at most one rpki-ov-state attribute")
	}
	value, _, _ := strings.Cut(values[0], "#")
	fields := strings.Fields(value)
	if len(fields) != 1 {
		return "", fmt.Errorf("invalid rpki-ov-state attribute")
	}
	state := strings.ToLower(fields[0])
	for _, character := range state {
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' {
			continue
		}
		return "", fmt.Errorf("invalid rpki-ov-state attribute")
	}
	return strings.ReplaceAll(state, "-", "_"), nil
}
