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
	// DefaultRISWhoisServer is the documented RIPE RIS routing-table query
	// endpoint.
	DefaultRISWhoisServer = "riswhois.ripe.net"
	// DefaultRISWhoisPort is the documented TCP WHOIS service port.
	DefaultRISWhoisPort = 43

	// RISWhoisSource identifies RIPE RISwhois results in provenance and cache
	// keys.
	RISWhoisSource = "ripe-riswhois"
	// RISWhoisProtocolVersion identifies the query protocol used in cache keys.
	RISWhoisProtocolVersion = "riswhois-rpsl-v2"
	// RISWhoisParserVersion identifies the parser contract used in cache keys.
	RISWhoisParserVersion = "riswhois-rpsl-v1"
	// RISWhoisResultSchemaVersion identifies the normalized result shape used
	// in cache keys.
	RISWhoisResultSchemaVersion = "riswhois-route-result-v1"
)

// RISWhoisProvider configures explicit observed-route lookups against RIPE
// RISwhois. It is separate from WhoisServer because RISwhois queries collected
// BGP routing tables and returns RPSL; it is not native PWHOIS or an IRR.
type RISWhoisProvider struct {
	Server  string
	Port    int
	Timeout time.Duration
	// MaxResponseBytes bounds the complete provider response before parsing. A
	// value less than or equal to zero uses DefaultMaxResponseBytes.
	MaxResponseBytes int64
	// Dialer optionally replaces the default TCP dialer. It must honor context
	// cancellation and be safe for concurrent use when the provider is shared.
	Dialer ContextDialer
}

// RISWhoisObservation records a timestamp supplied by RISwhois and the RIS
// peer and route collector associated with that observation.
type RISWhoisObservation struct {
	ObservedAt time.Time `json:"observed_at"`
	Peer       string    `json:"peer"`
	Collector  string    `json:"collector"`
}

// RISWhoisRouteResult is source-specific evidence from the routing tables
// collected by RIPE RIS. It describes observed BGP routing, not allocation,
// ownership, geolocation, or published IRR policy.
//
// RPSLAttributes preserves every response attribute using normalized,
// lower-case names and ordered values. Typed fields are derived from those
// attributes for common use.
type RISWhoisRouteResult struct {
	Query          string              `json:"query"`
	Prefix         string              `json:"prefix"`
	OriginASN      uint32              `json:"origin_asn"`
	Descriptions   []string            `json:"descriptions"`
	FirstObserved  RISWhoisObservation `json:"first_observed"`
	LastObserved   RISWhoisObservation `json:"last_observed"`
	SeenAt         []string            `json:"seen_at"`
	RISPeerCount   uint32              `json:"ris_peer_count"`
	RPSLAttributes map[string][]string `json:"rpsl_attributes"`
	Source         string              `json:"source"`
	Endpoint       string              `json:"endpoint"`
	FetchedAt      time.Time           `json:"fetched_at"`
}

type risWhoisQuery struct {
	normalized string
	wire       string
	match      string
	ip         net.IP
	prefix     *net.IPNet
}

func (provider RISWhoisProvider) configured() RISWhoisProvider {
	if provider.Server == "" {
		provider.Server = DefaultRISWhoisServer
	}
	if provider.Port == 0 {
		provider.Port = DefaultRISWhoisPort
	}
	if provider.Timeout <= 0 {
		provider.Timeout = time.Second * time.Duration(SocketTimeout)
	}
	if provider.MaxResponseBytes <= 0 {
		provider.MaxResponseBytes = DefaultMaxResponseBytes
	}
	return provider
}

// ServerAddressString returns the configured RISwhois TCP endpoint.
func (provider RISWhoisProvider) ServerAddressString() string {
	provider = provider.configured()
	return net.JoinHostPort(provider.Server, strconv.Itoa(provider.Port))
}

func (provider RISWhoisProvider) operationError(operation string, err error) error {
	return &OperationError{
		Operation: operation,
		Server:    provider.ServerAddressString(),
		Err:       err,
	}
}

func (provider RISWhoisProvider) dial(ctx context.Context) (net.Conn, error) {
	if provider.Dialer != nil {
		return provider.Dialer.DialContext(ctx, "tcp", provider.ServerAddressString())
	}

	dialer := &net.Dialer{
		KeepAlive: time.Second * time.Duration(SocketKeepAlive),
	}
	return dialer.DialContext(ctx, "tcp", provider.ServerAddressString())
}

func normalizeRISWhoisQuery(value string) (risWhoisQuery, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return risWhoisQuery{}, invalidInputError("an IP address or prefix is required")
	}

	if ip := net.ParseIP(value); ip != nil {
		canonical := ip.String()
		return risWhoisQuery{
			normalized: canonical,
			// RISwhois gives -M an IP-specific meaning: return only the
			// longest matches. For prefix inputs, -M instead means all more
			// specifics; those use -x below.
			wire:  "-M " + canonical + "\n",
			match: "longest",
			ip:    ip,
		}, nil
	}

	ip, prefix, err := net.ParseCIDR(value)
	if err != nil {
		return risWhoisQuery{}, invalidInputError("query must be an IP address or CIDR prefix")
	}
	if !prefix.IP.Equal(ip) {
		return risWhoisQuery{}, invalidInputError("CIDR query must use its network address")
	}

	canonical := prefix.String()
	return risWhoisQuery{
		normalized: canonical,
		wire:       "-x " + canonical + "\n",
		match:      "exact",
		prefix:     prefix,
	}, nil
}

// CacheKeySpec returns the source-aware key specification for a RISwhois
// lookup. It does not read or write a cache; the calling application still
// selects an explicit CacheCoordinator policy.
func (provider RISWhoisProvider) CacheKeySpec(value string) (CacheKeySpec, error) {
	provider = provider.configured()
	query, err := normalizeRISWhoisQuery(value)
	if err != nil {
		return CacheKeySpec{}, err
	}

	return CacheKeySpec{
		Source:              RISWhoisSource,
		Endpoint:            provider.ServerAddressString(),
		Protocol:            RISWhoisProtocolVersion,
		NormalizedQuery:     query.normalized,
		Options:             map[string]string{"match": query.match, "format": "rpsl"},
		ParserVersion:       RISWhoisParserVersion,
		ResultSchemaVersion: RISWhoisResultSchemaVersion,
	}, nil
}

// LookupRouteContext returns every RISwhois route-origin object matching one
// IP address or prefix. IP addresses request all longest-match origins;
// prefixes request exact matches. Multiple-origin results remain separate.
//
// The call owns its connection, honors the shorter of the context deadline
// and Timeout, applies MaxResponseBytes, and never retries or falls back to
// another provider. A provider may be shared by concurrent callers when its
// fields and custom Dialer are not mutated during use.
func (provider RISWhoisProvider) LookupRouteContext(ctx context.Context, value string) ([]RISWhoisRouteResult, error) {
	const operation = "lookup RISwhois observed route"

	provider = provider.configured()
	if ctx == nil {
		return nil, provider.operationError(operation, invalidInputError("context must not be nil"))
	}
	query, err := normalizeRISWhoisQuery(value)
	if err != nil {
		return nil, provider.operationError(operation, err)
	}

	lookupCtx, cancel := context.WithTimeout(ctx, provider.Timeout)
	defer cancel()

	connection, err := provider.dial(lookupCtx)
	if err != nil {
		return nil, provider.operationError(operation, classifyContextTransportError(lookupCtx, err))
	}
	if connection == nil {
		return nil, provider.operationError(operation, ErrConnection)
	}
	defer connection.Close()

	stopCancellationClose := context.AfterFunc(lookupCtx, func() {
		_ = connection.Close()
	})
	defer stopCancellationClose()

	deadline, _ := lookupCtx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, provider.operationError(operation, classifyContextTransportError(lookupCtx, err))
	}
	written, err := io.WriteString(connection, query.wire)
	if err == nil && written != len(query.wire) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return nil, provider.operationError(operation, classifyContextTransportError(lookupCtx, err))
	}

	rawResponse, err := readBoundedResponse(connection, provider.MaxResponseBytes)
	if err != nil {
		if errors.Is(err, ErrResponseTooLarge) {
			return nil, provider.operationError(operation, err)
		}
		return nil, provider.operationError(operation, classifyContextTransportError(lookupCtx, err))
	}
	if err := lookupCtx.Err(); err != nil {
		return nil, provider.operationError(operation, classifyTransportError(err))
	}

	response := string(rawResponse)
	switch {
	case isRISWhoisRateLimitedResponse(response):
		return nil, provider.operationError(operation, ErrRateLimited)
	case isRISWhoisRejectedResponse(response):
		return nil, provider.operationError(operation, ErrProviderRejected)
	}

	results, err := parseRISWhoisResponse(query, response, provider.ServerAddressString(), time.Now().UTC())
	if err != nil {
		return nil, provider.operationError(operation, err)
	}
	if err := lookupCtx.Err(); err != nil {
		return nil, provider.operationError(operation, classifyTransportError(err))
	}
	return results, nil
}

func isRISWhoisRateLimitedResponse(response string) bool {
	for _, line := range strings.Split(response, "\n") {
		message, ok := risWhoisDiagnostic(line)
		if ok && (strings.Contains(message, "rate limit") ||
			strings.Contains(message, "query limit") ||
			strings.Contains(message, "too many queries")) {
			return true
		}
	}
	return false
}

func isRISWhoisRejectedResponse(response string) bool {
	for _, line := range strings.Split(response, "\n") {
		message, ok := risWhoisDiagnostic(line)
		if !ok || strings.Contains(message, "no entries found") ||
			strings.Contains(message, "no records found") {
			continue
		}
		if strings.Contains(message, "error:") ||
			strings.Contains(message, "access denied") ||
			strings.Contains(message, "invalid query") {
			return true
		}
	}
	return false
}

func risWhoisDiagnostic(line string) (string, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(line))
	if !strings.HasPrefix(trimmed, "%") {
		return "", false
	}
	return strings.TrimSpace(strings.TrimLeft(trimmed, "%")), true
}

func parseRISWhoisResponse(query risWhoisQuery, response, endpoint string, fetchedAt time.Time) ([]RISWhoisRouteResult, error) {
	if strings.TrimSpace(response) == "" {
		return nil, noRecordsError("RISwhois observed-route lookup")
	}

	objects, err := parseRPSLObjects(response)
	if err != nil {
		return nil, malformedResponseError(err)
	}
	if len(objects) == 0 {
		return nil, noRecordsError("RISwhois observed-route lookup")
	}

	results := make([]RISWhoisRouteResult, 0, len(objects))
	seen := make(map[string]struct{}, len(objects))
	for index, attributes := range objects {
		result, err := normalizeRISWhoisRoute(query, attributes, endpoint, fetchedAt)
		if err != nil {
			return nil, malformedResponseError(fmt.Errorf("normalize RISwhois object %d: %w", index+1, err))
		}
		key := fmt.Sprintf("%s|%d", result.Prefix, result.OriginASN)
		if _, found := seen[key]; found {
			return nil, malformedResponseError(fmt.Errorf("RISwhois object %d duplicates an earlier route origin", index+1))
		}
		seen[key] = struct{}{}
		results = append(results, result)
	}
	return results, nil
}

func parseRPSLObjects(response string) ([]map[string][]string, error) {
	objects := make([]map[string][]string, 0)
	current := make(map[string][]string)
	lastAttribute := ""

	finishObject := func() {
		if len(current) != 0 {
			objects = append(objects, current)
			current = make(map[string][]string)
		}
		lastAttribute = ""
	}

	for lineNumber, line := range strings.Split(response, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			finishObject()
			continue
		}
		if strings.HasPrefix(trimmed, "%") {
			continue
		}

		if (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && lastAttribute != "" {
			values := current[lastAttribute]
			values[len(values)-1] += "\n" + trimmed
			current[lastAttribute] = values
			continue
		}

		colon := strings.IndexByte(line, ':')
		if colon < 1 {
			return nil, fmt.Errorf("parse RPSL response line %d: expected attribute", lineNumber+1)
		}

		name := strings.ToLower(strings.TrimSpace(line[:colon]))
		if !validRPSLAttributeName(name) {
			return nil, fmt.Errorf("parse RPSL response line %d: invalid attribute name", lineNumber+1)
		}
		value := strings.TrimSpace(line[colon+1:])
		current[name] = append(current[name], value)
		lastAttribute = name
	}
	finishObject()
	return objects, nil
}

func validRPSLAttributeName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '-' {
			continue
		}
		return false
	}
	return true
}

func normalizeRISWhoisRoute(query risWhoisQuery, attributes map[string][]string, endpoint string, fetchedAt time.Time) (RISWhoisRouteResult, error) {
	routeValues := attributes["route"]
	route6Values := attributes["route6"]
	if len(routeValues)+len(route6Values) != 1 {
		return RISWhoisRouteResult{}, fmt.Errorf("expected exactly one route or route6 attribute")
	}

	routeAttribute := "route"
	prefixValue := ""
	if len(routeValues) == 1 {
		prefixValue = routeValues[0]
	} else {
		routeAttribute = "route6"
		prefixValue = route6Values[0]
	}
	_, prefix, err := net.ParseCIDR(prefixValue)
	if err != nil {
		return RISWhoisRouteResult{}, fmt.Errorf("invalid %s prefix", routeAttribute)
	}
	if (routeAttribute == "route") != (prefix.IP.To4() != nil) {
		return RISWhoisRouteResult{}, fmt.Errorf("%s attribute has the wrong address family", routeAttribute)
	}
	if query.ip != nil && !prefix.Contains(query.ip) {
		return RISWhoisRouteResult{}, fmt.Errorf("route does not contain the queried IP")
	}
	if query.prefix != nil && prefix.String() != query.prefix.String() {
		return RISWhoisRouteResult{}, fmt.Errorf("route is not an exact match for the queried prefix")
	}

	originValues := attributes["origin"]
	if len(originValues) != 1 {
		return RISWhoisRouteResult{}, fmt.Errorf("expected exactly one origin attribute")
	}
	originText := strings.TrimSpace(originValues[0])
	if len(originText) < 3 || !strings.EqualFold(originText[:2], "AS") {
		return RISWhoisRouteResult{}, fmt.Errorf("invalid origin ASN")
	}
	origin, err := strconv.ParseUint(originText[2:], 10, 32)
	if err != nil {
		return RISWhoisRouteResult{}, fmt.Errorf("invalid origin ASN")
	}

	sourceValues := attributes["source"]
	if len(sourceValues) != 1 || !strings.EqualFold(strings.TrimSpace(sourceValues[0]), "RISWHOIS") {
		return RISWhoisRouteResult{}, fmt.Errorf("expected source RISWHOIS")
	}

	firstObserved, err := parseRISWhoisOptionalObservation(attributes["lastupd-frst"], "lastupd-frst")
	if err != nil {
		return RISWhoisRouteResult{}, err
	}
	lastObserved, err := parseRISWhoisOptionalObservation(attributes["lastupd-last"], "lastupd-last")
	if err != nil {
		return RISWhoisRouteResult{}, err
	}

	seenAt, err := parseRISWhoisSeenAt(attributes["seen-at"])
	if err != nil {
		return RISWhoisRouteResult{}, err
	}
	peerCount, err := parseRISWhoisOptionalUint32(attributes["num-rispeers"], "num-rispeers")
	if err != nil {
		return RISWhoisRouteResult{}, err
	}

	return RISWhoisRouteResult{
		Query:          query.normalized,
		Prefix:         prefix.String(),
		OriginASN:      uint32(origin),
		Descriptions:   append([]string(nil), attributes["descr"]...),
		FirstObserved:  firstObserved,
		LastObserved:   lastObserved,
		SeenAt:         seenAt,
		RISPeerCount:   peerCount,
		RPSLAttributes: copyRPSLAttributes(attributes),
		Source:         RISWhoisSource,
		Endpoint:       endpoint,
		FetchedAt:      fetchedAt,
	}, nil
}

func parseRISWhoisOptionalObservation(values []string, field string) (RISWhoisObservation, error) {
	if len(values) == 0 {
		return RISWhoisObservation{}, nil
	}
	if len(values) != 1 {
		return RISWhoisObservation{}, fmt.Errorf("expected at most one %s attribute", field)
	}

	parts := strings.Fields(values[0])
	if len(parts) != 3 {
		return RISWhoisObservation{}, fmt.Errorf("invalid %s observation", field)
	}
	observedAt, err := time.Parse("2006-01-02 15:04Z", parts[0]+" "+parts[1])
	if err != nil {
		return RISWhoisObservation{}, fmt.Errorf("invalid %s timestamp", field)
	}

	at := strings.LastIndexByte(parts[2], '@')
	if at < 1 || at == len(parts[2])-1 {
		return RISWhoisObservation{}, fmt.Errorf("invalid %s peer and collector", field)
	}
	peer := parts[2][:at]
	collector := parts[2][at+1:]
	if net.ParseIP(peer) == nil || strings.ContainsAny(collector, " \t,\r\n") {
		return RISWhoisObservation{}, fmt.Errorf("invalid %s peer and collector", field)
	}

	return RISWhoisObservation{
		ObservedAt: observedAt,
		Peer:       peer,
		Collector:  collector,
	}, nil
}

func parseRISWhoisSeenAt(values []string) ([]string, error) {
	var collectors []string
	for _, value := range values {
		for _, collector := range strings.Split(value, ",") {
			collector = strings.TrimSpace(collector)
			if collector == "" || strings.ContainsAny(collector, " \t\r\n") {
				return nil, fmt.Errorf("invalid seen-at collector")
			}
			collectors = append(collectors, collector)
		}
	}
	return collectors, nil
}

func parseRISWhoisOptionalUint32(values []string, field string) (uint32, error) {
	if len(values) == 0 {
		return 0, nil
	}
	if len(values) != 1 {
		return 0, fmt.Errorf("expected at most one %s attribute", field)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(values[0]), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid %s value", field)
	}
	return uint32(value), nil
}

func copyRPSLAttributes(attributes map[string][]string) map[string][]string {
	copied := make(map[string][]string, len(attributes))
	for name, values := range attributes {
		copied[name] = append([]string(nil), values...)
	}
	return copied
}
