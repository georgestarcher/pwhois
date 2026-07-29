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
	// DefaultTeamCymruServer is the documented Team Cymru origin-ASN mapping
	// endpoint.
	DefaultTeamCymruServer = "whois.cymru.com"
	// DefaultTeamCymruPort is the documented TCP WHOIS service port.
	DefaultTeamCymruPort = 43
	// DefaultTeamCymruBatchMaxSize keeps one request below the provider's
	// guidance to submit no more than a few thousand addresses per bulk run.
	DefaultTeamCymruBatchMaxSize = 1000

	// TeamCymruSource identifies Team Cymru results in provenance and cache
	// keys.
	TeamCymruSource = "team-cymru"
	// TeamCymruProtocolVersion identifies the request protocol used in cache
	// keys.
	TeamCymruProtocolVersion = "cymru-whois-v1"
	// TeamCymruParserVersion identifies the parser contract used in cache keys.
	TeamCymruParserVersion = "cymru-ip-v1"
	// TeamCymruResultSchemaVersion identifies the normalized result shape used
	// in cache keys.
	TeamCymruResultSchemaVersion = "cymru-ip-result-v1"
)

// TeamCymruProvider configures explicit Team Cymru IP-to-origin-ASN lookups.
// It is separate from WhoisServer because Team Cymru's protocol and result
// format are not native PWHOIS.
type TeamCymruProvider struct {
	Server       string
	Port         int
	BatchMaxSize int
	Timeout      time.Duration
	// MaxResponseBytes bounds the complete provider response before parsing. A
	// value less than or equal to zero uses DefaultMaxResponseBytes.
	MaxResponseBytes int64
	// Dialer optionally replaces the default TCP dialer. It must honor context
	// cancellation and be safe for concurrent use when the provider is shared.
	Dialer ContextDialer
}

// TeamCymruIPResult is source-specific BGP-origin enrichment for one queried
// IP address. CountryCode and Registry describe RIR allocation data and must
// not be treated as IP geolocation.
type TeamCymruIPResult struct {
	IP            string    `json:"ip"`
	Found         bool      `json:"found"`
	OriginASNs    []uint32  `json:"origin_asns"`
	Prefix        string    `json:"prefix"`
	CountryCode   string    `json:"country_code"`
	Registry      string    `json:"registry"`
	AllocatedDate time.Time `json:"allocated_date"`
	ASName        string    `json:"as_name"`
	Source        string    `json:"source"`
	Endpoint      string    `json:"endpoint"`
	FetchedAt     time.Time `json:"fetched_at"`
}

func (provider TeamCymruProvider) configured() TeamCymruProvider {
	if provider.Server == "" {
		provider.Server = DefaultTeamCymruServer
	}
	if provider.Port == 0 {
		provider.Port = DefaultTeamCymruPort
	}
	if provider.BatchMaxSize <= 0 {
		provider.BatchMaxSize = DefaultTeamCymruBatchMaxSize
	}
	if provider.Timeout <= 0 {
		provider.Timeout = time.Second * time.Duration(SocketTimeout)
	}
	if provider.MaxResponseBytes <= 0 {
		provider.MaxResponseBytes = DefaultMaxResponseBytes
	}
	return provider
}

// ServerAddressString returns the configured Team Cymru TCP endpoint.
func (provider TeamCymruProvider) ServerAddressString() string {
	provider = provider.configured()
	return net.JoinHostPort(provider.Server, strconv.Itoa(provider.Port))
}

func (provider TeamCymruProvider) operationError(operation string, err error) error {
	return &OperationError{
		Operation: operation,
		Server:    provider.ServerAddressString(),
		Err:       err,
	}
}

func (provider TeamCymruProvider) dial(ctx context.Context) (net.Conn, error) {
	if provider.Dialer != nil {
		return provider.Dialer.DialContext(ctx, "tcp", provider.ServerAddressString())
	}

	dialer := &net.Dialer{
		KeepAlive: time.Second * time.Duration(SocketKeepAlive),
	}
	return dialer.DialContext(ctx, "tcp", provider.ServerAddressString())
}

func normalizeTeamCymruIPs(values []string, batchMaxSize int) ([]string, error) {
	if len(values) == 0 {
		return nil, invalidInputError("at least one IP address is required")
	}

	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil {
			return nil, invalidInputError(fmt.Sprintf("invalid IP address at position %d", index+1))
		}
		canonical := ip.String()
		if _, found := seen[canonical]; found {
			continue
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}

	if len(normalized) > batchMaxSize {
		return nil, invalidInputError(fmt.Sprintf("Team Cymru IP batch exceeds maximum of %d addresses", batchMaxSize))
	}
	return normalized, nil
}

func formatTeamCymruIPQuery(values []string) string {
	var query strings.Builder
	query.WriteString("begin\nverbose\nnoheader\n")
	for _, value := range values {
		query.WriteString(value)
		query.WriteByte('\n')
	}
	query.WriteString("end\n")
	return query.String()
}

// CacheKeySpec returns the source-aware key specification for a Team Cymru
// lookup. It does not read or write a cache; the calling application still
// selects an explicit CacheCoordinator policy.
func (provider TeamCymruProvider) CacheKeySpec(values []string) (CacheKeySpec, error) {
	provider = provider.configured()
	normalized, err := normalizeTeamCymruIPs(values, provider.BatchMaxSize)
	if err != nil {
		return CacheKeySpec{}, err
	}

	return CacheKeySpec{
		Source:              TeamCymruSource,
		Endpoint:            provider.ServerAddressString(),
		Protocol:            TeamCymruProtocolVersion,
		NormalizedQuery:     strings.Join(normalized, "\n"),
		Options:             map[string]string{"mode": "bulk-verbose", "header": "disabled"},
		ParserVersion:       TeamCymruParserVersion,
		ResultSchemaVersion: TeamCymruResultSchemaVersion,
	}, nil
}

// LookupIPContext maps one or more IP addresses to Team Cymru BGP-origin data.
// One TCP bulk request is used even for a single address so grouped callers do
// not generate repeated individual WHOIS queries. Inputs are validated,
// canonicalized, and deduplicated before the request.
//
// The call owns its connection, honors the shorter of the context deadline
// and Timeout, applies MaxResponseBytes, and never retries or falls back to
// native PWHOIS. A provider may be shared by concurrent callers when its
// fields and custom Dialer are not mutated during use.
func (provider TeamCymruProvider) LookupIPContext(ctx context.Context, values []string) ([]TeamCymruIPResult, error) {
	const operation = "lookup Team Cymru IP-to-ASN"

	provider = provider.configured()
	if ctx == nil {
		return nil, provider.operationError(operation, invalidInputError("context must not be nil"))
	}
	normalized, err := normalizeTeamCymruIPs(values, provider.BatchMaxSize)
	if err != nil {
		return nil, provider.operationError(operation, err)
	}
	query := formatTeamCymruIPQuery(normalized)

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
	written, err := io.WriteString(connection, query)
	if err == nil && written != len(query) {
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
	case isTeamCymruRateLimitedResponse(response):
		return nil, provider.operationError(operation, ErrRateLimited)
	case isTeamCymruRejectedResponse(response):
		return nil, provider.operationError(operation, ErrProviderRejected)
	}

	results, err := parseTeamCymruIPResponse(normalized, response, provider.ServerAddressString(), time.Now().UTC())
	if err != nil {
		return nil, provider.operationError(operation, err)
	}
	if err := lookupCtx.Err(); err != nil {
		return nil, provider.operationError(operation, classifyTransportError(err))
	}
	return results, nil
}

func isTeamCymruRateLimitedResponse(response string) bool {
	lower := strings.ToLower(response)
	return strings.Contains(lower, "query limit exceeded") ||
		strings.Contains(lower, "rate limit") ||
		strings.Contains(lower, "too many queries")
}

func isTeamCymruRejectedResponse(response string) bool {
	for _, line := range strings.Split(response, "\n") {
		trimmed := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(trimmed, "error:") ||
			strings.HasPrefix(trimmed, "invalid query") {
			return true
		}
	}
	return false
}

func parseTeamCymruIPResponse(requested []string, response, endpoint string, fetchedAt time.Time) ([]TeamCymruIPResult, error) {
	if strings.TrimSpace(response) == "" {
		return nil, noRecordsError("Team Cymru IP-to-ASN lookup")
	}

	requestedSet := make(map[string]struct{}, len(requested))
	seen := make(map[string]bool, len(requested))
	seenFound := make(map[string]bool, len(requested))
	for _, value := range requested {
		requestedSet[value] = struct{}{}
	}

	results := make([]TeamCymruIPResult, 0, len(requested))
	foundCount := 0
	for lineNumber, line := range strings.Split(response, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(strings.ToLower(trimmed), "bulk mode;") {
			continue
		}
		if isTeamCymruHeader(trimmed) {
			continue
		}

		result, err := parseTeamCymruIPLine(trimmed, endpoint, fetchedAt)
		if err != nil {
			return nil, malformedResponseError(fmt.Errorf("parse Team Cymru response line %d: %w", lineNumber+1, err))
		}
		if _, expected := requestedSet[result.IP]; !expected {
			return nil, malformedResponseError(fmt.Errorf("Team Cymru response line %d returned unrequested IP", lineNumber+1))
		}
		if previousFound, duplicate := seenFound[result.IP]; duplicate && previousFound != result.Found {
			return nil, malformedResponseError(fmt.Errorf("Team Cymru response line %d conflicts with an earlier result", lineNumber+1))
		}
		seen[result.IP] = true
		seenFound[result.IP] = result.Found
		if result.Found {
			foundCount++
		}
		results = append(results, result)
	}

	if len(results) == 0 {
		return nil, noRecordsError("Team Cymru IP-to-ASN lookup")
	}
	for _, value := range requested {
		if !seen[value] {
			return nil, malformedResponseError(fmt.Errorf("Team Cymru response omitted a requested IP"))
		}
	}
	if foundCount == 0 {
		return nil, noRecordsError("Team Cymru IP-to-ASN lookup")
	}
	return results, nil
}

func isTeamCymruHeader(line string) bool {
	fields := strings.Split(line, "|")
	if len(fields) < 2 {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(fields[0]), "AS") &&
		strings.EqualFold(strings.TrimSpace(fields[1]), "IP")
}

func parseTeamCymruIPLine(line, endpoint string, fetchedAt time.Time) (TeamCymruIPResult, error) {
	fields := strings.SplitN(line, "|", 7)
	if len(fields) < 7 {
		return TeamCymruIPResult{}, fmt.Errorf("expected at least 7 pipe-delimited fields")
	}
	for index := 0; index < 6; index++ {
		fields[index] = strings.TrimSpace(fields[index])
	}

	ip := net.ParseIP(fields[1])
	if ip == nil {
		return TeamCymruIPResult{}, fmt.Errorf("invalid IP field")
	}

	result := TeamCymruIPResult{
		IP:        ip.String(),
		Source:    TeamCymruSource,
		Endpoint:  endpoint,
		FetchedAt: fetchedAt,
	}

	asnField := fields[0]
	prefixField := fields[2]
	if strings.EqualFold(asnField, "NA") && strings.EqualFold(prefixField, "NA") {
		return result, nil
	}
	if strings.EqualFold(asnField, "NA") || strings.EqualFold(prefixField, "NA") {
		return TeamCymruIPResult{}, fmt.Errorf("inconsistent no-record fields")
	}

	for _, asnText := range strings.Fields(asnField) {
		asn, err := strconv.ParseUint(asnText, 10, 32)
		if err != nil {
			return TeamCymruIPResult{}, fmt.Errorf("invalid origin ASN")
		}
		result.OriginASNs = append(result.OriginASNs, uint32(asn))
	}
	if len(result.OriginASNs) == 0 {
		return TeamCymruIPResult{}, fmt.Errorf("missing origin ASN")
	}
	if _, _, err := net.ParseCIDR(prefixField); err != nil {
		return TeamCymruIPResult{}, fmt.Errorf("invalid BGP prefix")
	}

	result.Found = true
	result.Prefix = prefixField
	result.CountryCode = normalizeTeamCymruOptionalField(fields[3])
	result.Registry = strings.ToLower(normalizeTeamCymruOptionalField(fields[4]))

	allocated := normalizeTeamCymruOptionalField(fields[5])
	if allocated != "" {
		parsed, err := time.Parse("2006-01-02", allocated)
		if err != nil {
			return TeamCymruIPResult{}, fmt.Errorf("invalid allocation date")
		}
		result.AllocatedDate = parsed
	}

	description := strings.TrimSpace(fields[6])
	// A verbose response may retain an empty Info column even when the request
	// supplied no per-IP metadata. Remove only that empty leading column while
	// preserving any later pipe delimiters in the AS description.
	if strings.HasPrefix(description, "|") {
		description = strings.TrimSpace(strings.TrimPrefix(description, "|"))
	}
	result.ASName = normalizeTeamCymruOptionalField(description)
	return result, nil
}

func normalizeTeamCymruOptionalField(value string) string {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "NA") {
		return ""
	}
	return value
}
