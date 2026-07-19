package pwhois

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Timeout for network socket in seconds to pwhois server
const SocketTimeout int = 5

// Time for network socket keep alive in seconds
const SocketKeepAlive int = 30

// App Name for this module similar to HTTP User Agent in use
const AppName string = "GO pwhois Module"

// Query string for ip batch query start
const BatchStart string = "begin\n"

// Query string for ip batch query end
const BatchEnd string = "end\n"

// DefaultMaxResponseBytes is the maximum response size used when
// WhoisServer.MaxResponseBytes is zero. Eight MiB provides more than 16 KiB
// per result in the documented 500-address IP batch while bounding memory
// consumed by an untrusted PWHOIS server.
const DefaultMaxResponseBytes int64 = 8 * 1024 * 1024

const responseReadChunkSize = 32 * 1024

// Stable error classes returned by this package. Use errors.Is to branch on a
// class and errors.As to retrieve OperationError or ResponseTooLargeError
// metadata without comparing error strings.
var (
	ErrInvalidInput      = errors.New("pwhois invalid input")
	ErrConnection        = errors.New("pwhois connection failure")
	ErrTimeout           = errors.New("pwhois lookup timed out")
	ErrCanceled          = errors.New("pwhois lookup canceled")
	ErrRateLimited       = errors.New("pwhois server rate limit exceeded")
	ErrResponseTooLarge  = errors.New("pwhois response exceeds maximum size")
	ErrMalformedResponse = errors.New("pwhois malformed response")
	ErrNoRecords         = errors.New("pwhois no records returned")
)

// OperationError adds lookup operation and server context while preserving the
// stable error class and the underlying cause through errors.Is and errors.As.
type OperationError struct {
	// Operation identifies the attempted action, such as "lookup IP" or
	// "connect".
	Operation string
	// Server is the configured PWHOIS endpoint when one was supplied.
	Server string
	// Err is the classified error and optional underlying cause.
	Err error
}

func (err *OperationError) Error() string {
	if err.Server == "" {
		return fmt.Sprintf("pwhois %s: %v", err.Operation, err.Err)
	}
	return fmt.Sprintf("pwhois %s against %s: %v", err.Operation, err.Server, err.Err)
}

func (err *OperationError) Unwrap() error {
	return err.Err
}

// ResponseTooLargeError reports the configured response-size limit without
// retaining or exposing remote response content.
type ResponseTooLargeError struct {
	// Limit is the configured maximum response size in bytes.
	Limit int64
}

func (err *ResponseTooLargeError) Error() string {
	return fmt.Sprintf("%s: limit %d bytes", ErrResponseTooLarge, err.Limit)
}

func (err *ResponseTooLargeError) Unwrap() error {
	return ErrResponseTooLarge
}

func invalidInputError(description string) error {
	return fmt.Errorf("%w: %s", ErrInvalidInput, description)
}

func noRecordsError(resource string) error {
	return fmt.Errorf("%w: %s", ErrNoRecords, resource)
}

func malformedResponseError(err error) error {
	if errors.Is(err, ErrNoRecords) || errors.Is(err, ErrMalformedResponse) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrMalformedResponse, err)
}

type responseValueError struct {
	field string
	err   error
}

func (err *responseValueError) Error() string {
	return fmt.Sprintf("invalid %s value", err.field)
}

func (err *responseValueError) Unwrap() error {
	return err.err
}

func invalidResponseValue(field string, err error) error {
	return &responseValueError{field: field, err: err}
}

// Utility function to deduplicate values
func removeDuplicate[T string | int](sliceList []T) []T {
	allKeys := make(map[T]bool)
	list := []T{}
	for _, item := range sliceList {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

// Utiliy function to check string is only digits
func isOnlyDigits(s string) bool {
	return regexp.MustCompile(`^\d+$`).MatchString(s)
}

// normalizeASN accepts decimal ASNs with an optional case-insensitive AS
// prefix. All ASN query formatters use it so they accept and reject the same
// inputs.
func normalizeASN(value string) (string, error) {
	asn := strings.TrimSpace(value)
	if len(asn) >= 2 && strings.EqualFold(asn[:2], "AS") {
		asn = asn[2:]
	}
	if !isOnlyDigits(asn) {
		return "", invalidInputError("ASN must be decimal digits with an optional AS prefix")
	}

	return asn, nil
}

// parseResponseLine splits a PWHOIS field without discarding delimiters in its
// value. Response content is remote input, so malformed lines must produce an
// error instead of panicking the caller.
func parseResponseLine(line string) (string, string, error) {
	key, value, ok := strings.Cut(line, ": ")
	if !ok {
		return "", "", fmt.Errorf("malformed response line: missing field delimiter")
	}

	key = strings.TrimSpace(key)
	if key == "" {
		return "", "", fmt.Errorf("malformed response line: empty field name")
	}

	return key, strings.TrimSpace(value), nil
}

func parseResponseTime(field, value string, layouts ...string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}

	var parseError error
	for _, layout := range layouts {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed, nil
		}
		parseError = err
	}

	return time.Time{}, invalidResponseValue(field, parseError)
}

func parseResponseInt64(field, value string) (int64, error) {
	if value == "" {
		return 0, nil
	}

	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, invalidResponseValue(field, err)
	}
	return parsed, nil
}

func parseResponseFloat64(field, value string) (float64, error) {
	if value == "" {
		return 0, nil
	}

	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, invalidResponseValue(field, err)
	}
	return parsed, nil
}

// Whois server object
type WhoisServer struct {
	Server       string `default:"whois.pwhois.org"`
	Port         int    `default:"43"`
	BatchMaxSize int    `default:"500"`
	// Timeout bounds connection establishment and each lookup's complete I/O
	// exchange. A zero value uses SocketTimeout.
	Timeout time.Duration
	// MaxResponseBytes bounds response data read before parsing. A value less
	// than or equal to zero uses DefaultMaxResponseBytes.
	MaxResponseBytes int64
	Connection       net.Conn
}

// Return full DNS server socket Aadress
func (server *WhoisServer) ServerAddressString() string {
	return fmt.Sprintf("%s:%d", server.Server, server.Port)
}

// Set default DNS server values
func (server *WhoisServer) SetDefaultValues() {

	v := reflect.ValueOf(server).Elem()
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		tag := t.Field(i).Tag.Get("default")

		if tag == "" {
			continue
		}

		switch field.Kind() {
		case reflect.String:
			if field.String() == "" {
				field.SetString(tag)
			}
		case reflect.Int:
			if field.Int() == 0 {
				if intValue, err := strconv.ParseInt(tag, 10, 64); err == nil {
					field.SetInt(intValue)
				}
			}
			// Add cases for other types if needed
		}
	}

	if server.Timeout == 0 {
		server.Timeout = time.Second * time.Duration(SocketTimeout)
	}
	if server.MaxResponseBytes <= 0 {
		server.MaxResponseBytes = DefaultMaxResponseBytes
	}
}

func (server WhoisServer) timeout() time.Duration {
	if server.Timeout > 0 {
		return server.Timeout
	}

	return time.Second * time.Duration(SocketTimeout)
}

// setLookupDeadline bounds both the request write and response read. PWHOIS
// lookups use a connection per request, so the deadline covers the complete
// exchange rather than allowing a server that stops responding to block
// indefinitely.
func (server WhoisServer) setLookupDeadline() error {
	return server.Connection.SetDeadline(time.Now().Add(server.timeout()))
}

func (server WhoisServer) operationError(operation string, err error) error {
	endpoint := ""
	if server.Server != "" && server.Port != 0 {
		endpoint = server.ServerAddressString()
	}
	return &OperationError{Operation: operation, Server: endpoint, Err: err}
}

func classifyTransportError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("%w: %w", ErrCanceled, err)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%w: %w", ErrTimeout, err)
	}

	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return fmt.Errorf("%w: %w", ErrTimeout, err)
	}

	return fmt.Errorf("%w: %w", ErrConnection, err)
}

func isRateLimitedResponse(response string) bool {
	return strings.Contains(strings.ToLower(response), "query limit exceeded")
}

// executeQuery applies one consistent connection, deadline, transport, and
// rate-limit error contract to every native PWHOIS lookup.
func (server WhoisServer) executeQuery(operation, query string) (string, error) {
	if server.Connection == nil {
		return "", server.operationError(operation, ErrConnection)
	}
	if err := server.setLookupDeadline(); err != nil {
		return "", server.operationError(operation, classifyTransportError(err))
	}
	if _, err := server.Connection.Write([]byte(query)); err != nil {
		return "", server.operationError(operation, classifyTransportError(err))
	}

	response, err := server.readLookupResponse()
	if err != nil {
		if errors.Is(err, ErrResponseTooLarge) {
			return "", server.operationError(operation, err)
		}
		return "", server.operationError(operation, classifyTransportError(err))
	}
	if isRateLimitedResponse(response) {
		return "", server.operationError(operation, ErrRateLimited)
	}

	return response, nil
}

func (server WhoisServer) responseSizeLimit() int64 {
	if server.MaxResponseBytes > 0 {
		return server.MaxResponseBytes
	}

	return DefaultMaxResponseBytes
}

// readLookupResponse reads remote input into a strictly capacity-controlled
// raw-response buffer. An over-limit connection is closed because its unread
// response cannot be safely reused.
func (server WhoisServer) readLookupResponse() (string, error) {
	limit := server.responseSizeLimit()
	response, err := readBoundedResponse(server.Connection, limit)
	if err != nil {
		if errors.Is(err, ErrResponseTooLarge) {
			_ = server.Connection.Close()
		}
		return "", err
	}

	return string(response), nil
}

func readBoundedResponse(reader io.Reader, limit int64) ([]byte, error) {
	initialCapacity := responseReadChunkSize
	if limit < int64(initialCapacity) {
		initialCapacity = int(limit)
	}
	response := make([]byte, 0, initialCapacity)
	chunk := make([]byte, responseReadChunkSize)

	for {
		read, err := reader.Read(chunk)
		if read > 0 {
			required := len(response) + read
			if int64(required) > limit {
				return nil, &ResponseTooLargeError{Limit: limit}
			}

			if required > cap(response) {
				nextCapacity := cap(response) * 2
				if nextCapacity < required {
					nextCapacity = required
				}
				if int64(nextCapacity) > limit {
					nextCapacity = int(limit)
				}

				grown := make([]byte, len(response), nextCapacity)
				copy(grown, response)
				response = grown
			}

			originalLength := len(response)
			response = response[:required]
			copy(response[originalLength:], chunk[:read])
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				return response, nil
			}
			return nil, err
		}
	}
}

// Establish connection to the pwhois server
func (server *WhoisServer) Connect() error {

	whoisDialer := &net.Dialer{
		Timeout:   server.timeout(),
		KeepAlive: time.Second * time.Duration(SocketKeepAlive),
	}

	var err error
	server.Connection, err = whoisDialer.Dial("tcp", server.ServerAddressString())
	if err != nil {
		return server.operationError("connect", classifyTransportError(err))
	}
	return nil
}
