package pwhois

import (
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

// ErrResponseTooLarge identifies a PWHOIS response that exceeded the
// configured maximum size. Use errors.Is to test lookup errors for this value.
var ErrResponseTooLarge = errors.New("pwhois response exceeds maximum size")

// ResponseTooLargeError reports the configured response-size limit without
// retaining or exposing remote response content.
type ResponseTooLargeError struct {
	Limit int64
}

func (err *ResponseTooLargeError) Error() string {
	return fmt.Sprintf("%s: limit %d bytes", ErrResponseTooLarge, err.Limit)
}

func (err *ResponseTooLargeError) Unwrap() error {
	return ErrResponseTooLarge
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
		return "", errors.New("invalid ASN value")
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

	for _, layout := range layouts {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed, nil
		}
	}

	return time.Time{}, fmt.Errorf("invalid %s value", field)
}

func parseResponseInt64(field, value string) (int64, error) {
	if value == "" {
		return 0, nil
	}

	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s value: %w", field, err)
	}
	return parsed, nil
}

func parseResponseFloat64(field, value string) (float64, error) {
	if value == "" {
		return 0, nil
	}

	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s value: %w", field, err)
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
		return err
	}
	return nil
}
