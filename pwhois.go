package pwhois

import (
	"fmt"
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
	Connection   net.Conn
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
}

// Establish connection to the pwhois server
func (server *WhoisServer) Connect() error {

	whoisDialer := &net.Dialer{
		Timeout:   time.Second * time.Duration(SocketTimeout),
		KeepAlive: time.Second * time.Duration(SocketKeepAlive),
	}

	var err error
	server.Connection, err = whoisDialer.Dial("tcp", server.ServerAddressString())
	if err != nil {
		return err
	}
	return nil
}
