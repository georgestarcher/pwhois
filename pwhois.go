package pwhois

import (
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strconv"
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
