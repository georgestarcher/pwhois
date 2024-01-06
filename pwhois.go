package pwhois

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Timeout for network socket in seconds to pwhois server
const SocketTimeout int = 5

// Time for netowrk socket keep alive in seconds
const SocketKeepAlive int = 30

// App Name for this module similar to HTTP User Agent in use
const AppName string = "GO pwhois Module"

// Query string for batch query start
const BatchStart string = "begin\n"

// Query string for batch query end
const BatchEnd string = "end\n"

// Max size of a batch query
const BatchMaxSize int = 500

// Whois server object
type WhoisServer struct {
	Server     string `default:"whois.pwhois.org"`
	Port       int    `default:"43"`
	Connection net.Conn
}

// Return full DNS server socket Aadress
func (server *WhoisServer) ServerAddressString() string {
	return fmt.Sprintf("%s:%d", server.Server, server.Port)
}

// Channel return object for lookup response
type LookupResponse struct {
	Response []WhoIs
	Error    error
}

// Whois lookup response object
type WhoIs struct {
	IP                  string  `json:"ip"`
	OriginAS            string  `json:"origin_asn"`
	Prefix              string  `json:"prefix"`
	OrgName             string  `json:"org_name"`
	AsnPath             string  `json:"asn_path"`
	AsnOrgName          string  `json:"asn_org_name"`
	NetworkName         string  `json:"net_name"`
	CacheDate           string  `json:"cache_date"`
	Latitude            float64 `json:"latitude"`
	Longitude           float64 `json:"longitude"`
	City                string  `json:"city"`
	Region              string  `json:"region"`
	Country             string  `json:"country"`
	CountryCode         string  `json:"country_code"`
	CC                  string  `json:"cc"`
	RouteOriginatedDate string  `json:"route_orginated_date"`
	RouteOriginatedTS   string  `json:"route_orginated_ts"`
}

// Deduplicate values
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

// Return string formatted query.
// Takes slice of IP address values.
// Provide slice of len 1 for single value.
func formatLookupQuery(values []string) (string, error) {

	queryString := fmt.Sprintf("app=\"%s\"\n", AppName)
	var checkedValues []string

	// build slice of valid IP values from provided values
	for _, value := range values {
		if net.ParseIP(value) == nil {
			continue
		}
		checkedValues = append(checkedValues, value)
	}

	deduplicatedValues := removeDuplicate(checkedValues)

	// check slice sizes and build query string
	if len(deduplicatedValues) == 0 {
		return "", errors.New("no valid values provided")
	} else if len(deduplicatedValues) > BatchMaxSize {
		return "", fmt.Errorf("values slice larger than maximum: %v", BatchMaxSize)
	} else if len(deduplicatedValues) == 1 {
		queryString = queryString + fmt.Sprintf("%s\n", deduplicatedValues[0])
		return queryString, nil
	}
	queryString = queryString + BatchStart
	for _, value := range deduplicatedValues {
		queryString = queryString + fmt.Sprintf("%s\n", value)
	}
	queryString = queryString + BatchEnd

	return queryString, nil
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

// Parse response slice of bytes into slice of WhoIs records
func parseResponseBytes(response []byte) ([]WhoIs, error) {

	var responseWhoIs []WhoIs
	responseMap := make(map[string]string)

	// Convert slice of bytes to string
	responseString := string(response[:])
	responseRecords := strings.Split(responseString, "\n\n")

	// Break the string records apart and into the WhoIs structs
	// One record will be returned as a slice of one WhoIs member
	if len(response) == 0 || len(responseRecords) == 0 {
		return nil, fmt.Errorf("no records returned")
	}
	for _, record := range responseRecords {
		if len(record) == 0 {
			continue
		}
		lines := strings.Split(record, "\n")
		for _, line := range lines {
			if len(line) == 0 {
				continue
			}
			values := strings.Split(line, ":")
			responseMap[values[0]] = strings.Trim(values[1], " ")
			if len(responseMap) == 0 {
				continue
			}
		}
		latitudeFloat, _ := strconv.ParseFloat(responseMap["Latitude"], 64)
		LongitudeFloat, _ := strconv.ParseFloat(responseMap["Longitude"], 64)
		var whoIsParsedStruct WhoIs
		whoIsParsedStruct.IP = responseMap["IP"]
		whoIsParsedStruct.OriginAS = responseMap["Origin-AS"]
		whoIsParsedStruct.AsnPath = responseMap["AS-Path"]
		whoIsParsedStruct.AsnOrgName = responseMap["AS-Org-Name"]
		whoIsParsedStruct.OrgName = responseMap["Org-Name"]
		whoIsParsedStruct.NetworkName = responseMap["Net-Name"]
		whoIsParsedStruct.CacheDate = responseMap["Cache-Date:"]
		whoIsParsedStruct.Latitude = latitudeFloat
		whoIsParsedStruct.Longitude = LongitudeFloat
		whoIsParsedStruct.City = responseMap["City"]
		whoIsParsedStruct.Region = responseMap["Region"]
		whoIsParsedStruct.Country = responseMap["Country"]
		whoIsParsedStruct.CountryCode = responseMap["Country-Code"]
		whoIsParsedStruct.RouteOriginatedDate = responseMap["Route-Originated-Date"]
		whoIsParsedStruct.CacheDate = responseMap["Route-Originated-TS"]
		responseWhoIs = append(responseWhoIs, whoIsParsedStruct)
	}
	return responseWhoIs, nil

}

// Lookup single IP address query
func (server WhoisServer) Lookup(query string, c chan LookupResponse) {

	var Answer []WhoIs

	// Check for pwhois server connection
	if server.Connection == nil {
		c <- LookupResponse{Answer, errors.New("execute Connect method to establish connection")}
		return
	}

	// Post query to pwhois server
	address_bytes := []byte(query)
	_, err := server.Connection.Write(address_bytes)
	if err != nil {
		c <- LookupResponse{Answer, err}
		return
	}

	// Receive query response from pwhois server
	var buf bytes.Buffer
	_, err = io.Copy(&buf, server.Connection)
	if err != nil {
		c <- LookupResponse{Answer, err}
		return
	}

	// Check for daily limit and raise error
	if strings.Contains(buf.String(), "query limit exceeded") {
		var errString string
		errString = strings.Replace(buf.String(), "Error: Error: ", errString, 1)
		c <- LookupResponse{Answer, fmt.Errorf("%v", errString)}
		return
	}
	// Parse the query response into our response and return
	Answer, err = parseResponseBytes(buf.Bytes())
	if err != nil {
		c <- LookupResponse{Answer, err}
		return
	}

	c <- LookupResponse{Answer, nil}
}
