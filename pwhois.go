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

// Query string for ip batch query start
const BatchStart string = "begin\n"

// Query string for ip batch query end
const BatchEnd string = "end\n"

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

// Whois record object
type WhoIs struct {
	IP                  string    `json:"ip"`
	OriginAS            string    `json:"origin_asn"`
	Prefix              string    `json:"prefix"`
	OrgName             string    `json:"org_name"`
	AsnPath             string    `json:"asn_path"`
	AsnOrgName          string    `json:"asn_org_name"`
	NetworkName         string    `json:"net_name"`
	CacheDate           time.Time `json:"cache_date"`
	Latitude            float64   `json:"latitude"`
	Longitude           float64   `json:"longitude"`
	City                string    `json:"city"`
	Region              string    `json:"region"`
	Country             string    `json:"country"`
	CountryCode         string    `json:"country_code"`
	RouteOriginatedDate time.Time `json:"route_orginated_date"`
	RouteOriginatedTS   int64     `json:"route_orginated_ts"`
}

// Channel return object for ip query response
type IpLookupResponse struct {
	Response []WhoIs
	Error    error
}

// BGP Route object
type BGPRoute struct {
	Prefix         string    `json:"prefix"`
	CreateDate     time.Time `json:"create_date"`
	ModifyDate     time.Time `json:"modify_date"`
	OriginatedDate time.Time `json:"originated_date"`
	NextHop        string    `json:"next_hop"`
	ASPath         []int     `json:"as_path"`
}

// BGP routeview object
type BGPRoutes struct {
	Asn    string     `json:"asn"`
	Routes []BGPRoute `json:"routes"`
}

// Channel return object for routeview query response
type BGPLookupResponse struct {
	Response BGPRoutes
	Error    error
}

// Parse BGP route data from string
func parseBGPData(data string) []BGPRoute {
	var routes []BGPRoute

	lines := strings.Split(data, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 20 {
			continue // Skip invalid lines
		}

		prefix := fields[1]
		createDate, _ := time.Parse("Jan 02 2006 15:04:05", fmt.Sprintf("%s %s %s %s", fields[3], fields[4], fields[5], fields[6]))
		modifyDate, _ := time.Parse("Jan 02 2006 15:04:05", fmt.Sprintf("%s %s %s %s", fields[8], fields[9], fields[10], fields[11]))
		originatedDate, _ := time.Parse("Jan 02 2006 15:04:05", fmt.Sprintf("%s %s %s %s", fields[13], fields[14], fields[15], fields[16]))
		nextHop := fields[18]
		asPath := parseASPath(fields[20:])

		route := BGPRoute{
			Prefix:         prefix,
			CreateDate:     createDate,
			ModifyDate:     modifyDate,
			OriginatedDate: originatedDate,
			NextHop:        nextHop,
			ASPath:         asPath,
		}

		routes = append(routes, route)
	}
	return routes
}

// Parse AS number path
func parseASPath(asPathFields []string) []int {
	var asPath []int
	for _, asStr := range asPathFields {
		as, _ := strconv.Atoi(asStr)
		asPath = append(asPath, as)
	}
	return asPath
}

// BGP routeview object
type RegistryRecord struct {
	Asn      string   `json:"asn"`
	Registry Registry `json:"routes"`
}

// Channel return object for registry query response
type RegistryLookupResponse struct {
	Response RegistryRecord
	Error    error
}

// ASN Registry record object
type Registry struct {
	OrgRecord    string    `json:"org_record"`
	OrgID        string    `json:"org_id"`
	OrgName      string    `json:"org_name"`
	CanAllocate  bool      `json:"can_allocate"`
	Source       string    `json:"source"`
	Street1      string    `json:"street_1"`
	PostalCode   float64   `json:"postal_code"`
	City         string    `json:"city"`
	Region       string    `json:"region"`
	Country      string    `json:"country"`
	CountryCode  string    `json:"country_code"`
	RegisterDate time.Time `json:"register_date"`
	UpdateDate   time.Time `json:"update_date"`
	CreateDate   time.Time `json:"create_date"`
	ModifyDate   time.Time `json:"modify_date"`
	AdminHandle0 string    `json:"admin_handle_0"`
	AbuseHandle0 string    `json:"abuse_handle_0"`
	TechHandle0  string    `json:"tech_handle_0"`
	Comment      string    `json:"comment_handle_0"`
}

/*
	Returns string formatted IP(s) query.

args:

>values: slice of strings of IP address(es)
*/
func (server *WhoisServer) FormatIpQuery(values []string) (string, error) {

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
	} else if len(deduplicatedValues) > server.BatchMaxSize {
		return "", fmt.Errorf("values slice larger than maximum: %v", server.BatchMaxSize)
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

/*
	Returns string formatted routeview query.

args:

>asn: string of the ASN to lookup
*/
func (server *WhoisServer) FormatRouteViewQuery(asn string) (string, error) {

	if len(asn) == 0 {
		return "", errors.New("no valid value provided")
	}
	asn = strings.TrimPrefix(asn, "AS")
	queryString := fmt.Sprintf("app=\"%s\" routeview source-as=%s\n", AppName, asn)
	return queryString, nil
}

/*
	Returns string formatted registry query.

args:

>asn: string of the ASN to lookup
*/
func (server *WhoisServer) FormatRegistryQuery(asn string) (string, error) {

	if len(asn) == 0 {
		return "", errors.New("no valid value provided")
	}
	asn = strings.TrimPrefix(asn, "AS")
	queryString := fmt.Sprintf("app=\"%s\" registry source-as=%s\n", AppName, asn)

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

// Parse response string into slice of WhoIs records
func parseIpResponse(response string) ([]WhoIs, error) {

	var responseWhoIs []WhoIs
	responseMap := make(map[string]string)
	responseRecords := strings.Split(response, "\n\n")

	// Break the records apart and into the WhoIs structs
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
			values := strings.Split(line, ": ")
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
		whoIsParsedStruct.CacheDate, _ = time.Parse("Jan 02 2006 15:04:05", responseMap["Cache-Date"])
		whoIsParsedStruct.Latitude = latitudeFloat
		whoIsParsedStruct.Longitude = LongitudeFloat
		whoIsParsedStruct.City = responseMap["City"]
		whoIsParsedStruct.Region = responseMap["Region"]
		whoIsParsedStruct.Country = responseMap["Country"]
		whoIsParsedStruct.CountryCode = responseMap["Country-Code"]
		whoIsParsedStruct.RouteOriginatedDate, _ = time.Parse("Jan 02 2006 15:04:05", responseMap["Route-Originated-Date"])
		whoIsParsedStruct.RouteOriginatedTS, _ = strconv.ParseInt(responseMap["Route-Originated-TS"], 10, 64)
		responseWhoIs = append(responseWhoIs, whoIsParsedStruct)
	}
	return responseWhoIs, nil
}

/*
	Lookup IP address(es)

args:

>query: string is the pwhois query to execute

>c: a channel to return an IpLookupResponse struct
*/
func (server WhoisServer) LookupIP(query string, c chan IpLookupResponse) {

	var Answer []WhoIs

	// Check for pwhois server connection
	if server.Connection == nil {
		c <- IpLookupResponse{Answer, fmt.Errorf("execute Connect method to establish connection")}
		return
	}

	// Post query to pwhois server
	address_bytes := []byte(query)
	_, err := server.Connection.Write(address_bytes)
	if err != nil {
		c <- IpLookupResponse{Answer, err}
		return
	}

	// Receive query response from pwhois server
	var buf bytes.Buffer
	_, err = io.Copy(&buf, server.Connection)
	if err != nil {
		c <- IpLookupResponse{Answer, err}
		return
	}

	// Check for daily limit and raise error
	if strings.Contains(buf.String(), "query limit exceeded") {
		var errString string
		errString = strings.Replace(buf.String(), "Error: Error: ", errString, 1)
		c <- IpLookupResponse{Answer, fmt.Errorf("%v", errString)}
		return
	}
	// Parse the query response into our response and return
	//Answer, err = parseIpResponseBytes(buf.Bytes())
	Answer, err = parseIpResponse(buf.String())
	if err != nil {
		c <- IpLookupResponse{Answer, err}
		return
	}
	c <- IpLookupResponse{Answer, nil}
}

// Parse response string into slice of BGP routing records
func parseBgpResponse(response string) ([]BGPRoute, error) {
	if len(response) == 0 {
		return nil, fmt.Errorf("no records returned")

	}
	return parseBGPData(response), nil
}

/*
	Lookup routes by ASN

args:

>asn: string is the ASN value

>query: string is the pwhois query to execute

>c: a channel to return an BGPLookupResponse struct
*/
func (server WhoisServer) LookupRouteView(asn string, query string, c chan BGPLookupResponse) {

	var Answer BGPRoutes

	// Check for pwhois server connection
	if server.Connection == nil {
		c <- BGPLookupResponse{Answer, fmt.Errorf("execute Connect method to establish connection")}
		return
	}

	// Post query to pwhois server
	address_bytes := []byte(query)
	_, err := server.Connection.Write(address_bytes)
	if err != nil {
		c <- BGPLookupResponse{Answer, err}
		return
	}

	// Receive query response from pwhois server
	var buf bytes.Buffer
	_, err = io.Copy(&buf, server.Connection)
	if err != nil {
		c <- BGPLookupResponse{Answer, err}
		return
	}

	// Check for daily limit and raise error
	if strings.Contains(buf.String(), "query limit exceeded") {
		var errString string
		errString = strings.Replace(buf.String(), "Error: Error: ", errString, 1)
		c <- BGPLookupResponse{Answer, fmt.Errorf("%v", errString)}
		return
	}

	routes, err := parseBgpResponse(buf.String())
	Answer.Asn = asn
	Answer.Routes = routes

	if err != nil {
		c <- BGPLookupResponse{Answer, err}
		return
	}

	c <- BGPLookupResponse{Answer, nil}
}

// SCOOBY
// Parse response string into slice of WhoIs records
func parseRegistryResponse(response string) ([]Registry, error) {

	var responseRegistry []Registry
	responseMap := make(map[string]string)
	responseRecords := strings.Split(response, "\n\n")

	// Break the records apart and into the WhoIs structs
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
			values := strings.Split(line, ": ")
			responseMap[values[0]] = strings.Trim(values[1], " ")
			if len(responseMap) == 0 {
				continue
			}
		}
		var registryParsedStruct Registry
		registryParsedStruct.OrgRecord = responseMap["Org-Record"]
		registryParsedStruct.OrgID = responseMap["Org-ID"]
		registryParsedStruct.OrgName = responseMap["Org-Name"]
		registryParsedStruct.CanAllocate, _ = strconv.ParseBool(responseMap["Can-Allocate"])
		registryParsedStruct.Source = responseMap["Source"]
		registryParsedStruct.Street1 = responseMap["Street-1"]
		registryParsedStruct.City = responseMap["City"]
		registryParsedStruct.Region = responseMap["Region"]
		registryParsedStruct.Country = responseMap["Country"]
		registryParsedStruct.CountryCode = responseMap["Country-Code"]
		registryParsedStruct.RegisterDate, _ = time.Parse("Jan 02 2006 15:04:05", responseMap["Register-Date"])
		registryParsedStruct.UpdateDate, _ = time.Parse("Jan 02 2006 15:04:05", responseMap["Update-Date"])
		registryParsedStruct.CreateDate, _ = time.Parse("Jan 02 2006 15:04:05", responseMap["Create-Date"])
		registryParsedStruct.ModifyDate, _ = time.Parse("Jan 02 2006 15:04:05", responseMap["Modify-Date"])
		registryParsedStruct.AdminHandle0 = responseMap["Admin-0-Handle"]
		registryParsedStruct.AbuseHandle0 = responseMap["Abuse-0-Handle"]
		registryParsedStruct.TechHandle0 = responseMap["CTech-0-Handle"]
		registryParsedStruct.Comment = responseMap["Comment"]

		responseRegistry = append(responseRegistry, registryParsedStruct)
	}
	return responseRegistry, nil
}

/*
	Lookup registration by ASN

args:

>asn: string is the ASN value

>query: string is the pwhois query to execute

>c: a channel to return an BGPLookupResponse struct
*/
func (server WhoisServer) LookupRegistry(asn string, query string, c chan RegistryLookupResponse) {

	var Answer RegistryRecord

	// Check for pwhois server connection
	if server.Connection == nil {
		c <- RegistryLookupResponse{Answer, fmt.Errorf("execute Connect method to establish connection")}
		return
	}

	// Post query to pwhois server
	address_bytes := []byte(query)
	_, err := server.Connection.Write(address_bytes)
	if err != nil {
		c <- RegistryLookupResponse{Answer, err}
		return
	}

	// Receive query response from pwhois server
	var buf bytes.Buffer
	_, err = io.Copy(&buf, server.Connection)
	if err != nil {
		c <- RegistryLookupResponse{Answer, err}
		return
	}

	for _, line := range strings.Split(buf.String(), "\n") {
		fmt.Println(line)
	}

	// Check for daily limit and raise error
	if strings.Contains(buf.String(), "query limit exceeded") {
		var errString string
		errString = strings.Replace(buf.String(), "Error: Error: ", errString, 1)
		c <- RegistryLookupResponse{Answer, fmt.Errorf("%v", errString)}
		return
	}

	registry, err := parseRegistryResponse(buf.String())
	if err != nil {
		c <- RegistryLookupResponse{Answer, err}
		return
	}
	if len(registry) == 0 {
		c <- RegistryLookupResponse{Answer, fmt.Errorf("no records returned")}
		return
	}

	Answer.Asn = asn
	Answer.Registry = registry[0]

	c <- RegistryLookupResponse{Answer, nil}
}
