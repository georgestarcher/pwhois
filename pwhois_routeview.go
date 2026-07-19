package pwhois

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

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

/*
	Returns string formatted routeview query.

args:

>asn: string of the ASN to lookup
*/
func (server *WhoisServer) FormatRouteViewQuery(asn string) (string, error) {

	normalizedASN, err := normalizeASN(asn)
	if err != nil {
		return "", err
	}
	queryString := fmt.Sprintf("app=\"%s\" routeview source-as=%s\n", AppName, normalizedASN)
	return queryString, nil
}

// Parse response string into slice of BGP routing records
func parseBgpResponse(response string) ([]BGPRoute, error) {
	if len(response) == 0 {
		return nil, fmt.Errorf("no records returned")

	}
	routes, err := parseBGPData(response)
	if err != nil {
		return nil, err
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("no routes returned")
	}
	return routes, nil
}

// Parse BGP route data from string
func parseBGPData(data string) ([]BGPRoute, error) {
	var routes []BGPRoute

	lines := strings.Split(data, "\n")
	for lineIndex, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), "*>") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 21 {
			return nil, fmt.Errorf("parse route record at line %d: expected at least 21 fields", lineIndex+1)
		}

		prefix := fields[1]
		createDate, err := parseResponseTime("Create-Date", fmt.Sprintf("%s %s %s %s", fields[3], fields[4], fields[5], fields[6]), "Jan 02 2006 15:04:05")
		if err != nil {
			return nil, fmt.Errorf("parse route record at line %d: %w", lineIndex+1, err)
		}
		modifyDate, err := parseResponseTime("Modify-Date", fmt.Sprintf("%s %s %s %s", fields[8], fields[9], fields[10], fields[11]), "Jan 02 2006 15:04:05")
		if err != nil {
			return nil, fmt.Errorf("parse route record at line %d: %w", lineIndex+1, err)
		}
		originatedDate, err := parseResponseTime("Originated-Date", fmt.Sprintf("%s %s %s %s", fields[13], fields[14], fields[15], fields[16]), "Jan 02 2006 15:04:05")
		if err != nil {
			return nil, fmt.Errorf("parse route record at line %d: %w", lineIndex+1, err)
		}
		nextHop := fields[18]
		asPath, err := parseASPath(fields[20:])
		if err != nil {
			return nil, fmt.Errorf("parse route record at line %d: %w", lineIndex+1, err)
		}

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
	return routes, nil
}

// Parse AS number path
func parseASPath(asPathFields []string) ([]int, error) {
	var asPath []int
	for index, asStr := range asPathFields {
		as, err := strconv.Atoi(asStr)
		if err != nil {
			return nil, fmt.Errorf("invalid AS path value at position %d: %w", index+1, err)
		}
		asPath = append(asPath, as)
	}
	return asPath, nil
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
	if err := server.setLookupDeadline(); err != nil {
		c <- BGPLookupResponse{Answer, err}
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
	response, err := server.readLookupResponse()
	if err != nil {
		c <- BGPLookupResponse{Answer, err}
		return
	}

	// Check for daily limit and raise error
	if strings.Contains(response, "query limit exceeded") {
		var errString string
		errString = strings.Replace(response, "Error: Error: ", errString, 1)
		c <- BGPLookupResponse{Answer, fmt.Errorf("%v", errString)}
		return
	}

	routes, err := parseBgpResponse(response)
	Answer.Asn = asn
	Answer.Routes = routes

	if err != nil {
		c <- BGPLookupResponse{Answer, err}
		return
	}

	c <- BGPLookupResponse{Answer, nil}
}
