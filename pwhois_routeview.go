package pwhois

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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

	if len(asn) == 0 {
		return "", errors.New("no valid value provided")
	}
	asn = strings.TrimPrefix(asn, "AS")
	queryString := fmt.Sprintf("app=\"%s\" routeview source-as=%s\n", AppName, asn)
	return queryString, nil
}

// Parse response string into slice of BGP routing records
func parseBgpResponse(response string) ([]BGPRoute, error) {
	if len(response) == 0 {
		return nil, fmt.Errorf("no records returned")

	}
	return parseBGPData(response), nil
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
