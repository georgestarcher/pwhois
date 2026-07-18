package pwhois

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

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

// Parse response string into slice of WhoIs records
func parseIpResponse(response string) ([]WhoIs, error) {

	var responseWhoIs []WhoIs
	responseRecords := strings.Split(response, "\n\n")

	// Break the records apart and into the WhoIs structs
	// One record will be returned as a slice of one WhoIs member
	if len(response) == 0 || len(responseRecords) == 0 {
		return nil, fmt.Errorf("no records returned")
	}
	for recordIndex, record := range responseRecords {
		if len(record) == 0 {
			continue
		}
		responseMap := make(map[string]string)
		lines := strings.Split(record, "\n")
		for lineIndex, line := range lines {
			if len(line) == 0 {
				continue
			}
			key, value, err := parseResponseLine(line)
			if err != nil {
				return nil, fmt.Errorf("parse IP response record %d line %d: %w", recordIndex+1, lineIndex+1, err)
			}
			responseMap[key] = value
		}
		if len(responseMap) == 0 {
			continue
		}

		latitudeFloat, err := parseResponseFloat64("Latitude", responseMap["Latitude"])
		if err != nil {
			return nil, fmt.Errorf("parse IP response record %d: %w", recordIndex+1, err)
		}
		longitudeFloat, err := parseResponseFloat64("Longitude", responseMap["Longitude"])
		if err != nil {
			return nil, fmt.Errorf("parse IP response record %d: %w", recordIndex+1, err)
		}
		cacheDate, err := parseResponseTime("Cache-Date", responseMap["Cache-Date"], "Jan 02 2006 15:04:05")
		if err != nil {
			return nil, fmt.Errorf("parse IP response record %d: %w", recordIndex+1, err)
		}
		routeOriginatedDate, err := parseResponseTime("Route-Originated-Date", responseMap["Route-Originated-Date"], "Jan 02 2006 15:04:05")
		if err != nil {
			return nil, fmt.Errorf("parse IP response record %d: %w", recordIndex+1, err)
		}
		routeOriginatedTS, err := parseResponseInt64("Route-Originated-TS", responseMap["Route-Originated-TS"])
		if err != nil {
			return nil, fmt.Errorf("parse IP response record %d: %w", recordIndex+1, err)
		}

		var whoIsParsedStruct WhoIs
		whoIsParsedStruct.IP = responseMap["IP"]
		whoIsParsedStruct.OriginAS = responseMap["Origin-AS"]
		whoIsParsedStruct.AsnPath = responseMap["AS-Path"]
		whoIsParsedStruct.AsnOrgName = responseMap["AS-Org-Name"]
		whoIsParsedStruct.OrgName = responseMap["Org-Name"]
		whoIsParsedStruct.NetworkName = responseMap["Net-Name"]
		whoIsParsedStruct.CacheDate = cacheDate
		whoIsParsedStruct.Latitude = latitudeFloat
		whoIsParsedStruct.Longitude = longitudeFloat
		whoIsParsedStruct.City = responseMap["City"]
		whoIsParsedStruct.Region = responseMap["Region"]
		whoIsParsedStruct.Country = responseMap["Country"]
		whoIsParsedStruct.CountryCode = responseMap["Country-Code"]
		whoIsParsedStruct.RouteOriginatedDate = routeOriginatedDate
		whoIsParsedStruct.RouteOriginatedTS = routeOriginatedTS
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
	// Answer, err = parseIpResponseBytes(buf.Bytes())
	Answer, err = parseIpResponse(buf.String())
	if err != nil {
		c <- IpLookupResponse{Answer, err}
		return
	}
	c <- IpLookupResponse{Answer, nil}
}
