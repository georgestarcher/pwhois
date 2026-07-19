package pwhois

import (
	"fmt"
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
	RouteOriginatedDate time.Time `json:"route_originated_date"`
	RouteOriginatedTS   int64     `json:"route_originated_ts"`
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
		return "", invalidInputError("at least one valid IP address is required")
	} else if len(deduplicatedValues) > server.BatchMaxSize {
		return "", invalidInputError(fmt.Sprintf("IP batch exceeds maximum of %d addresses", server.BatchMaxSize))
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

// Parse response string into slice of WhoIs records.
func parseIpResponse(response string) ([]WhoIs, error) {
	records, err := parseIPResponseData(response)
	if err != nil {
		return nil, malformedResponseError(err)
	}
	return records, nil
}

func parseIPResponseData(response string) ([]WhoIs, error) {

	var responseWhoIs []WhoIs
	responseRecords := strings.Split(response, "\n\n")

	// Break the records apart and into the WhoIs structs
	// One record will be returned as a slice of one WhoIs member
	if len(response) == 0 || len(responseRecords) == 0 {
		return nil, noRecordsError("IP lookup")
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
	if len(responseWhoIs) == 0 {
		return nil, noRecordsError("IP lookup")
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

	response, err := server.executeQuery("lookup IP", query)
	if err != nil {
		c <- IpLookupResponse{Answer, err}
		return
	}

	// Parse the query response into our response and return
	Answer, err = parseIpResponse(response)
	if err != nil {
		c <- IpLookupResponse{Answer, server.operationError("lookup IP", err)}
		return
	}
	c <- IpLookupResponse{Answer, nil}
}
