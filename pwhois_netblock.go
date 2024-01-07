package pwhois

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// BGP netblock object
type NetblockRecord struct {
	Asn       string     `json:"asn"`
	OriginAs  string     `json:"origin_as"`
	ASSource  string     `json:"as_source"`
	OrgID     string     `json:"org_id"`
	Org       int64      `json:"org"`
	AS        int64      `json:"org"`
	OrgName   string     `json:"org_nam"`
	OrgSource string     `json:"org_source"`
	Netblocks []Netblock `json:"blocks"`
}

// Channel return object for netblock query response
type NetblockLookupResponse struct {
	Response NetblockRecord
	Error    error
}

// Netblock record object
type Netblock struct {
	Name         string    `json:"net_name"`
	Type         string    `json:"net_type"`
	Range        string    `json:"net_range"`
	RegisterDate time.Time `json:"register_date"`
	UpdateDate   time.Time `json:"update_date"`
	CreateDate   time.Time `json:"create_date"`
	ModifyDate   time.Time `json:"modify_date"`
	Source       string    `json:"source"`
}

/*
	Returns string formatted netblock query.

args:

>asn: string of the ASN to lookup
*/
func (server *WhoisServer) FormatNetblockQuery(asn string) (string, error) {

	if len(asn) == 0 {
		return "", fmt.Errorf("no valid value provided")
	}

	asn = strings.TrimPrefix(asn, "AS")
	if !isOnlyDigits(asn) {
		return "", fmt.Errorf("invalid asn value")
	}
	queryString := fmt.Sprintf("app=\"%s\" netblock source-as=%s\n", AppName, asn)

	return queryString, nil
}

// Extract header slice from netblock response
func getNetblockSections(response string) ([]string, []string, error) {

	var header []string
	var blocks []string

	// Check for empty response
	if len(response) == 0 {
		return nil, nil, fmt.Errorf("no records returned")
	}

	lines := strings.Split(response, "\n")
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		if strings.Contains(line, ": ") {
			// If header type line add to header
			header = append(header, line)
		} else if strings.HasPrefix(line, "*>") {
			// If block type line add to blocks
			temp := strings.TrimPrefix(line, "*>")
			blocks = append(blocks, temp)
		}
	}

	// Check for presense of returned error message in header and raise it
	// Example `Error: No netblock found in registry database for org-id=UAAB`s`
	for _, line := range header {
		if strings.HasPrefix(line, "Error: ") {
			return header, blocks, fmt.Errorf("%s", strings.TrimPrefix(line, "Error: "))
		}
	}
	return header, blocks, nil

}

// Parse response string into slice of WhoIs records
func parseNetblockResponse(asn string, response string) ([]NetblockRecord, error) {

	var responseNetblockRecords []NetblockRecord
	var responseRecord NetblockRecord
	var blocks []Netblock
	responseMap := make(map[string]string)

	//responseMap := make(map[string]string)

	if len(response) == 0 {
		return nil, fmt.Errorf("no records returned")
	}

	headerStrings, blockStrings, err := getNetblockSections(response)
	if err != nil {
		return nil, err
	}
	if len(headerStrings) == 0 {
		return nil, fmt.Errorf("no header found")
	}
	if len(blockStrings) == 0 {
		return nil, fmt.Errorf("no network blocks found")
	}

	// Process headerStrings
	for _, line := range headerStrings {
		if len(line) == 0 {
			continue
		}
		values := strings.Split(line, ": ")
		responseMap[values[0]] = strings.Trim(values[1], " ")
		if len(responseMap) == 0 {
			continue
		}
	}

	responseRecord.Asn = asn
	responseRecord.OriginAs = responseMap["AS"]
	responseRecord.ASSource = responseMap["AS-Source"]
	responseRecord.AS, _ = strconv.ParseInt(responseMap["AS"], 10, 64)
	responseRecord.Org, _ = strconv.ParseInt(responseMap["Org"], 10, 64)
	responseRecord.OrgID = responseMap["Org-ID"]
	responseRecord.OrgName = responseMap["Org-Name"]
	responseRecord.OrgSource = responseMap["Org-Source"]
	responseRecord.OriginAs = responseMap["Origin-AS"]

	// Process blockStrings

	for _, line := range blockStrings {
		if len(line) == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 23 {
			continue // Skip invalid lines
		}
		networkRange := fmt.Sprintf("%v-%v", fields[0], fields[2])
		networkName := fields[4]
		networkType := fields[6]
		registerDate, _ := time.Parse("2006-01-02", fields[8])
		updateDate, _ := time.Parse("2006-01-02", fields[10])
		createDate, _ := time.Parse("Jan 02 2006 15:04:05", fmt.Sprintf("%s %s %s %s", fields[12], fields[13], fields[14], fields[15]))
		modifyDate, _ := time.Parse("Jan 02 2006 15:04:05", fmt.Sprintf("%s %s %s %s", fields[17], fields[18], fields[19], fields[20]))
		source := fields[22]

		block := Netblock{
			Name:         networkName,
			Type:         networkType,
			Range:        networkRange,
			RegisterDate: registerDate,
			UpdateDate:   updateDate,
			CreateDate:   createDate,
			ModifyDate:   modifyDate,
			Source:       source,
		}
		blocks = append(blocks, block)
	}
	responseRecord.Netblocks = blocks
	responseNetblockRecords = append(responseNetblockRecords, responseRecord)

	return responseNetblockRecords, nil
}

/*
	Lookup netblock by ASN

args:

>asn: string is the ASN value

>query: string is the pwhois query to execute

>c: a channel to return an BGPLookupResponse struct
*/
func (server WhoisServer) LookupNetblock(asn string, query string, c chan NetblockLookupResponse) {

	var Answer NetblockRecord

	// Check for pwhois server connection
	if server.Connection == nil {
		c <- NetblockLookupResponse{Answer, fmt.Errorf("execute Connect method to establish connection")}
		return
	}

	// Post query to pwhois server
	address_bytes := []byte(query)
	_, err := server.Connection.Write(address_bytes)
	if err != nil {
		c <- NetblockLookupResponse{Answer, err}
		return
	}

	// Receive query response from pwhois server
	var buf bytes.Buffer
	_, err = io.Copy(&buf, server.Connection)
	if err != nil {
		c <- NetblockLookupResponse{Answer, err}
		return
	}

	// Check for daily limit and raise error
	if strings.Contains(buf.String(), "query limit exceeded") {
		var errString string
		errString = strings.Replace(buf.String(), "Error: Error: ", errString, 1)
		c <- NetblockLookupResponse{Answer, fmt.Errorf("%v", errString)}
		return
	}

	// Parse respose string and return results
	netblock, err := parseNetblockResponse(asn, buf.String())
	if err != nil {
		c <- NetblockLookupResponse{Answer, err}
		return
	}
	if len(netblock) == 0 {
		c <- NetblockLookupResponse{Answer, fmt.Errorf("no records returned")}
		return
	}

	c <- NetblockLookupResponse{netblock[0], nil}
}
