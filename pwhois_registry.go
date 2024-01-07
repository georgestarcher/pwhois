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

// ASN registry object
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
	Lookup registry by ASN

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
