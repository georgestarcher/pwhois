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
				return nil, fmt.Errorf("parse registry response record %d line %d: %w", recordIndex+1, lineIndex+1, err)
			}
			responseMap[key] = value
		}
		if len(responseMap) == 0 {
			continue
		}

		canAllocate, err := parseCanAllocate(responseMap["Can-Allocate"])
		if err != nil {
			return nil, fmt.Errorf("parse registry response record %d: %w", recordIndex+1, err)
		}
		registerDate, err := parseResponseTime("Register-Date", responseMap["Register-Date"], "2006-01-02", "Jan 02 2006 15:04:05")
		if err != nil {
			return nil, fmt.Errorf("parse registry response record %d: %w", recordIndex+1, err)
		}
		updateDate, err := parseResponseTime("Update-Date", responseMap["Update-Date"], "2006-01-02", "Jan 02 2006 15:04:05")
		if err != nil {
			return nil, fmt.Errorf("parse registry response record %d: %w", recordIndex+1, err)
		}
		createDate, err := parseResponseTime("Create-Date", responseMap["Create-Date"], "Jan 02 2006 15:04:05")
		if err != nil {
			return nil, fmt.Errorf("parse registry response record %d: %w", recordIndex+1, err)
		}
		modifyDate, err := parseResponseTime("Modify-Date", responseMap["Modify-Date"], "Jan 02 2006 15:04:05")
		if err != nil {
			return nil, fmt.Errorf("parse registry response record %d: %w", recordIndex+1, err)
		}

		var registryParsedStruct Registry
		registryParsedStruct.OrgRecord = responseMap["Org-Record"]
		registryParsedStruct.OrgID = responseMap["Org-ID"]
		registryParsedStruct.OrgName = responseMap["Org-Name"]
		registryParsedStruct.CanAllocate = canAllocate
		registryParsedStruct.Source = responseMap["Source"]
		registryParsedStruct.Street1 = responseMap["Street-1"]
		registryParsedStruct.City = responseMap["City"]
		registryParsedStruct.Region = responseMap["Region"]
		registryParsedStruct.Country = responseMap["Country"]
		registryParsedStruct.CountryCode = responseMap["Country-Code"]
		registryParsedStruct.RegisterDate = registerDate
		registryParsedStruct.UpdateDate = updateDate
		registryParsedStruct.CreateDate = createDate
		registryParsedStruct.ModifyDate = modifyDate
		registryParsedStruct.AdminHandle0 = responseMap["Admin-0-Handle"]
		registryParsedStruct.AbuseHandle0 = responseMap["Abuse-0-Handle"]
		registryParsedStruct.TechHandle0 = responseMap["CTech-0-Handle"]
		registryParsedStruct.Comment = responseMap["Comment"]

		responseRegistry = append(responseRegistry, registryParsedStruct)
	}
	return responseRegistry, nil
}

func parseCanAllocate(value string) (bool, error) {
	switch value {
	case "", "0":
		return false, nil
	case "1":
		return true, nil
	default:
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return false, fmt.Errorf("invalid Can-Allocate value: %w", err)
		}
		return parsed, nil
	}
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
