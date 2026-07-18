package pwhois

import (
	"io"
	"net"
	"os"
	"strings"
	"testing"
)

func TestParseResponseLine(t *testing.T) {
	key, value, err := parseResponseLine("Comment: first: second")
	if err != nil {
		t.Fatalf("parse response line: %v", err)
	}
	if key != "Comment" || value != "first: second" {
		t.Fatalf("unexpected field: key=%q value=%q", key, value)
	}

	if _, _, err := parseResponseLine("malformed response line"); err == nil {
		t.Fatal("expected malformed response line to return an error")
	}
}

func TestParseIpResponseIsolatesRecords(t *testing.T) {
	response := strings.Join([]string{
		"IP: 192.0.2.1",
		"Prefix: 192.0.2.0/24",
		"Org-Name: First: Network",
		"Cache-Date: Jul 18 2026 07:19:28",
		"Latitude: 37.405992",
		"Longitude: -122.078515",
		"Route-Originated-Date: Mar 12 2026 15:22:33",
		"Route-Originated-TS: 1773328953",
		"",
		"IP: 192.0.2.2",
	}, "\n")

	records, err := parseIpResponse(response)
	if err != nil {
		t.Fatalf("parse IP response: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("record count: got %d, want 2", len(records))
	}
	if records[0].OrgName != "First: Network" {
		t.Fatalf("first organization: got %q", records[0].OrgName)
	}
	if records[1].OrgName != "" {
		t.Fatalf("second record inherited organization %q", records[1].OrgName)
	}
	if !records[1].CacheDate.IsZero() {
		t.Fatalf("second record inherited cache date %v", records[1].CacheDate)
	}
}

func TestParseIpResponseRejectsMalformedValues(t *testing.T) {
	tests := []struct {
		name     string
		response string
	}{
		{name: "line", response: "IP 192.0.2.1"},
		{name: "latitude", response: "IP: 192.0.2.1\nLatitude: invalid"},
		{name: "date", response: "IP: 192.0.2.1\nCache-Date: invalid"},
		{name: "timestamp", response: "IP: 192.0.2.1\nRoute-Originated-TS: invalid"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseIpResponse(test.response); err == nil {
				t.Fatal("expected malformed IP response to return an error")
			}
		})
	}
}

func TestParseRegistryResponseIsolatesRecords(t *testing.T) {
	response := strings.Join([]string{
		"Org-ID: FIRST",
		"Org-Name: First: Organization",
		"Can-Allocate: 1",
		"State: NJ",
		"Register-Date: 2001-09-18",
		"",
		"Org-ID: SECOND",
		"Can-Allocate: 0",
	}, "\n")

	records, err := parseRegistryResponse(response)
	if err != nil {
		t.Fatalf("parse registry response: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("record count: got %d, want 2", len(records))
	}
	if records[0].OrgName != "First: Organization" {
		t.Fatalf("first organization: got %q", records[0].OrgName)
	}
	if !records[0].CanAllocate {
		t.Fatal("expected numeric Can-Allocate value 1 to parse as true")
	}
	if records[0].RegisterDate.IsZero() {
		t.Fatal("expected ISO register date to be parsed")
	}
	if records[1].OrgName != "" {
		t.Fatalf("second record inherited organization %q", records[1].OrgName)
	}
	if records[1].CanAllocate {
		t.Fatal("expected numeric Can-Allocate value 0 to parse as false")
	}
}

func TestParseRegistryResponseRejectsMalformedValues(t *testing.T) {
	tests := []struct {
		name     string
		response string
	}{
		{name: "line", response: "Org-ID FIRST"},
		{name: "boolean", response: "Org-ID: FIRST\nCan-Allocate: sometimes"},
		{name: "date", response: "Org-ID: FIRST\nRegister-Date: invalid"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseRegistryResponse(test.response); err == nil {
				t.Fatal("expected malformed registry response to return an error")
			}
		})
	}
}

func TestParseBgpResponseRejectsMalformedRoutes(t *testing.T) {
	validRoute := "*> 4.0.0.0/9 | Jul 18 2026 00:00:04 | Jul 18 2026 00:00:04 | May 28 2026 06:56:01 | 208.115.137.35 | 8220 1299 3356"
	routes, err := parseBgpResponse("Origin-AS: 3356\n" + validRoute)
	if err != nil {
		t.Fatalf("parse valid route: %v", err)
	}
	if len(routes) != 1 || len(routes[0].ASPath) != 3 {
		t.Fatalf("unexpected valid route result: %+v", routes)
	}

	malformed := []string{
		"Origin-AS: 3356\n*> too short",
		"Origin-AS: 3356\n" + strings.Replace(validRoute, "1299", "invalid", 1),
		"Origin-AS: 3356\nno route records",
	}
	for _, response := range malformed {
		if _, err := parseBgpResponse(response); err == nil {
			t.Fatalf("expected malformed route response to fail: %q", response)
		}
	}
}

func TestParseNetblockResponseRejectsMalformedBlocks(t *testing.T) {
	valid := strings.Join([]string{
		"Origin-AS: 13335",
		"AS: 0",
		"Org: 0",
		"Org-Name: Example: Networks",
		"*> 8.6.112.0 - 8.6.112.255 | EXAMPLE-NET | reassignment | 2019-05-25 | 2019-09-25 | Jun 28 2019 16:53:01 | Jul 18 2026 03:19:32 | ARIN",
	}, "\n")

	records, err := parseNetblockResponse("13335", valid)
	if err != nil {
		t.Fatalf("parse valid netblock response: %v", err)
	}
	if len(records) != 1 || records[0].OrgName != "Example: Networks" {
		t.Fatalf("unexpected valid netblock result: %+v", records)
	}
	if len(records[0].Netblocks) != 1 {
		t.Fatalf("netblock count: got %d, want 1", len(records[0].Netblocks))
	}

	malformed := strings.Join([]string{
		"Origin-AS: 13335",
		"AS: 0",
		"Org: 0",
		"*> too short",
	}, "\n")
	if _, err := parseNetblockResponse("13335", malformed); err == nil {
		t.Fatal("expected malformed netblock record to return an error")
	}
}

func TestLookupRegistryDoesNotWriteStdout(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	defer clientConnection.Close()

	query := "registry query\n"
	serverResult := make(chan error, 1)
	go func() {
		defer serverConnection.Close()
		request := make([]byte, len(query))
		if _, err := io.ReadFull(serverConnection, request); err != nil {
			serverResult <- err
			return
		}
		_, err := io.WriteString(serverConnection, "Org-ID: EXAMPLE\nOrg-Name: Example Organization\n")
		serverResult <- err
	}()

	lookupResult := make(chan RegistryLookupResponse, 1)
	server := WhoisServer{Connection: clientConnection}
	var response RegistryLookupResponse
	output := captureStdout(t, func() {
		server.LookupRegistry("64500", query, lookupResult)
		response = <-lookupResult
	})

	if err := <-serverResult; err != nil {
		t.Fatalf("serve synthetic registry response: %v", err)
	}
	if response.Error != nil {
		t.Fatalf("lookup registry: %v", response.Error)
	}
	if output != "" {
		t.Fatalf("LookupRegistry wrote to stdout: %q", output)
	}
}

func captureStdout(t *testing.T, function func()) string {
	t.Helper()

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout capture pipe: %v", err)
	}
	original := os.Stdout
	os.Stdout = writer
	defer func() {
		os.Stdout = original
		reader.Close()
		writer.Close()
	}()

	function()
	if err := writer.Close(); err != nil {
		t.Fatalf("close stdout capture writer: %v", err)
	}
	os.Stdout = original

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return string(output)
}
