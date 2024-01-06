package pwhois

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"testing"
)

// Test Setup and Load Report from File
func TestSetDefaultValues(t *testing.T) {

	server := new(WhoisServer)
	server.SetDefaultValues()

	cases := []struct {
		name     string
		got      string
		expected string
	}{
		{
			name:     "DefaultServer",
			got:      server.Server,
			expected: "whois.pwhois.org",
		},
		{
			name:     "DefaultPort",
			got:      fmt.Sprintf("%v", server.Port),
			expected: "43",
		},
		{
			name:     "MaxBatchSize",
			got:      fmt.Sprintf("%v", server.BatchMaxSize),
			expected: "500",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.expected {
				t.Errorf("Expected %v, got %v", c.expected, c.got)
			}
		})
	}
}

// Helper function to generate a random IP Address
func generateRandomIP(n int) []string {

	var returnAddresses []string

	buf := make([]byte, 4)

	for i := 0; i <= n; i++ {

		ip := rand.Uint32()
		binary.LittleEndian.PutUint32(buf, ip)
		returnAddresses = append(returnAddresses, net.IP(buf).String())
	}
	return returnAddresses
}

// Test formatting pwhois query
func TestIPFormatLookupQuery(t *testing.T) {

	server := new(WhoisServer)
	server.SetDefaultValues()

	overCapactitySlice := generateRandomIP(600)

	cases := []struct {
		name     string
		values   []string
		expected string
		err      error
	}{
		{
			name:     "InvalidSingleValue",
			values:   []string{"dolly.bean"},
			expected: "",
			err:      fmt.Errorf("no valid values provided"),
		},
		{
			name:     "SingleIpValue",
			values:   []string{"8.8.8.8"},
			expected: "app=\"GO pwhois Module\"\n8.8.8.8\n",
			err:      nil,
		},
		{
			name:     "TwoIpValues",
			values:   []string{"8.8.8.8", "1.1.1.1"},
			expected: "app=\"GO pwhois Module\"\nbegin\n8.8.8.8\n1.1.1.1\nend\n",
			err:      nil,
		},
		{
			name:     "OverMaxValues",
			values:   overCapactitySlice,
			expected: "",
			err:      fmt.Errorf("values slice larger than maximum: %v", server.BatchMaxSize),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := server.FormatIpLookupQuery(c.values)
			if c.err != nil {
				t.Log(c.err)
				if fmt.Sprintf("%v", err) != fmt.Sprintf("%v", c.err) {
					t.Errorf("Expected %v, got %v", c.err, err)
				}
				t.Logf("%v", err)
			}

			if got != c.expected {
				t.Errorf("Expected %v, got %v", c.expected, got)
			}
		})
	}
}

// Test Connection to default pwhois server
func TestConnect(t *testing.T) {

	server := new(WhoisServer)
	server.SetDefaultValues()
	err := server.Connect()
	if err != nil {
		t.Errorf("got %v", err)
	} else {
		t.Logf("Connection Established to %+v\n", server.Connection.RemoteAddr())
	}
}

// Test IP lookup against default pwhois
func TestIpLookup(t *testing.T) {

	server := new(WhoisServer)
	server.SetDefaultValues()
	err := server.Connect()

	if err != nil {
		t.Errorf("got %v", err)
	}

	// process lookup of values
	var wg sync.WaitGroup

	c := make(chan IpLookupResponse)

	value1 := "8.8.8.8"
	value2 := "1.1.1.1"
	value3 := "8.8.8.8"
	var values []string
	values = append(values, value1)
	values = append(values, value2)
	values = append(values, value3)
	query, err := server.FormatIpLookupQuery(values)
	if err != nil {
		t.Fatal(err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		server.LookupIP(query, c)
	}()

	whoisAnswer := <-c
	if whoisAnswer.Error != nil {
		t.Fatalf("ERROR: %v\n", whoisAnswer.Error)
	}
	t.Logf("Query Response:%+v\n", whoisAnswer.Response)

	got := len(whoisAnswer.Response)
	want := 2

	if got != want {
		t.Errorf("Response Count: got %v, wanted %v", got, want)
	}
}

// Test Setup and Load Report from File
func TestAsnFormatLookupQuery(t *testing.T) {

	server := new(WhoisServer)
	server.SetDefaultValues()

	cases := []struct {
		name     string
		value    string
		expected string
		err      error
	}{
		{
			name:     "InvalidValue",
			value:    "",
			expected: "",
			err:      fmt.Errorf("no valid value provided"),
		},
		{
			name:     "ValidAsn",
			value:    "1236",
			expected: "app=\"GO pwhois Module\" routeview source-as=1236",
			err:      nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := server.FormatAsnLookupQuery(c.value)
			if c.err != nil {
				t.Log(c.err)
				if fmt.Sprintf("%v", err) != fmt.Sprintf("%v", c.err) {
					t.Errorf("Expected %v, got %v", c.err, err)
				}
				t.Logf("%v", err)
			}

			if got != c.expected {
				t.Errorf("Expected %v, got %v", c.expected, got)
			}
		})
	}
}

// Test ASN lookup against default pwhois
func TestLookupRouteView(t *testing.T) {

	server := new(WhoisServer)
	server.SetDefaultValues()
	err := server.Connect()

	if err != nil {
		t.Errorf("got %v", err)
	}

	// process lookup of values
	var wg sync.WaitGroup

	c := make(chan AsnLookupResponse)

	value := "3356"

	query, err := server.FormatAsnLookupQuery(value)
	if err != nil {
		t.Fatal(err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		server.LookupRouteView(value, query, c)
	}()

	asnAnswer := <-c
	if asnAnswer.Error != nil {
		t.Fatalf("ERROR: %v\n", asnAnswer.Error)
	}

	got := len(asnAnswer.Response.Routes[:2])
	want := 2

	if got != want {
		t.Errorf("Response Count: got %v, wanted %v", got, want)
	}
}
