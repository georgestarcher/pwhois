package pwhois

import (
	"fmt"
	"sync"
	"testing"
)

// Test formatting netblock pwhois query
func TestFormatNetblockQuery(t *testing.T) {

	server := new(WhoisServer)
	server.SetDefaultValues()

	cases := []struct {
		name     string
		value    string
		expected string
		err      error
	}{
		{
			name:     "EmptyValue",
			value:    "",
			expected: "",
			err:      fmt.Errorf("no valid value provided"),
		},
		{
			name:     "InvalidValue",
			value:    "8.8.8.8",
			expected: "",
			err:      fmt.Errorf("invalid asn value"),
		},
		{
			name:     "ValidValue",
			value:    "1236",
			expected: "app=\"GO pwhois Module\" netblock source-as=1236\n",
			err:      nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := server.FormatNetblockQuery(c.value)
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

// Test routeview lookup against default pwhois
func TestLookupNetblock(t *testing.T) {

	server := new(WhoisServer)
	server.SetDefaultValues()
	err := server.Connect()

	if err != nil {
		t.Errorf("got %v", err)
	}

	// process lookup of values
	var wg sync.WaitGroup

	c := make(chan NetblockLookupResponse)

	value := "3452" // UAB
	value = "13335"

	query, err := server.FormatNetblockQuery(value)
	if err != nil {
		t.Fatal(err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		server.LookupNetblock(value, query, c)
	}()

	netblockAnswer := <-c
	if netblockAnswer.Error != nil {
		t.Fatalf("ERROR: %v\n", netblockAnswer.Error)
	}

	got := netblockAnswer.Response.OrgName
	want := "Cloudflare, Inc."

	if got != want {
		t.Errorf("Response Count: got %v, wanted %v", got, want)
	}
}
