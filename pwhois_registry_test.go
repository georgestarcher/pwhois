package pwhois

import (
	"fmt"
	"sync"
	"testing"
)

// Test formatting registry pwhois query
func TestFormatRegistryQuery(t *testing.T) {

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
			expected: "app=\"GO pwhois Module\" registry source-as=1236\n",
			err:      nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := server.FormatRegistryQuery(c.value)
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
func TestLookupRegistry(t *testing.T) {

	server := new(WhoisServer)
	server.SetDefaultValues()
	err := server.Connect()

	if err != nil {
		t.Errorf("got %v", err)
	}

	// process lookup of values
	var wg sync.WaitGroup

	c := make(chan RegistryLookupResponse)

	value := "7922"

	query, err := server.FormatRegistryQuery(value)
	if err != nil {
		t.Fatal(err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		server.LookupRegistry(value, query, c)
	}()

	registryAnswer := <-c
	if registryAnswer.Error != nil {
		t.Fatalf("ERROR: %v\n", registryAnswer.Error)
	}

	got := registryAnswer.Response.Registry.OrgName
	want := "Comcast Cable Communications, LLC"

	if got != want {
		t.Errorf("Response Count: got %v, wanted %v", got, want)
	}
}
