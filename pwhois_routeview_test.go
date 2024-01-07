package pwhois

import (
	"fmt"
	"sync"
	"testing"
)

// Test formatting routeview pwhois query
func TestFormatRouteviewQuery(t *testing.T) {

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
			expected: "app=\"GO pwhois Module\" routeview source-as=1236\n",
			err:      nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := server.FormatRouteViewQuery(c.value)
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
func TestLookupRouteView(t *testing.T) {

	server := new(WhoisServer)
	server.SetDefaultValues()
	err := server.Connect()

	if err != nil {
		t.Errorf("got %v", err)
	}

	// process lookup of values
	var wg sync.WaitGroup

	c := make(chan BGPLookupResponse)

	value := "3356"

	query, err := server.FormatRouteViewQuery(value)
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
