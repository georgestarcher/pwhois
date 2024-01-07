package pwhois

import (
	"fmt"
	"testing"
)

// Test server object defaults
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

// Test connection to default pwhois server
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
