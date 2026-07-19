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
		{
			name:     "MaxResponseBytes",
			got:      fmt.Sprintf("%v", server.MaxResponseBytes),
			expected: fmt.Sprintf("%v", DefaultMaxResponseBytes),
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
