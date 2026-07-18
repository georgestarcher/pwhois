package pwhois

import (
	"fmt"
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
