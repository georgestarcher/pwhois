package pwhois

import (
	"errors"
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
			err:      ErrInvalidInput,
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
				if !errors.Is(err, c.err) {
					t.Errorf("error = %v, want errors.Is(..., %v)", err, c.err)
				}
			}

			if got != c.expected {
				t.Errorf("Expected %v, got %v", c.expected, got)
			}
		})
	}
}
