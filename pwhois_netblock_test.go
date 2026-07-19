package pwhois

import (
	"errors"
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
			err:      ErrInvalidInput,
		},
		{
			name:     "InvalidValue",
			value:    "8.8.8.8",
			expected: "",
			err:      ErrInvalidInput,
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
