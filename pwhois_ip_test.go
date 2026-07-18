package pwhois

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"testing"
)

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

// Test formatting ip pwhois query
func TestFormatIpQuery(t *testing.T) {

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
			got, err := server.FormatIpQuery(c.values)
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
