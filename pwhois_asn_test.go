package pwhois

import (
	"fmt"
	"testing"
)

func TestASNQueryFormattersNormalizeInputsConsistently(t *testing.T) {
	server := new(WhoisServer)
	server.SetDefaultValues()

	formatters := []struct {
		name   string
		format func(string) (string, error)
		query  string
	}{
		{"RouteView", server.FormatRouteViewQuery, "routeview"},
		{"Registry", server.FormatRegistryQuery, "registry"},
		{"Netblock", server.FormatNetblockQuery, "netblock"},
	}
	tests := []struct {
		name          string
		input         string
		normalizedASN string
		wantErr       bool
	}{
		{name: "bare number", input: "123"},
		{name: "uppercase prefix", input: "AS123", normalizedASN: "123"},
		{name: "lowercase prefix", input: "as123", normalizedASN: "123"},
		{name: "surrounding whitespace", input: " AS123 ", normalizedASN: "123"},
		{name: "empty", input: "", wantErr: true},
		{name: "prefix only", input: "AS", wantErr: true},
		{name: "prefix with space", input: "AS 123", wantErr: true},
		{name: "non-numeric", input: "AS12x", wantErr: true},
		{name: "IP address", input: "8.8.8.8", wantErr: true},
	}

	for _, formatter := range formatters {
		for _, test := range tests {
			t.Run(formatter.name+"/"+test.name, func(t *testing.T) {
				got, err := formatter.format(test.input)
				if test.wantErr {
					if err == nil {
						t.Fatal("expected an error")
					}
					if got != "" {
						t.Fatalf("query on invalid input: got %q", got)
					}
					return
				}
				if err != nil {
					t.Fatalf("format query: %v", err)
				}

				normalizedASN := test.normalizedASN
				if normalizedASN == "" {
					normalizedASN = test.input
				}
				want := fmt.Sprintf("app=\"%s\" %s source-as=%s\n", AppName, formatter.query, normalizedASN)
				if got != want {
					t.Errorf("query: got %q, want %q", got, want)
				}
			})
		}
	}
}
