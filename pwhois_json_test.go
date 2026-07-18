package pwhois

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

func TestPublicJSONRecordContracts(t *testing.T) {
	tests := []struct {
		name  string
		value any
		keys  []string
	}{
		{
			name:  "WhoIs",
			value: WhoIs{},
			keys: []string{
				"asn_org_name", "asn_path", "cache_date", "city", "country", "country_code",
				"ip", "latitude", "longitude", "net_name", "org_name", "origin_asn", "prefix",
				"region", "route_originated_date", "route_originated_ts",
			},
		},
		{
			name:  "BGPRoute",
			value: BGPRoute{},
			keys:  []string{"as_path", "create_date", "modify_date", "next_hop", "originated_date", "prefix"},
		},
		{
			name:  "BGPRoutes",
			value: BGPRoutes{},
			keys:  []string{"asn", "routes"},
		},
		{
			name:  "RegistryRecord",
			value: RegistryRecord{},
			keys:  []string{"asn", "registry"},
		},
		{
			name:  "Registry",
			value: Registry{},
			keys: []string{
				"abuse_handle_0", "admin_handle_0", "can_allocate", "city", "comment", "country",
				"country_code", "create_date", "modify_date", "org_id", "org_name", "org_record", "postal_code",
				"region", "register_date", "source", "street_1", "tech_handle_0", "update_date",
			},
		},
		{
			name:  "NetblockRecord",
			value: NetblockRecord{},
			keys:  []string{"as", "as_source", "asn", "blocks", "org", "org_id", "org_name", "org_source", "origin_asn"},
		},
		{
			name:  "Netblock",
			value: Netblock{},
			keys:  []string{"create_date", "modify_date", "net_name", "net_range", "net_type", "register_date", "source", "update_date"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(test.value)
			if err != nil {
				t.Fatalf("marshal %s: %v", test.name, err)
			}

			var output map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &output); err != nil {
				t.Fatalf("decode %s: %v", test.name, err)
			}

			got := make([]string, 0, len(output))
			for key := range output {
				got = append(got, key)
			}
			sort.Strings(got)
			if !reflect.DeepEqual(got, test.keys) {
				t.Errorf("JSON keys: got %v, want %v", got, test.keys)
			}
		})
	}
}
