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
		{
			name:  "TeamCymruIPResult",
			value: TeamCymruIPResult{},
			keys: []string{
				"allocated_date", "as_name", "country_code", "endpoint", "fetched_at", "found",
				"ip", "origin_asns", "prefix", "registry", "source",
			},
		},
		{
			name:  "RISWhoisObservation",
			value: RISWhoisObservation{},
			keys:  []string{"collector", "observed_at", "peer"},
		},
		{
			name:  "RISWhoisRouteResult",
			value: RISWhoisRouteResult{},
			keys: []string{
				"descriptions", "endpoint", "fetched_at", "first_observed", "last_observed",
				"origin_asn", "prefix", "query", "ris_peer_count", "rpsl_attributes", "seen_at", "source",
			},
		},
		{
			name:  "IRRRoutePolicyResult",
			value: IRRRoutePolicyResult{},
			keys: []string{
				"descriptions", "endpoint", "endpoint_id", "fetched_at", "maintainers", "member_of",
				"origin_asn", "prefix", "query", "query_mode", "rpki_state", "rpsl_source", "source",
			},
		},
		{
			name:  "RDAPEvent",
			value: RDAPEvent{},
			keys:  []string{"action", "date"},
		},
		{
			name:  "RDAPEntityReference",
			value: RDAPEntityReference{},
			keys:  []string{"handle", "roles"},
		},
		{
			name:  "RDAPRedactionIndicator",
			value: RDAPRedactionIndicator{},
			keys:  []string{"method", "name", "reason"},
		},
		{
			name:  "RDAPIPResult",
			value: RDAPIPResult{},
			keys: []string{
				"abuse_contacts", "bootstrap_publication", "country_code", "end_address", "endpoint",
				"events", "fetched_at", "handle", "ip_version", "name", "parent_handle", "query",
				"redacted", "redactions", "referral_count", "registered_organizations", "registry",
				"source", "start_address", "status", "type",
			},
		},
		{
			name:  "RDAPASNResult",
			value: RDAPASNResult{},
			keys: []string{
				"abuse_contacts", "bootstrap_publication", "country_code", "end_autnum", "endpoint",
				"events", "fetched_at", "handle", "name", "query", "redacted", "redactions",
				"referral_count", "registered_organizations", "registry", "source", "start_autnum",
				"status", "type",
			},
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
