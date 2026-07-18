//go:build integration

package pwhois

import "testing"

func connectIntegrationServer(t *testing.T) *WhoisServer {
	t.Helper()

	server := new(WhoisServer)
	server.SetDefaultValues()
	if err := server.Connect(); err != nil {
		t.Fatalf("connect to %s: %v", server.ServerAddressString(), err)
	}
	t.Cleanup(func() {
		if err := server.Connection.Close(); err != nil {
			t.Errorf("close connection to %s: %v", server.ServerAddressString(), err)
		}
	})

	return server
}

func TestIntegrationConnect(t *testing.T) {
	server := connectIntegrationServer(t)
	t.Logf("connection established to %s", server.Connection.RemoteAddr())
}

func TestIntegrationIpLookup(t *testing.T) {
	server := connectIntegrationServer(t)
	query, err := server.FormatIpQuery([]string{"8.8.8.8", "1.1.1.1", "8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}

	responses := make(chan IpLookupResponse, 1)
	server.LookupIP(query, responses)
	response := <-responses
	if response.Error != nil {
		t.Fatalf("lookup IPs: %v", response.Error)
	}
	if got, want := len(response.Response), 2; got != want {
		t.Errorf("response count: got %d, want %d", got, want)
	}
}

func TestIntegrationRouteViewLookup(t *testing.T) {
	server := connectIntegrationServer(t)
	const asn = "3356"
	query, err := server.FormatRouteViewQuery(asn)
	if err != nil {
		t.Fatal(err)
	}

	responses := make(chan BGPLookupResponse, 1)
	server.LookupRouteView(asn, query, responses)
	response := <-responses
	if response.Error != nil {
		t.Fatalf("lookup RouteView data: %v", response.Error)
	}
	if got := len(response.Response.Routes); got < 2 {
		t.Errorf("route count: got %d, want at least 2", got)
	}
}

func TestIntegrationRegistryLookup(t *testing.T) {
	server := connectIntegrationServer(t)
	const asn = "7922"
	query, err := server.FormatRegistryQuery(asn)
	if err != nil {
		t.Fatal(err)
	}

	responses := make(chan RegistryLookupResponse, 1)
	server.LookupRegistry(asn, query, responses)
	response := <-responses
	if response.Error != nil {
		t.Fatalf("lookup registry data: %v", response.Error)
	}
	if got, want := response.Response.Registry.OrgName, "Comcast Cable Communications, LLC"; got != want {
		t.Errorf("organization name: got %q, want %q", got, want)
	}
}

func TestIntegrationNetblockLookup(t *testing.T) {
	server := connectIntegrationServer(t)
	const asn = "13335"
	query, err := server.FormatNetblockQuery(asn)
	if err != nil {
		t.Fatal(err)
	}

	responses := make(chan NetblockLookupResponse, 1)
	server.LookupNetblock(asn, query, responses)
	response := <-responses
	if response.Error != nil {
		t.Fatalf("lookup netblock data: %v", response.Error)
	}
	if got, want := response.Response.OrgName, "Cloudflare, Inc."; got != want {
		t.Errorf("organization name: got %q, want %q", got, want)
	}
}
