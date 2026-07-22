package pwhois

import (
	"errors"
	"net"
	"testing"
	"time"
)

func assertTimeout(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		t.Fatal("lookup succeeded against a stalled server")
	}
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("lookup error = %v, want ErrTimeout", err)
	}

	var networkError net.Error
	if !errors.As(err, &networkError) || !networkError.Timeout() {
		t.Fatalf("lookup error = %v, want timeout", err)
	}
}

func TestLookupDeadlineTimesOutStalledServers(t *testing.T) {
	const timeout = 100 * time.Millisecond

	tests := []struct {
		name    string
		request string
		lookup  func(WhoisServer) error
	}{
		{
			name:    "IP",
			request: "app=\"GO pwhois Module\"\n192.0.2.1\n",
			lookup: func(server WhoisServer) error {
				responses := make(chan IpLookupResponse, 1)
				server.LookupIP("app=\"GO pwhois Module\"\n192.0.2.1\n", responses)
				return (<-responses).Error
			},
		},
		{
			name:    "RouteView",
			request: "app=\"GO pwhois Module\" routeview source-as=64500\n",
			lookup: func(server WhoisServer) error {
				responses := make(chan BGPLookupResponse, 1)
				server.LookupRouteView("64500", "app=\"GO pwhois Module\" routeview source-as=64500\n", responses)
				return (<-responses).Error
			},
		},
		{
			name:    "Registry",
			request: "app=\"GO pwhois Module\" registry source-as=64500\n",
			lookup: func(server WhoisServer) error {
				responses := make(chan RegistryLookupResponse, 1)
				server.LookupRegistry("64500", "app=\"GO pwhois Module\" registry source-as=64500\n", responses)
				return (<-responses).Error
			},
		},
		{
			name:    "Netblock",
			request: "app=\"GO pwhois Module\" netblock source-as=64500\n",
			lookup: func(server WhoisServer) error {
				responses := make(chan NetblockLookupResponse, 1)
				server.LookupNetblock("64500", "app=\"GO pwhois Module\" netblock source-as=64500\n", responses)
				return (<-responses).Error
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, results := connectLoopbackProtocolServer(t, loopbackProtocolScript{
				expectedRequest: test.request,
				noResponse:      true,
			})
			server.Timeout = timeout
			assertTimeout(t, test.lookup(*server))
			closeAndVerifyLoopbackProtocol(t, server, results, test.request)
		})
	}
}

func TestWhoisServerTimeoutDefaultsAndOverrides(t *testing.T) {
	server := new(WhoisServer)
	server.SetDefaultValues()
	if got, want := server.Timeout, time.Second*time.Duration(SocketTimeout); got != want {
		t.Errorf("default timeout = %s, want %s", got, want)
	}

	server.Timeout = 100 * time.Millisecond
	if got, want := server.timeout(), 100*time.Millisecond; got != want {
		t.Errorf("configured timeout = %s, want %s", got, want)
	}
}
