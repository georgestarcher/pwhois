package pwhois

import (
	"errors"
	"net"
	"testing"
	"time"
)

func connectStalledServer(t *testing.T) net.Conn {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	accepted := make(chan net.Conn, 1)
	done := make(chan struct{})
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			accepted <- connection
			<-done
			connection.Close()
		}
	}()

	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		listener.Close()
		close(done)
		t.Fatalf("dial stalled server: %v", err)
	}

	select {
	case <-accepted:
	case <-time.After(time.Second):
		connection.Close()
		listener.Close()
		close(done)
		t.Fatal("stalled server did not accept connection")
	}

	t.Cleanup(func() {
		connection.Close()
		listener.Close()
		close(done)
	})

	return connection
}

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
	const timeout = 25 * time.Millisecond

	tests := []struct {
		name   string
		lookup func(WhoisServer) error
	}{
		{
			name: "IP",
			lookup: func(server WhoisServer) error {
				responses := make(chan IpLookupResponse, 1)
				server.LookupIP("8.8.8.8\n", responses)
				return (<-responses).Error
			},
		},
		{
			name: "RouteView",
			lookup: func(server WhoisServer) error {
				responses := make(chan BGPLookupResponse, 1)
				server.LookupRouteView("3356", "routeview source-as=3356\n", responses)
				return (<-responses).Error
			},
		},
		{
			name: "Registry",
			lookup: func(server WhoisServer) error {
				responses := make(chan RegistryLookupResponse, 1)
				server.LookupRegistry("3356", "registry source-as=3356\n", responses)
				return (<-responses).Error
			},
		},
		{
			name: "Netblock",
			lookup: func(server WhoisServer) error {
				responses := make(chan NetblockLookupResponse, 1)
				server.LookupNetblock("3356", "netblock source-as=3356\n", responses)
				return (<-responses).Error
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := WhoisServer{Connection: connectStalledServer(t), Timeout: timeout}
			assertTimeout(t, test.lookup(server))
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
