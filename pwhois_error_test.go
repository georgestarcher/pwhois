package pwhois

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

type deadlineErrorConnection struct {
	net.Conn
	err error
}

func (connection deadlineErrorConnection) SetDeadline(time.Time) error {
	return connection.err
}

func lookupErrorCases() []struct {
	name      string
	operation string
	query     string
	lookup    func(WhoisServer) error
} {
	return []struct {
		name      string
		operation string
		query     string
		lookup    func(WhoisServer) error
	}{
		{
			name:      "IP",
			operation: "lookup IP",
			query:     "app=\"GO pwhois Module\"\n192.0.2.1\n",
			lookup: func(server WhoisServer) error {
				responses := make(chan IpLookupResponse, 1)
				server.LookupIP("app=\"GO pwhois Module\"\n192.0.2.1\n", responses)
				return (<-responses).Error
			},
		},
		{
			name:      "RouteView",
			operation: "lookup RouteView",
			query:     "app=\"GO pwhois Module\" routeview source-as=64500\n",
			lookup: func(server WhoisServer) error {
				responses := make(chan BGPLookupResponse, 1)
				server.LookupRouteView("64500", "app=\"GO pwhois Module\" routeview source-as=64500\n", responses)
				return (<-responses).Error
			},
		},
		{
			name:      "Registry",
			operation: "lookup registry",
			query:     "app=\"GO pwhois Module\" registry source-as=64500\n",
			lookup: func(server WhoisServer) error {
				responses := make(chan RegistryLookupResponse, 1)
				server.LookupRegistry("64500", "app=\"GO pwhois Module\" registry source-as=64500\n", responses)
				return (<-responses).Error
			},
		},
		{
			name:      "Netblock",
			operation: "lookup netblock",
			query:     "app=\"GO pwhois Module\" netblock source-as=64500\n",
			lookup: func(server WhoisServer) error {
				responses := make(chan NetblockLookupResponse, 1)
				server.LookupNetblock("64500", "app=\"GO pwhois Module\" netblock source-as=64500\n", responses)
				return (<-responses).Error
			},
		},
	}
}

func assertOperationError(t *testing.T, err error, operation, server string) {
	t.Helper()

	var operationError *OperationError
	if !errors.As(err, &operationError) {
		t.Fatalf("error type = %T, want *OperationError", err)
	}
	if operationError.Operation != operation {
		t.Errorf("operation = %q, want %q", operationError.Operation, operation)
	}
	if operationError.Server != server {
		t.Errorf("server = %q, want %q", operationError.Server, server)
	}
}

func lookupErrorFromResponse(t *testing.T, lookupCase struct {
	name      string
	operation string
	query     string
	lookup    func(WhoisServer) error
}, response string, maximumResponseBytes int64) (error, string) {
	t.Helper()

	server, results := connectLoopbackProtocolServer(t, loopbackProtocolScript{
		expectedRequest: lookupCase.query,
		responseChunks:  []string{response},
	})
	if maximumResponseBytes > 0 {
		server.MaxResponseBytes = maximumResponseBytes
	}
	err := lookupCase.lookup(*server)
	closeAndVerifyLoopbackProtocol(t, server, results, lookupCase.query)
	return err, server.ServerAddressString()
}

func TestLookupErrorClassesAreConsistent(t *testing.T) {
	secret := "do-not-return-this-server-response"
	malformedResponses := map[string]string{
		"IP":        "IP 192.0.2.1",
		"RouteView": "*> too short",
		"Registry":  "Org-ID EXAMPLE",
		"Netblock":  "Origin-AS: 64500",
	}

	for _, lookupCase := range lookupErrorCases() {
		t.Run(lookupCase.name+"/not connected", func(t *testing.T) {
			err := lookupCase.lookup(WhoisServer{Server: "test.pwhois.example", Port: 43})
			if !errors.Is(err, ErrConnection) {
				t.Fatalf("error = %v, want ErrConnection", err)
			}
			assertOperationError(t, err, lookupCase.operation, "test.pwhois.example:43")
		})

		t.Run(lookupCase.name+"/rate limited", func(t *testing.T) {
			err, endpoint := lookupErrorFromResponse(t, lookupCase, "Error: query limit exceeded\n"+secret, 0)
			if !errors.Is(err, ErrRateLimited) {
				t.Fatalf("error = %v, want ErrRateLimited", err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatal("rate-limit error exposed remote response content")
			}
			assertOperationError(t, err, lookupCase.operation, endpoint)
		})

		t.Run(lookupCase.name+"/no records", func(t *testing.T) {
			err, endpoint := lookupErrorFromResponse(t, lookupCase, "", 0)
			if !errors.Is(err, ErrNoRecords) {
				t.Fatalf("error = %v, want ErrNoRecords", err)
			}
			assertOperationError(t, err, lookupCase.operation, endpoint)
		})

		t.Run(lookupCase.name+"/malformed response", func(t *testing.T) {
			err, endpoint := lookupErrorFromResponse(t, lookupCase, malformedResponses[lookupCase.name], 0)
			if !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("error = %v, want ErrMalformedResponse", err)
			}
			assertOperationError(t, err, lookupCase.operation, endpoint)
		})
	}
}

func TestLookupCancellationErrorPreservesClass(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()

	server := WhoisServer{
		Server:     "test.pwhois.example",
		Port:       43,
		Connection: deadlineErrorConnection{Conn: client, err: context.Canceled},
	}
	responses := make(chan IpLookupResponse, 1)
	server.LookupIP("192.0.2.1\n", responses)
	err := (<-responses).Error
	if !errors.Is(err, ErrCanceled) || !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want ErrCanceled and context.Canceled", err)
	}
	assertOperationError(t, err, "lookup IP", "test.pwhois.example:43")
}

func TestConnectErrorPreservesTransportCause(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	address := listener.Addr().(*net.TCPAddr)
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	server := WhoisServer{Server: "127.0.0.1", Port: address.Port, Timeout: time.Second}
	err = server.Connect()
	if !errors.Is(err, ErrConnection) {
		t.Fatalf("connect error = %v, want ErrConnection", err)
	}
	var operationError *OperationError
	if !errors.As(err, &operationError) || operationError.Operation != "connect" {
		t.Fatalf("connect error = %v, want connect OperationError", err)
	}
	var networkError *net.OpError
	if !errors.As(err, &networkError) {
		t.Fatalf("connect error = %v, want wrapped *net.OpError", err)
	}
}

func TestMalformedResponsePreservesParserCause(t *testing.T) {
	secret := "untrusted-field-value"
	_, err := parseIpResponse("IP: 192.0.2.1\nLatitude: " + secret)
	if !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("parse error = %v, want ErrMalformedResponse", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("parse error exposed an untrusted response value")
	}
	var numberError *strconv.NumError
	if !errors.As(err, &numberError) {
		t.Fatalf("parse error = %v, want wrapped *strconv.NumError", err)
	}
}

func TestNetblockServerErrorDoesNotExposeRemoteContent(t *testing.T) {
	secret := "untrusted-server-detail"
	_, err := parseNetblockResponse("64500", "Error: "+secret)
	if !errors.Is(err, ErrNoRecords) {
		t.Fatalf("parse error = %v, want ErrNoRecords", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("netblock error exposed remote response content")
	}
}

func TestResponseTooLargeIncludesOperationContext(t *testing.T) {
	lookupCase := lookupErrorCases()[0]
	err, endpoint := lookupErrorFromResponse(t, lookupCase, strings.Repeat("x", 65), 64)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("error = %v, want ErrResponseTooLarge", err)
	}
	assertOperationError(t, err, lookupCase.operation, endpoint)
}
