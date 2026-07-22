package pwhois

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type loopbackProtocolScript struct {
	expectedRequest string
	responseChunks  []string
	noResponse      bool
}

type loopbackProtocolResult struct {
	request      string
	clientClosed bool
	err          error
}

// connectLoopbackProtocolServer starts a one-connection, IPv4 loopback-only
// PWHOIS test server and connects through WhoisServer.Connect. The server
// reads the exact scripted request, optionally returns response chunks, sends
// orderly EOF with CloseWrite, and then verifies that the caller closes its
// side of the connection.
func connectLoopbackProtocolServer(t *testing.T, script loopbackProtocolScript) (*WhoisServer, <-chan loopbackProtocolResult) {
	t.Helper()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on loopback: %v", err)
	}
	results := make(chan loopbackProtocolResult, 1)

	go func() {
		result := loopbackProtocolResult{}
		defer func() {
			results <- result
		}()
		defer listener.Close()

		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			result.err = fmt.Errorf("accept loopback connection: %w", acceptErr)
			return
		}
		defer connection.Close()
		if deadlineErr := connection.SetDeadline(time.Now().Add(3 * time.Second)); deadlineErr != nil {
			result.err = fmt.Errorf("set loopback deadline: %w", deadlineErr)
			return
		}

		request := make([]byte, len(script.expectedRequest))
		if _, readErr := io.ReadFull(connection, request); readErr != nil {
			result.err = fmt.Errorf("read scripted request: %w", readErr)
			return
		}
		result.request = string(request)

		if !script.noResponse {
			for _, chunk := range script.responseChunks {
				if _, writeErr := io.WriteString(connection, chunk); writeErr != nil {
					result.err = fmt.Errorf("write scripted response: %w", writeErr)
					return
				}
			}

			tcpConnection, ok := connection.(*net.TCPConn)
			if !ok {
				result.err = fmt.Errorf("loopback connection type = %T, want *net.TCPConn", connection)
				return
			}
			if closeErr := tcpConnection.CloseWrite(); closeErr != nil {
				result.err = fmt.Errorf("send orderly EOF: %w", closeErr)
				return
			}
		}

		buffer := make([]byte, 1)
		read, readErr := connection.Read(buffer)
		if read != 0 {
			result.err = fmt.Errorf("received %d unexpected bytes after scripted request", read)
			return
		}
		if !errors.Is(readErr, io.EOF) {
			result.err = fmt.Errorf("wait for client close: %w", readErr)
			return
		}
		result.clientClosed = true
	}()

	address := listener.Addr().(*net.TCPAddr)
	server := &WhoisServer{
		Server:           address.IP.String(),
		Port:             address.Port,
		BatchMaxSize:     500,
		Timeout:          2 * time.Second,
		MaxResponseBytes: DefaultMaxResponseBytes,
	}
	if err := server.Connect(); err != nil {
		listener.Close()
		t.Fatalf("connect to loopback server: %v", err)
	}

	t.Cleanup(func() {
		if server.Connection != nil {
			_ = server.Connection.Close()
		}
		_ = listener.Close()
	})
	return server, results
}

func closeAndVerifyLoopbackProtocol(t *testing.T, server *WhoisServer, results <-chan loopbackProtocolResult, expectedRequest string) {
	t.Helper()

	if err := server.Connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close loopback client: %v", err)
	}
	select {
	case result := <-results:
		if result.err != nil {
			t.Fatalf("loopback protocol server: %v", result.err)
		}
		if result.request != expectedRequest {
			t.Errorf("wire request = %q, want %q", result.request, expectedRequest)
		}
		if !result.clientClosed {
			t.Error("loopback server did not observe client connection cleanup")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("loopback protocol server did not finish")
	}
}

func TestLoopbackProtocolSuccessfulLookups(t *testing.T) {
	const (
		ipSingleRequest = "app=\"GO pwhois Module\"\n192.0.2.1\n"
		ipBatchRequest  = "app=\"GO pwhois Module\"\nbegin\n192.0.2.1\n198.51.100.2\nend\n"
		routeRequest    = "app=\"GO pwhois Module\" routeview source-as=64500\n"
		registryRequest = "app=\"GO pwhois Module\" registry source-as=64500\n"
		netblockRequest = "app=\"GO pwhois Module\" netblock source-as=64500\n"
	)

	tests := []struct {
		name            string
		expectedRequest string
		responseChunks  []string
		format          func(*WhoisServer) (string, error)
		lookup          func(WhoisServer, string) (any, error)
		check           func(*testing.T, any)
	}{
		{
			name:            "single IP",
			expectedRequest: ipSingleRequest,
			responseChunks: []string{
				"IP: 192.0.2.1\nOrigin-AS: 64500\n",
				"Org-Name: Example Network\nCountry-Code: ZZ",
			},
			format: func(server *WhoisServer) (string, error) {
				return server.FormatIpQuery([]string{"192.0.2.1"})
			},
			lookup: func(server WhoisServer, query string) (any, error) {
				responses := make(chan IpLookupResponse, 1)
				server.LookupIP(query, responses)
				response := <-responses
				return response.Response, response.Error
			},
			check: func(t *testing.T, value any) {
				records := value.([]WhoIs)
				if len(records) != 1 || records[0].IP != "192.0.2.1" || records[0].OriginAS != "64500" {
					t.Fatalf("IP response = %+v", records)
				}
			},
		},
		{
			name:            "batch IP",
			expectedRequest: ipBatchRequest,
			responseChunks: []string{
				"IP: 192.0.2.1\nOrigin-AS: 64500\nOrg-Name: Example One\n\n",
				"IP: 198.51.100.2\nOrigin-AS: 64501\nOrg-Name: Example Two",
			},
			format: func(server *WhoisServer) (string, error) {
				return server.FormatIpQuery([]string{"192.0.2.1", "198.51.100.2", "192.0.2.1"})
			},
			lookup: func(server WhoisServer, query string) (any, error) {
				responses := make(chan IpLookupResponse, 1)
				server.LookupIP(query, responses)
				response := <-responses
				return response.Response, response.Error
			},
			check: func(t *testing.T, value any) {
				records := value.([]WhoIs)
				if len(records) != 2 || records[0].IP != "192.0.2.1" || records[1].IP != "198.51.100.2" {
					t.Fatalf("batch IP response = %+v", records)
				}
			},
		},
		{
			name:            "RouteView",
			expectedRequest: routeRequest,
			responseChunks: []string{
				"Origin-AS: 64500\n",
				"*> 192.0.2.0/24 | Jul 18 2026 00:00:04 | Jul 18 2026 00:00:04 | May 28 2026 06:56:01 | 192.0.2.254 | 64501 64500",
			},
			format: func(server *WhoisServer) (string, error) {
				return server.FormatRouteViewQuery("AS64500")
			},
			lookup: func(server WhoisServer, query string) (any, error) {
				responses := make(chan BGPLookupResponse, 1)
				server.LookupRouteView("64500", query, responses)
				response := <-responses
				return response.Response, response.Error
			},
			check: func(t *testing.T, value any) {
				routes := value.(BGPRoutes)
				if routes.Asn != "64500" || len(routes.Routes) != 1 || routes.Routes[0].Prefix != "192.0.2.0/24" {
					t.Fatalf("RouteView response = %+v", routes)
				}
			},
		},
		{
			name:            "registry",
			expectedRequest: registryRequest,
			responseChunks: []string{
				"Org-Record: TEST-ORG\nOrg-ID: TEST\nOrg-Name: Example Registry Organization\n",
				"Can-Allocate: 1\nSource: TEST\nPostal-Code: 00000\nCountry-Code: ZZ",
			},
			format: func(server *WhoisServer) (string, error) {
				return server.FormatRegistryQuery("AS64500")
			},
			lookup: func(server WhoisServer, query string) (any, error) {
				responses := make(chan RegistryLookupResponse, 1)
				server.LookupRegistry("64500", query, responses)
				response := <-responses
				return response.Response, response.Error
			},
			check: func(t *testing.T, value any) {
				record := value.(RegistryRecord)
				if record.Asn != "64500" || record.Registry.OrgID != "TEST" || !record.Registry.CanAllocate {
					t.Fatalf("registry response = %+v", record)
				}
			},
		},
		{
			name:            "netblock",
			expectedRequest: netblockRequest,
			responseChunks: []string{
				"Origin-AS: 64500\nAS: 64500\nAS-Source: TEST\nOrg: 1\nOrg-ID: TEST\nOrg-Name: Example Networks\nOrg-Source: TEST\n",
				"*> 192.0.2.0 - 192.0.2.255 | EXAMPLE-NET | reassignment | 2019-05-25 | 2019-09-25 | Jun 28 2019 16:53:01 | Jul 18 2026 03:19:32 | TEST",
			},
			format: func(server *WhoisServer) (string, error) {
				return server.FormatNetblockQuery("AS64500")
			},
			lookup: func(server WhoisServer, query string) (any, error) {
				responses := make(chan NetblockLookupResponse, 1)
				server.LookupNetblock("64500", query, responses)
				response := <-responses
				return response.Response, response.Error
			},
			check: func(t *testing.T, value any) {
				record := value.(NetblockRecord)
				if record.Asn != "64500" || record.OrgName != "Example Networks" || len(record.Netblocks) != 1 {
					t.Fatalf("netblock response = %+v", record)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, results := connectLoopbackProtocolServer(t, loopbackProtocolScript{
				expectedRequest: test.expectedRequest,
				responseChunks:  test.responseChunks,
			})

			query, err := test.format(server)
			if err != nil {
				t.Fatalf("format query: %v", err)
			}
			if query != test.expectedRequest {
				t.Fatalf("formatted query = %q, want %q", query, test.expectedRequest)
			}
			response, err := test.lookup(*server, query)
			if err != nil {
				t.Fatalf("lookup: %v", err)
			}
			test.check(t, response)
			closeAndVerifyLoopbackProtocol(t, server, results, test.expectedRequest)
		})
	}
}

func TestLoopbackProtocolTruncatedResponsesFailSafely(t *testing.T) {
	tests := []struct {
		name     string
		request  string
		response string
		lookup   func(WhoisServer) error
	}{
		{
			name:     "IP",
			request:  "app=\"GO pwhois Module\"\n192.0.2.1\n",
			response: "IP: 192.0.2.1\nLatitude: 1e",
			lookup: func(server WhoisServer) error {
				responses := make(chan IpLookupResponse, 1)
				server.LookupIP("app=\"GO pwhois Module\"\n192.0.2.1\n", responses)
				return (<-responses).Error
			},
		},
		{
			name:     "RouteView",
			request:  "app=\"GO pwhois Module\" routeview source-as=64500\n",
			response: "*> 192.0.2.0/24 | Jul 18",
			lookup: func(server WhoisServer) error {
				responses := make(chan BGPLookupResponse, 1)
				server.LookupRouteView("64500", "app=\"GO pwhois Module\" routeview source-as=64500\n", responses)
				return (<-responses).Error
			},
		},
		{
			name:     "registry",
			request:  "app=\"GO pwhois Module\" registry source-as=64500\n",
			response: "Org-ID: TEST\nCan-Allocate: not-",
			lookup: func(server WhoisServer) error {
				responses := make(chan RegistryLookupResponse, 1)
				server.LookupRegistry("64500", "app=\"GO pwhois Module\" registry source-as=64500\n", responses)
				return (<-responses).Error
			},
		},
		{
			name:     "netblock",
			request:  "app=\"GO pwhois Module\" netblock source-as=64500\n",
			response: "Origin-AS: 64500\n*> 192.0.2.0 -",
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
				responseChunks:  []string{test.response},
			})
			err := test.lookup(*server)
			if !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("truncated lookup error = %v, want ErrMalformedResponse", err)
			}
			if strings.Contains(err.Error(), test.response) {
				t.Fatal("truncated lookup error exposed remote response content")
			}
			closeAndVerifyLoopbackProtocol(t, server, results, test.request)
		})
	}
}
