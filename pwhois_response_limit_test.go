package pwhois

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type shortReadConnection struct {
	net.Conn
	maximumRead int
}

func (connection shortReadConnection) Read(buffer []byte) (int, error) {
	if len(buffer) > connection.maximumRead {
		buffer = buffer[:connection.maximumRead]
	}
	return connection.Conn.Read(buffer)
}

func connectScriptedResponseServer(t *testing.T, handler func(net.Conn) error) (net.Conn, <-chan error) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer connection.Close()
		done <- handler(connection)
	}()

	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatalf("dial scripted server: %v", err)
	}

	t.Cleanup(func() {
		connection.Close()
		listener.Close()
	})

	return connection, done
}

func waitForScriptedServer(t *testing.T, done <-chan error) {
	t.Helper()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("scripted server: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("scripted server did not finish")
	}
}

func TestReadLookupResponseAcceptsExactLimit(t *testing.T) {
	const limit = int64(64)
	payload := strings.Repeat("x", int(limit))
	connection, done := connectScriptedResponseServer(t, func(connection net.Conn) error {
		_, err := io.WriteString(connection, payload)
		return err
	})

	server := WhoisServer{Connection: connection, MaxResponseBytes: limit}
	response, err := server.readLookupResponse()
	if err != nil {
		t.Fatalf("read exact-limit response: %v", err)
	}
	if response != payload {
		t.Fatalf("response = %q, want %q", response, payload)
	}
	waitForScriptedServer(t, done)
}

func TestReadLookupResponseAcceptsChunkedResponse(t *testing.T) {
	const limit = int64(64)
	payload := strings.Repeat("chunked-", 8)
	connection, done := connectScriptedResponseServer(t, func(connection net.Conn) error {
		_, err := io.WriteString(connection, payload)
		return err
	})

	server := WhoisServer{
		Connection:       shortReadConnection{Conn: connection, maximumRead: 3},
		MaxResponseBytes: limit,
	}
	response, err := server.readLookupResponse()
	if err != nil {
		t.Fatalf("read chunked response: %v", err)
	}
	if response != payload {
		t.Fatalf("response = %q, want %q", response, payload)
	}
	waitForScriptedServer(t, done)
}

func TestAllLookupsAcceptValidResponseAtExactLimit(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		lookup  func(WhoisServer) error
	}{
		{
			name:    "IP",
			payload: "IP: 192.0.2.1",
			lookup: func(server WhoisServer) error {
				responses := make(chan IpLookupResponse, 1)
				server.LookupIP("192.0.2.1\n", responses)
				return (<-responses).Error
			},
		},
		{
			name: "RouteView",
			payload: strings.Join([]string{
				"Origin-AS: 64500",
				"*> 192.0.2.0/24 | Jul 18 2026 00:00:04 | Jul 18 2026 00:00:04 | May 28 2026 06:56:01 | 192.0.2.254 | 64501 64500",
			}, "\n"),
			lookup: func(server WhoisServer) error {
				responses := make(chan BGPLookupResponse, 1)
				server.LookupRouteView("64500", "routeview source-as=64500\n", responses)
				return (<-responses).Error
			},
		},
		{
			name:    "Registry",
			payload: "Org-ID: EXAMPLE\nOrg-Name: Example Organization",
			lookup: func(server WhoisServer) error {
				responses := make(chan RegistryLookupResponse, 1)
				server.LookupRegistry("64500", "registry source-as=64500\n", responses)
				return (<-responses).Error
			},
		},
		{
			name: "Netblock",
			payload: strings.Join([]string{
				"Origin-AS: 64500",
				"AS: 0",
				"Org: 0",
				"Org-Name: Example Networks",
				"*> 192.0.2.0 - 192.0.2.255 | EXAMPLE-NET | reassignment | 2019-05-25 | 2019-09-25 | Jun 28 2019 16:53:01 | Jul 18 2026 03:19:32 | TEST",
			}, "\n"),
			lookup: func(server WhoisServer) error {
				responses := make(chan NetblockLookupResponse, 1)
				server.LookupNetblock("64500", "netblock source-as=64500\n", responses)
				return (<-responses).Error
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connection, done := connectScriptedResponseServer(t, func(connection net.Conn) error {
				if _, err := bufio.NewReader(connection).ReadString('\n'); err != nil {
					return err
				}
				_, err := io.WriteString(connection, test.payload)
				return err
			})

			server := WhoisServer{
				Connection:       connection,
				MaxResponseBytes: int64(len(test.payload)),
			}
			if err := test.lookup(server); err != nil {
				t.Fatalf("exact-limit lookup: %v", err)
			}
			waitForScriptedServer(t, done)
		})
	}
}

func TestAllLookupsRejectOneByteOverLimit(t *testing.T) {
	const limit = int64(64)
	payload := strings.Repeat("s", int(limit+1))

	tests := []struct {
		name   string
		lookup func(WhoisServer) error
	}{
		{
			name: "IP",
			lookup: func(server WhoisServer) error {
				responses := make(chan IpLookupResponse, 1)
				server.LookupIP("192.0.2.1\n", responses)
				return (<-responses).Error
			},
		},
		{
			name: "RouteView",
			lookup: func(server WhoisServer) error {
				responses := make(chan BGPLookupResponse, 1)
				server.LookupRouteView("64500", "routeview source-as=64500\n", responses)
				return (<-responses).Error
			},
		},
		{
			name: "Registry",
			lookup: func(server WhoisServer) error {
				responses := make(chan RegistryLookupResponse, 1)
				server.LookupRegistry("64500", "registry source-as=64500\n", responses)
				return (<-responses).Error
			},
		},
		{
			name: "Netblock",
			lookup: func(server WhoisServer) error {
				responses := make(chan NetblockLookupResponse, 1)
				server.LookupNetblock("64500", "netblock source-as=64500\n", responses)
				return (<-responses).Error
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connection, done := connectScriptedResponseServer(t, func(connection net.Conn) error {
				if _, err := io.WriteString(connection, payload); err != nil {
					return err
				}
				if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					return err
				}
				_, err := io.Copy(io.Discard, connection)
				return err
			})

			server := WhoisServer{Connection: connection, MaxResponseBytes: limit}
			err := test.lookup(server)
			if !errors.Is(err, ErrResponseTooLarge) {
				t.Fatalf("lookup error = %v, want ErrResponseTooLarge", err)
			}

			var sizeError *ResponseTooLargeError
			if !errors.As(err, &sizeError) {
				t.Fatalf("lookup error type = %T, want *ResponseTooLargeError", err)
			}
			if sizeError.Limit != limit {
				t.Errorf("error limit = %d, want %d", sizeError.Limit, limit)
			}
			if strings.Contains(err.Error(), payload) {
				t.Error("size error exposed remote response content")
			}

			waitForScriptedServer(t, done)
		})
	}
}

func TestReadLookupResponseStopsNeverEndingResponseAtLimit(t *testing.T) {
	const limit = int64(128)
	connection, done := connectScriptedResponseServer(t, func(connection net.Conn) error {
		if err := connection.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		chunk := []byte(strings.Repeat("n", 32))
		for {
			if _, err := connection.Write(chunk); err != nil {
				return nil
			}
		}
	})

	server := WhoisServer{Connection: connection, MaxResponseBytes: limit}
	started := time.Now()
	_, err := server.readLookupResponse()
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("read never-ending response error = %v, want ErrResponseTooLarge", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("over-limit response took %s to terminate", elapsed)
	}
	waitForScriptedServer(t, done)
}

func TestResponseTooLargeErrorContract(t *testing.T) {
	err := &ResponseTooLargeError{Limit: 1234}
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatal("ResponseTooLargeError does not unwrap to ErrResponseTooLarge")
	}
	if got, want := err.Error(), fmt.Sprintf("%s: limit 1234 bytes", ErrResponseTooLarge); got != want {
		t.Errorf("error text = %q, want %q", got, want)
	}
}
