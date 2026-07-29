package pwhois

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	contextIPRequest       = "app=\"GO pwhois Module\"\n192.0.2.1\n"
	contextRouteRequest    = "app=\"GO pwhois Module\" routeview source-as=64500\n"
	contextRegistryRequest = "app=\"GO pwhois Module\" registry source-as=64500\n"
	contextNetblockRequest = "app=\"GO pwhois Module\" netblock source-as=64500\n"

	contextIPResponse    = "IP: 192.0.2.1\nOrigin-AS: 64500\nOrg-Name: Example Network\nCountry-Code: ZZ"
	contextRouteResponse = "Origin-AS: 64500\n" +
		"*> 192.0.2.0/24 | Jul 18 2026 00:00:04 | Jul 18 2026 00:00:04 | May 28 2026 06:56:01 | 192.0.2.254 | 64501 64500"
	contextRegistryResponse = "Org-Record: TEST-ORG\nOrg-ID: TEST\nOrg-Name: Example Registry Organization\n" +
		"Can-Allocate: 1\nSource: TEST\nPostal-Code: 00000\nCountry-Code: ZZ"
	contextNetblockResponse = "Origin-AS: 64500\nAS: 64500\nAS-Source: TEST\nOrg: 1\nOrg-ID: TEST\nOrg-Name: Example Networks\nOrg-Source: TEST\n" +
		"*> 192.0.2.0 - 192.0.2.255 | EXAMPLE-NET | reassignment | 2019-05-25 | 2019-09-25 | Jun 28 2019 16:53:01 | Jul 18 2026 03:19:32 | TEST"
)

func TestContextLookupsOwnCompleteConnectionLifecycle(t *testing.T) {
	tests := []struct {
		name     string
		request  string
		response string
		lookup   func(context.Context, WhoisServer) error
	}{
		{
			name:     "IP",
			request:  contextIPRequest,
			response: contextIPResponse,
			lookup: func(ctx context.Context, server WhoisServer) error {
				records, err := server.LookupIPContext(ctx, []string{"192.0.2.1"})
				if err == nil && (len(records) != 1 || records[0].OriginAS != "64500") {
					return fmt.Errorf("unexpected IP records: %+v", records)
				}
				return err
			},
		},
		{
			name:     "RouteView",
			request:  contextRouteRequest,
			response: contextRouteResponse,
			lookup: func(ctx context.Context, server WhoisServer) error {
				routes, err := server.LookupRouteViewContext(ctx, "AS64500")
				if err == nil && (routes.Asn != "64500" || len(routes.Routes) != 1) {
					return fmt.Errorf("unexpected RouteView response: %+v", routes)
				}
				return err
			},
		},
		{
			name:     "registry",
			request:  contextRegistryRequest,
			response: contextRegistryResponse,
			lookup: func(ctx context.Context, server WhoisServer) error {
				record, err := server.LookupRegistryContext(ctx, "as64500")
				if err == nil && (record.Asn != "64500" || record.Registry.OrgID != "TEST") {
					return fmt.Errorf("unexpected registry response: %+v", record)
				}
				return err
			},
		},
		{
			name:     "netblock",
			request:  contextNetblockRequest,
			response: contextNetblockResponse,
			lookup: func(ctx context.Context, server WhoisServer) error {
				record, err := server.LookupNetblockContext(ctx, "64500")
				if err == nil && (record.Asn != "64500" || len(record.Netblocks) != 1) {
					return fmt.Errorf("unexpected netblock response: %+v", record)
				}
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, results := startLoopbackProtocolServer(t, loopbackProtocolScript{
				expectedRequest: test.request,
				responseChunks:  []string{test.response},
			})

			if err := test.lookup(context.Background(), *server); err != nil {
				t.Fatalf("context lookup: %v", err)
			}
			if server.Connection != nil {
				t.Error("context lookup mutated the caller's Connection field")
			}
			verifyAutomaticallyClosedLoopbackProtocol(t, results, test.request)
		})
	}
}

func TestContextLookupZeroValueUsesDefaultsAndDialHook(t *testing.T) {
	var (
		gotNetwork string
		gotAddress string
	)
	serverDone := make(chan error, 1)
	server := WhoisServer{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			gotNetwork = network
			gotAddress = address
			client, provider := net.Pipe()
			go func() {
				defer provider.Close()
				request := make([]byte, len(contextIPRequest))
				if _, err := io.ReadFull(provider, request); err != nil {
					serverDone <- err
					return
				}
				if string(request) != contextIPRequest {
					serverDone <- fmt.Errorf("request = %q", request)
					return
				}
				_, err := io.WriteString(provider, contextIPResponse)
				serverDone <- err
			}()
			return client, nil
		},
	}

	records, err := server.LookupIPContext(context.Background(), []string{"192.0.2.1"})
	if err != nil {
		t.Fatalf("LookupIPContext: %v", err)
	}
	if len(records) != 1 || records[0].IP != "192.0.2.1" {
		t.Fatalf("records = %+v", records)
	}
	if gotNetwork != "tcp" || gotAddress != "whois.pwhois.org:43" {
		t.Errorf("dial = %s %s, want tcp whois.pwhois.org:43", gotNetwork, gotAddress)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("injected provider: %v", err)
	}
}

func TestContextLookupCancellationClosesConnection(t *testing.T) {
	server, results := startLoopbackProtocolServer(t, loopbackProtocolScript{
		expectedRequest: contextIPRequest,
		noResponse:      true,
	})
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	defer cancel()

	_, err := server.LookupIPContext(ctx, []string{"192.0.2.1"})
	if !errors.Is(err, ErrCanceled) || !errors.Is(err, context.Canceled) {
		t.Fatalf("lookup error = %v, want ErrCanceled and context.Canceled", err)
	}
	verifyAutomaticallyClosedLoopbackProtocol(t, results, contextIPRequest)
}

func TestContextLookupTimeoutClosesConnection(t *testing.T) {
	server, results := startLoopbackProtocolServer(t, loopbackProtocolScript{
		expectedRequest: contextIPRequest,
		noResponse:      true,
	})
	server.Timeout = 50 * time.Millisecond

	_, err := server.LookupIPContext(context.Background(), []string{"192.0.2.1"})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("lookup error = %v, want ErrTimeout", err)
	}
	verifyAutomaticallyClosedLoopbackProtocol(t, results, contextIPRequest)
}

func TestContextLookupCallerDeadlineTakesPrecedence(t *testing.T) {
	server, results := startLoopbackProtocolServer(t, loopbackProtocolScript{
		expectedRequest: contextIPRequest,
		noResponse:      true,
	})
	server.Timeout = 2 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := server.LookupIPContext(ctx, []string{"192.0.2.1"})
	if !errors.Is(err, ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lookup error = %v, want ErrTimeout and context.DeadlineExceeded", err)
	}
	verifyAutomaticallyClosedLoopbackProtocol(t, results, contextIPRequest)
}

func TestContextLookupCancellationReachesDialer(t *testing.T) {
	dialStarted := make(chan struct{})
	server := WhoisServer{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			close(dialStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-dialStarted
		cancel()
	}()

	_, err := server.LookupIPContext(ctx, []string{"192.0.2.1"})
	if !errors.Is(err, ErrCanceled) || !errors.Is(err, context.Canceled) {
		t.Fatalf("dial error = %v, want ErrCanceled and context.Canceled", err)
	}
}

func TestContextLookupTimeoutReachesDialer(t *testing.T) {
	server := WhoisServer{
		Timeout: 50 * time.Millisecond,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	_, err := server.LookupIPContext(context.Background(), []string{"192.0.2.1"})
	if !errors.Is(err, ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dial error = %v, want ErrTimeout and context.DeadlineExceeded", err)
	}
}

func TestContextLookupRejectsNilContext(t *testing.T) {
	_, err := (WhoisServer{}).LookupIPContext(nil, []string{"192.0.2.1"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("lookup error = %v, want ErrInvalidInput", err)
	}
}

func TestContextLookupsAreSafeForConcurrentUse(t *testing.T) {
	var dialCount atomic.Int64
	serverErrors := make(chan error, 32)
	server := WhoisServer{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialCount.Add(1)
			client, provider := net.Pipe()
			go func() {
				defer provider.Close()
				request := make([]byte, len(contextIPRequest))
				if _, err := io.ReadFull(provider, request); err != nil {
					serverErrors <- err
					return
				}
				if string(request) != contextIPRequest {
					serverErrors <- fmt.Errorf("request = %q", request)
					return
				}
				_, err := io.WriteString(provider, contextIPResponse)
				serverErrors <- err
			}()
			return client, nil
		},
	}

	var wait sync.WaitGroup
	lookupErrors := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			records, err := server.LookupIPContext(context.Background(), []string{"192.0.2.1"})
			if err == nil && (len(records) != 1 || records[0].IP != "192.0.2.1") {
				err = fmt.Errorf("unexpected records: %+v", records)
			}
			lookupErrors <- err
		}()
	}
	wait.Wait()

	for i := 0; i < 32; i++ {
		if err := <-lookupErrors; err != nil {
			t.Errorf("concurrent lookup: %v", err)
		}
		if err := <-serverErrors; err != nil {
			t.Errorf("concurrent provider: %v", err)
		}
	}
	if got := dialCount.Load(); got != 32 {
		t.Errorf("dial count = %d, want 32 independent connections", got)
	}
	if server.Connection != nil {
		t.Error("concurrent context lookups mutated shared Connection")
	}
}
