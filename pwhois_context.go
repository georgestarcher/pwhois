package pwhois

import (
	"context"
	"net"
	"time"
)

func (server WhoisServer) configured() WhoisServer {
	server.SetDefaultValues()
	return server
}

func (server WhoisServer) dial(ctx context.Context) (net.Conn, error) {
	if server.DialContext != nil {
		return server.DialContext(ctx, "tcp", server.ServerAddressString())
	}

	dialer := &net.Dialer{
		KeepAlive: time.Second * time.Duration(SocketKeepAlive),
	}
	return dialer.DialContext(ctx, "tcp", server.ServerAddressString())
}

// executeOwnedQuery performs a complete high-level lookup transport exchange.
// It applies the shorter of the caller's deadline and WhoisServer.Timeout,
// closes the connection on cancellation, and always closes the connection
// before returning.
func (server WhoisServer) executeOwnedQuery(ctx context.Context, operation, query string) (string, error) {
	if ctx == nil {
		return "", server.operationError(operation, invalidInputError("context must not be nil"))
	}

	lookupCtx, cancel := context.WithTimeout(ctx, server.timeout())
	defer cancel()

	connection, err := server.dial(lookupCtx)
	if err != nil {
		return "", server.operationError(operation, classifyContextTransportError(lookupCtx, err))
	}
	if connection == nil {
		return "", server.operationError(operation, ErrConnection)
	}
	defer connection.Close()

	stopCancellationClose := context.AfterFunc(lookupCtx, func() {
		_ = connection.Close()
	})
	defer stopCancellationClose()

	deadline, _ := lookupCtx.Deadline()

	server.Connection = connection
	return server.executeQueryContext(lookupCtx, operation, query, deadline)
}

// LookupIPContext looks up one or more IP addresses using a connection owned
// by this call. The zero-value WhoisServer uses the documented defaults.
//
// The method honors context cancellation and the shorter of the context
// deadline and WhoisServer.Timeout. It is safe to call concurrently on the
// same WhoisServer when its configuration and any custom DialContext function
// are not mutated during the calls.
func (server WhoisServer) LookupIPContext(ctx context.Context, values []string) ([]WhoIs, error) {
	server = server.configured()
	query, err := server.FormatIpQuery(values)
	if err != nil {
		return nil, server.operationError("lookup IP", err)
	}

	response, err := server.executeOwnedQuery(ctx, "lookup IP", query)
	if err != nil {
		return nil, err
	}

	records, err := parseIpResponse(response)
	if err != nil {
		return nil, server.operationError("lookup IP", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, server.operationError("lookup IP", classifyTransportError(err))
	}
	return records, nil
}

// LookupRouteViewContext looks up observed routes for an ASN using a
// connection owned by this call. ASN accepts decimal digits with an optional
// case-insensitive AS prefix.
//
// It has the same context, deadline, and concurrency guarantees as
// LookupIPContext.
func (server WhoisServer) LookupRouteViewContext(ctx context.Context, asn string) (BGPRoutes, error) {
	server = server.configured()
	normalizedASN, err := normalizeASN(asn)
	if err != nil {
		return BGPRoutes{}, server.operationError("lookup RouteView", err)
	}
	query, err := server.FormatRouteViewQuery(normalizedASN)
	if err != nil {
		return BGPRoutes{}, server.operationError("lookup RouteView", err)
	}

	response, err := server.executeOwnedQuery(ctx, "lookup RouteView", query)
	if err != nil {
		return BGPRoutes{}, err
	}

	routes, err := parseBgpResponse(response)
	if err != nil {
		return BGPRoutes{}, server.operationError("lookup RouteView", err)
	}
	if err := ctx.Err(); err != nil {
		return BGPRoutes{}, server.operationError("lookup RouteView", classifyTransportError(err))
	}
	return BGPRoutes{Asn: normalizedASN, Routes: routes}, nil
}

// LookupRegistryContext looks up registry data for an ASN using a connection
// owned by this call. ASN accepts decimal digits with an optional
// case-insensitive AS prefix.
//
// It has the same context, deadline, and concurrency guarantees as
// LookupIPContext.
func (server WhoisServer) LookupRegistryContext(ctx context.Context, asn string) (RegistryRecord, error) {
	server = server.configured()
	normalizedASN, err := normalizeASN(asn)
	if err != nil {
		return RegistryRecord{}, server.operationError("lookup registry", err)
	}
	query, err := server.FormatRegistryQuery(normalizedASN)
	if err != nil {
		return RegistryRecord{}, server.operationError("lookup registry", err)
	}

	response, err := server.executeOwnedQuery(ctx, "lookup registry", query)
	if err != nil {
		return RegistryRecord{}, err
	}

	records, err := parseRegistryResponse(response)
	if err != nil {
		return RegistryRecord{}, server.operationError("lookup registry", err)
	}
	if err := ctx.Err(); err != nil {
		return RegistryRecord{}, server.operationError("lookup registry", classifyTransportError(err))
	}
	return RegistryRecord{Asn: normalizedASN, Registry: records[0]}, nil
}

// LookupNetblockContext looks up announced netblocks for an ASN using a
// connection owned by this call. ASN accepts decimal digits with an optional
// case-insensitive AS prefix.
//
// It has the same context, deadline, and concurrency guarantees as
// LookupIPContext.
func (server WhoisServer) LookupNetblockContext(ctx context.Context, asn string) (NetblockRecord, error) {
	server = server.configured()
	normalizedASN, err := normalizeASN(asn)
	if err != nil {
		return NetblockRecord{}, server.operationError("lookup netblock", err)
	}
	query, err := server.FormatNetblockQuery(normalizedASN)
	if err != nil {
		return NetblockRecord{}, server.operationError("lookup netblock", err)
	}

	response, err := server.executeOwnedQuery(ctx, "lookup netblock", query)
	if err != nil {
		return NetblockRecord{}, err
	}

	records, err := parseNetblockResponse(normalizedASN, response)
	if err != nil {
		return NetblockRecord{}, server.operationError("lookup netblock", err)
	}
	if err := ctx.Err(); err != nil {
		return NetblockRecord{}, server.operationError("lookup netblock", classifyTransportError(err))
	}
	return records[0], nil
}
