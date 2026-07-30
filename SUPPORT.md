# Support

## Usage questions

Start with the [README](README.md), [consumer integration guide](docs/consumer-agent-guide.md), and [Go package documentation](https://pkg.go.dev/github.com/georgestarcher/pwhois).

For a question or bug report, include the exact module version, Go version,
provider and endpoint, lookup type, expected result, actual result, and a
minimal synthetic reproduction. For Redis cache issues, also include the Redis
and go-redis versions, topology, TLS/ACL mode, database number, cache policy,
and non-sensitive namespace configuration. Never include the Redis URL,
credentials, or cached values.

## Project scope

This project supports native PWHOIS IP, RouteView, registry, and netblock
queries plus its documented source-specific providers. RISwhois support is
observed BGP evidence. IRR support is limited to exact route/route6 queries
against the documented allowlisted IRRd endpoints. RDAP support is limited to
the documented IANA-bootstrap IP/ASN registration provider. Generic WHOIS and
arbitrary port-43 protocols are outside its scope; changing only a server
hostname does not make them compatible.

## Sensitive data and security

Do not attach live provider responses, registry contacts, credentials, private
addresses, or rate-limit artifacts to public issues. For vulnerabilities, use
the private process in [SECURITY.md](SECURITY.md).
