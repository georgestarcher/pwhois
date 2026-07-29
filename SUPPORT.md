# Support

## Usage questions

Start with the [README](README.md), [consumer integration guide](docs/consumer-agent-guide.md), and [Go package documentation](https://pkg.go.dev/github.com/georgestarcher/pwhois).

For a question or bug report, include the exact module version, Go version,
provider and endpoint, lookup type, expected result, actual result, and a minimal
synthetic reproduction.

## Project scope

This project supports native PWHOIS IP, RouteView, registry, and netblock
queries plus its documented source-specific providers. RISwhois support is
observed BGP evidence and does not make this a generic IRR client. Generic
WHOIS, IRR, and RDAP protocols are outside its current scope; changing only
the server hostname does not make them compatible.

## Sensitive data and security

Do not attach live provider responses, registry contacts, credentials, private
addresses, or rate-limit artifacts to public issues. For vulnerabilities, use
the private process in [SECURITY.md](SECURITY.md).
