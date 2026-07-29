# Security policy

## Supported version

Security fixes are applied to the current released `v1` line.

## Reporting a vulnerability

Please report security issues privately through GitHub's private vulnerability
reporting for this repository. Do not open a public issue, publish a proof of
concept containing live provider data, or include credentials, contact data,
or private network information.

Include the affected module version, Go version, a synthetic or minimized
reproduction, impact, and any relevant configuration. We will acknowledge the
report and coordinate a fix or disclosure as appropriate.

## Input and network expectations

PWHOIS and source-specific provider responses are untrusted network input. The
module bounds connection time, lookup I/O time, and response size, but
applications remain responsible for their chosen provider, privacy policy,
rate-limit policy, data retention, and how results are displayed or acted
upon. Port 43 queries are plaintext.

IRR lookups accept only the documented endpoint identifiers and reject unknown
values before dialing. A custom `ContextDialer` receives the selected
allowlisted destination and is part of the application's trust boundary.
Normalized IRR results deliberately omit raw RPSL objects and contact
attributes; do not replace them with raw provider responses in caches or logs.

RDAP lookups require HTTPS by default and follow only bounded referrals whose
authority appeared in the trusted bootstrap document. Normalized RDAP results
omit complete jCards, personal names, email addresses, telephone numbers,
postal addresses, event actors, raw JSON, and redaction paths. Do not enable
the insecure-HTTP or private-network target options for public lookups.
Public-only mode also rejects DNS results in private, reserved, documentation,
benchmarking, and other IANA special-purpose ranges at dial time, and bypasses
HTTP proxies whose remote resolution could evade that check. A custom HTTP
transport or bootstrap resolver is part of the application's trust boundary
and must not inject credentials or authorize arbitrary internal destinations.
