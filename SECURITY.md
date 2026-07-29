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
