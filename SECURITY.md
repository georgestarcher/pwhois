# Security policy

## Supported version

Security fixes are applied to the current released `v1` line.

## Reporting a vulnerability

Please report security issues privately through GitHub's private vulnerability
reporting for this repository. Do not open a public issue, publish a proof of
concept containing live PWHOIS data, or include credentials, contact data, or
private network information.

Include the affected module version, Go version, a synthetic or minimized
reproduction, impact, and any relevant configuration. We will acknowledge the
report and coordinate a fix or disclosure as appropriate.

## Input and network expectations

PWHOIS responses are untrusted network input. The module currently bounds
connection and lookup I/O time, but applications remain responsible for their
chosen server, timeout, rate-limit policy, data retention, and how results are
displayed or acted upon. Response-size limits are tracked in issue #32.
