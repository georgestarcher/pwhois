## Summary

Describe the consumer problem and the implemented solution.

## Change type

- [ ] Bug fix
- [ ] Additive feature
- [ ] Breaking API change
- [ ] Documentation or tooling
- [ ] Dependency update

## Public API and behavior

- [ ] Exported API or JSON changes are intentional and documented.
- [ ] Connection ownership, cleanup, timeout, and rate-limit behavior were considered.
- [ ] Untrusted-response handling and response-size impact were considered.
- [ ] The change does not imply generic WHOIS, IRR, RDAP, or alternative-server compatibility without tests.

## Validation

- [ ] `go test ./...`, `go vet ./...`, and `go build ./...` pass.
- [ ] `go test -race ./...` passes when concurrency or network behavior changed.
- [ ] New or changed public behavior has deterministic tests.
- [ ] README and documentation are updated when needed.
- [ ] Changelog or release impact is noted for user-facing changes.

## Data and review

- [ ] No live/private PWHOIS responses, registry contacts, credentials, or local paths are included.
- [ ] Commits are signed, `@codex review` has completed, actionable threads are resolved, and CI is green.
