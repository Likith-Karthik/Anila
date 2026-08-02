# sshscope implementation plan

## Scope and assumptions

- The repository began empty; `github.com/sshscope/sshscope` is the provisional module path until a hosting location is selected.
- Go 1.26 is the baseline. Go 1.26.5 was the current stable release when Phase 1 began.
- The scanner is authorized-use defensive software. Authorization metadata documents operator intent and never disables safety limits.
- One logical target is one resolved IP and port. DNS names that resolve to multiple addresses may therefore produce multiple target results, still subject to the global maximum.
- CIDR expansion is bounded before allocation, and DNS resolution applies the same target limit incrementally while deduplicating resolved IP-and-port endpoints.
- Server algorithm order is evidence and must be preserved. Comparison code may create sorted copies but may not mutate observations.
- Probe packages collect facts and typed operational errors only. Security severity is exclusively a policy concern.
- No probe retries are supported initially. A future retry option would require a separate safety review.
- The default global connection-start rate is five per second. Unlike concurrency, it cannot be set to zero to disable the safety control.
- Cobra is the sole Phase 1 dependency because the requested command tree and validation benefit from its mature flag/usage handling. YAML and SSH dependencies are deferred until code uses them.
- Phase 2 adds `golang.org/x/time/rate` for cancellation-aware connection-start limiting with no custom timing goroutine. YAML remains deferred. Phase 3 deliberately does not add `x/crypto/ssh` because its public API does not expose the complete ordered peer KEXINIT proposal; it remains the intended dependency for suitable later handshake work.

## Dependency direction

```text
cmd -> cli -> app
             |-> target -> config
             |-> probe -> target, evidence
             |-> policy -> evidence, finding
             `-> report -> config, target, probe, evidence, finding
```

Presentation must not be imported by application or domain packages. Network probes must not import policy or reporting packages.

## Architectural decisions

1. `net/netip` represents resolved addresses and produces unambiguous IPv6 endpoints.
2. Observation values use a closed discriminated union rather than `map[string]any`. New evidence shapes require an explicit model change.
3. Canonical report data and renderers are separate. JSON remains the source of truth; terminal output is a view.
4. Probe results retain partial observations alongside typed errors and an explicit completion status.
5. Operational error causes are retained for logging/debugging but excluded from serialized reports.
6. Scan configuration contains no credentials. `known_hosts` is an explicit comparison input, not silent trust bypass.
7. CLI commands that belong to later phases fail explicitly during Phase 1. Only command structure, validation, help, and `version` are currently functional.
8. Equality policy operands are typed string, boolean, or finite-number scalars. The Phase 6 YAML loader will translate compact YAML scalars into that model.
9. Canonical report collections are slices, not maps. A canonicalizer must sort copies and preserve raw SSH server-preference lists.
10. Durations are encoded as Go duration strings in canonical JSON rather than implementation-dependent nanosecond counts.
11. An omitted `--policy` selects an embedded default policy once Phase 6 provides it; the installed binary must not depend on its current working directory.
12. Authorization metadata is invocation context, not scan behavior. It travels separately in `app.ScanRequest` and is serialized once at the report root.
13. TCP reachability and identification use separate, sequential connections. Banner collection is skipped after a failed TCP probe to avoid a predictably unproductive second attempt.
14. The identification reader allows at most 255 bytes per line, 20 pre-banner lines, and 8 KiB total, and stops immediately after the SSH identification line.
15. User-configurable safety values have non-bypassable ceilings: 64 workers, 16 active connections per host, 1,000 starts per second, 4,096 targets, a five-minute target timeout, and a one-minute operation timeout.
16. Report files are written through a same-directory temporary file with mode `0600`, synced, and atomically renamed.
17. The Phase 3 raw transport surface is limited to unencrypted packet framing and KEXINIT name-list decoding. It does not implement key exchange, ciphers, MACs, host-key acceptance, or authentication.
18. Initial packets are validated before allocation, capped at 64 KiB, and checked for minimum length, eight-byte alignment, padding bounds, and a non-empty payload. Each name-list is capped at 16 KiB and 1,024 unique names.
19. KEX collection uses a separate connection, sends one minimal client KEXINIT, reads exactly one server KEXINIT, preserves every server-supplied list order, and closes before negotiation continues.

## Phased delivery

### Phase 1 — Repository and design (complete)

- [x] Inspect the repository and toolchain.
- [x] Record assumptions and architectural decisions.
- [x] Define typed configuration, target, observation, finding, report, and comparison models.
- [x] Define loader, parser, resolver, scope, probe, normalizer, evaluator, scanner, comparer, and renderer interfaces.
- [x] Create the complete Cobra command skeleton and conservative flag defaults.
- [x] Add validation and basic table-driven tests.
- [x] Format, vet, test, race-test, and build.

#### Phase 1 consistency review

- [x] Separate authorization metadata from operational scan configuration.
- [x] Make resolved-target limits explicit in the resolver contract so DNS expansion cannot bypass the CIDR limit.
- [x] Replace string-only comparison changes with typed change models.
- [x] Replace report maps with ordered slices and define a copy-before-sort canonicalizer contract.
- [x] Encode configuration and probe durations as portable strings in JSON.
- [x] Add typed boolean, string, and numeric equality operands for future policy loading.
- [x] Validate observation unions, host-key trust states, finding provenance, probe statuses/errors, and report composition.
- [x] Carry documented exit codes through a CLI-only error wrapper.

### Phase 2 — TCP and banner scanning (complete)

- [x] Implement target parsing, bounded target-file loading, DNS resolution, CIDR expansion, endpoint deduplication, and public-IP detection.
- [x] Implement bounded workers, per-host connection gates, per-target deadlines, operation deadlines, and global rate limiting.
- [x] Implement single-attempt TCP reachability and bounded SSH identification collection with typed errors.
- [x] Preserve partial probe and resolution evidence through normalization and scan status aggregation.
- [x] Implement initial deterministic JSON and terminal renderers plus private atomic file output.
- [x] Wire `scan`, authorization metadata, public-scope notices, output selection, and signal cancellation.
- [x] Add table-driven parser/probe/scheduler/report tests, banner fixtures, an in-memory fuzz target, and loopback-only integration coverage.
- [x] Run formatting, vet, unit/integration tests, race tests, fuzzing, and a release-style build.

### Phase 3 — KEXINIT collection (complete)

- [x] Confirm and document whether `x/crypto/ssh` exposes the complete server proposal.
- [x] Add the minimal bounded raw transport parser if necessary.
- [x] Wire a pre-cryptographic KEXINIT probe into the ordered scan pipeline and reporting.
- [x] Test and fuzz packet framing, name-lists, KEXINIT parsing, buffered identification handoff, and the loopback probe exchange.

#### Phase 3 library investigation

The current [`golang.org/x/crypto/ssh` public API](https://pkg.go.dev/golang.org/x/crypto/ssh) exposes negotiated algorithms through `NegotiatedAlgorithms`/`AlgorithmsConnMetadata` and limited negotiation failure details through `AlgorithmNegotiationError`. It does not expose all ten ordered name-lists, the peer cookie, `first_kex_packet_follows`, or the reserved field from the server's raw proposal. The package's own [`kexInitMsg` definition](https://go.googlesource.com/crypto/+/master/ssh/messages.go) is unexported. Phase 3 therefore uses a minimal bounded parser for only the pre-encryption packet and SSH_MSG_KEXINIT structures; it does not reproduce SSH cryptography.

### Phase 4 — Host keys

- [ ] Collect host keys through controlled handshakes.
- [ ] Calculate fingerprints and meaningful key sizes.
- [ ] Implement explicit `known_hosts` match/mismatch/unknown states.

### Phase 5 — Authentication surface

- [ ] Perform exactly one `none` authentication observation for one configured audit username.
- [ ] Record advertised methods and document conditional behavior.

### Phase 6 — Policy engine

- [ ] Add strict YAML loading and schema/semantic validation.
- [ ] Implement leaf, numeric, and compound match operators.
- [ ] Add the configurable default policy and finding tests.

### Phase 7 — Reporting and comparison

- [ ] Finalize deterministic JSON and terminal output.
- [ ] Implement thresholds, documented exit behavior, report loading, and semantic comparison.
- [ ] Add golden and determinism tests.

### Phase 8 — Hardening and release

- [ ] Audit all bounds, deadlines, cancellation paths, and goroutine ownership.
- [ ] Run race and fuzz suites, review licenses and documentation, and build release artifacts.
- [ ] Complete loopback-only Docker integration fixtures and commands.

## Known limitations

- Phase 3 collects advertised KEXINIT algorithms but not concrete host keys, authentication methods, or policy findings.
- `report`, `compare`, and `policy validate` intentionally return a phase-pending error. Later-phase scan flags are recorded but do not activate unavailable probes or policy evaluation.
- The module path is provisional.
- Initial canonical sorting and deterministic JSON are implemented, but schema finalization and golden compatibility enforcement remain Phase 7 work.
- Compact YAML scalar decoding and full one-operator-per-condition validation remain Phase 6 work.
- `net.Resolver` materializes the operating system resolver's answer before returning it; sshscope caps all retained and copied address slices, but cannot impose an internal allocation limit on the platform resolver itself.
- Docker-based multi-configuration OpenSSH fixtures remain later integration-hardening work; Phase 3 uses a loopback-only identification-and-KEXINIT protocol fixture.
- A banner is untrusted self-identification and cannot establish package, patch, or backport status. A timeout establishes only that one bounded attempt timed out.
- Banner and KEXINIT observations come from separate connections; conditional server configuration or connection-specific behavior can make them differ.
- The ambient development shell has no Go binary on `PATH`; local verification currently uses a checksum-verified temporary Go 1.26.5 toolchain.
