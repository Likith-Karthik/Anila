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
- Cobra is the sole Phase 1 dependency because the requested command tree and validation benefit from its mature flag/usage handling. Later phases add only `x/time/rate`, `x/crypto/ssh`, and `yaml.v3` at the points where they are used.
- Phase 2 adds `golang.org/x/time/rate` for cancellation-aware connection-start limiting with no custom timing goroutine. YAML remains deferred. Phase 3 deliberately does not use `x/crypto/ssh` for raw KEXINIT because its public API does not expose the complete ordered proposal. Phase 4 adds `golang.org/x/crypto/ssh` for controlled signed handshakes and its `knownhosts` package for explicit trust-file comparison.

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
19. KEX collection uses a separate connection, sends one minimal client KEXINIT, accepts only structurally valid and count/byte-bounded `SSH_MSG_IGNORE` or `SSH_MSG_DEBUG` messages before the server KEXINIT, preserves every server-supplied list order, and closes before negotiation continues.
20. Evidence-dependent probes receive defensive copies of earlier observations through an optional probe interface; the base probe contract remains usable by independent collectors.
21. Host-key collection selects distinct key families from observed KEXINIT evidence, caps collection at eight handshakes per endpoint, and deliberately aborts from the verified host-key callback before user authentication.
22. A missing known_hosts input is recorded as `not_checked`. An explicitly supplied bounded snapshot produces `match`, `mismatch`, `new`, or `revoked`; none of these evidence states controls handshake acceptance or attributes malicious intent.
23. The Phase 5 authentication connection is pinned to a SHA-256 fingerprint collected during Phase 4. A changed key stops the connection before user authentication.
24. The SSH client's initial `none` request is the only authentication attempt. Its post-failure callback copies the server's ordered allowed-method list and returns a sentinel error; no credential-bearing `AuthMethod` is configured.
25. If `none` succeeds, a dedicated Boolean fact records acceptance independently of the server-supplied allowed-method list, and the authenticated transport is immediately closed without opening a channel. `--no-auth-probe` omits the probe and its connection entirely.
26. Policy YAML is capped at 1 MiB, decoded with known-field enforcement, rejects aliases and multiple documents, and applies depth, node, rule, condition, string, and reference bounds before evaluation.
27. Policy fields use a closed registry over normalized observation IDs and explicit host-key projections. The immutable engine is safe for concurrent target evaluation and findings always retain evidence provenance, including explicit absence provenance for absence-based rules.
28. The default policy is YAML embedded into the executable and can be replaced per invocation with `--policy`. Policy loading and compilation complete before target resolution or network activity; finding-based exit enforcement remains a Phase 7 responsibility.
29. Canonical report schema version `1` is loaded through a 64 MiB bounded, single-value, unknown-field-rejecting JSON decoder. Loaded reports undergo the same structural, target-count, uniqueness, provenance, and domain validation as newly generated reports.
30. Canonicalization sorts copied report collections, concrete host keys, finding evidence, references, and affected values while preserving every server-ordered algorithm list. A checked-in golden report fixes the version-1 wire representation.
31. Finding thresholds are evaluated only after report output succeeds. A failed scan takes precedence with exit 3; otherwise `critical`, `high`, and `medium` include findings at or above that severity, while `never` disables finding exits. Re-rendering a saved report reproduces the same outcome.
32. Report comparison keys targets by resolved endpoint, findings by rule ID, and algorithm/authentication lists by set membership. Host-key identity drift is separated from known_hosts comparison-state drift. Missing observations are treated as incomplete evidence rather than removals; banner and host-key changes are described without malicious attribution.
33. Established connections are bound to their operation context with both an absolute deadline and a cancellation callback that wakes blocked I/O. The callback is stopped before normal connection close, and the worker pool joins every worker before returning.
34. Explicit target-list, policy, saved-report, and known_hosts inputs are regular files with pre-parse size checks, while the target, policy, and report parsers retain independent streaming or allocation bounds. Terminal renderers escape untrusted control and bidirectional-formatting characters.
35. Release output is a version-injected, CGO-disabled matrix for macOS, Linux, and Windows on amd64 and arm64, accompanied by checksums, first-party documentation, dependency notices, and the complete pinned dependency license texts.
36. Docker integration publishes modern and deliberately legacy OpenSSH fixtures only on `127.0.0.1`, uses an internal container network, performs no credential-bearing authentication, and owns cleanup of containers, volumes, and temporary reports.
37. Known observation IDs have a fixed value shape and probe provenance. Report and probe completion states must agree with their contained errors and meaningful results, preventing malformed saved data from overstating scan completeness.
38. Programmatic target, probe-pipeline, prior-evidence, policy-evaluation, report, finding, and nested observation inputs retain independent cardinality and byte bounds even when callers bypass the CLI's file limits.

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

### Phase 4 — Host keys (complete)

- [x] Collect host keys through controlled handshakes.
- [x] Calculate fingerprints and meaningful key sizes.
- [x] Implement explicit `known_hosts` match/mismatch/new/revoked states.

#### Phase 4 handshake boundary

Phase 4 uses [`ssh.NewClientConn`](https://pkg.go.dev/golang.org/x/crypto/ssh#NewClientConn) only until its [`HostKeyCallback`](https://pkg.go.dev/golang.org/x/crypto/ssh#HostKeyCallback) receives a signature-verified server key. The callback records the key and returns a sentinel error, ending the connection before the client requests user authentication. OpenSSH trust files are parsed by [`ssh/knownhosts`](https://pkg.go.dev/golang.org/x/crypto/ssh/knownhosts); `KeyError.Want` distinguishes a new host from a differing stored key, while `RevokedError` remains a separate operator-supplied trust state.

### Phase 5 — Authentication surface (complete)

- [x] Perform exactly one `none` authentication observation for one configured audit username.
- [x] Record advertised methods and document conditional behavior.

#### Phase 5 observation boundary

The current [`ssh.ClientAuthCallback`](https://pkg.go.dev/golang.org/x/crypto/ssh#ClientAuthCallback) is invoked after the library's initial `none` request and exposes cloned `AllowedMethods`, `TriedMethods`, and partial-success state through [`ssh.ClientAuthContext`](https://pkg.go.dev/golang.org/x/crypto/ssh#ClientAuthContext). Phase 5 requires `TriedMethods` to be exactly `[none]`, copies the bounded allowed list, and returns an error immediately. No password, signer, keyboard-interactive callback, GSSAPI client, agent, or other authentication method is configured.

### Phase 6 — Policy engine (complete)

- [x] Add strict YAML loading and schema/semantic validation.
- [x] Implement leaf, numeric, and compound match operators.
- [x] Add the configurable default policy and finding tests.

#### Phase 6 policy boundary

Policies are versioned YAML documents whose conditions reference only registered normalized observation fields. Exactly one operator is permitted per condition. Regexes are compiled once when the immutable engine is constructed, and custom-policy failures stop the command before DNS or network work. The embedded default ruleset covers protocol 1, legacy/SHA-1 algorithms, CBC and obsolete ciphers, weak host keys and MACs, small RSA keys, `none`, contextual password exposure, explicit known_hosts mismatch, and informational banner disclosure without making CVE claims.

### Phase 7 — Reporting and comparison (complete)

- [x] Finalize deterministic JSON and terminal output.
- [x] Implement thresholds, documented exit behavior, report loading, and semantic comparison.
- [x] Add golden and determinism tests.

#### Phase 7 report and comparison boundary

JSON schema version `1` is the canonical persistent representation. Terminal output is a deterministic view with findings grouped by severity, complete severity totals, partial-result warnings, and the applicable exit explanation. `report` strictly loads and re-renders saved JSON; `compare` reports target, host-key identity, known_hosts state, algorithm, finding, severity, authentication-method, and banner changes. Comparison is conservative when either report lacks an observation and ignores server-list order when calculating additions and removals.

### Phase 8 — Hardening and release (complete)

- [x] Audit all bounds, deadlines, cancellation paths, and goroutine ownership.
- [x] Run race and fuzz suites, review licenses and documentation, and build release artifacts.
- [x] Complete loopback-only Docker integration fixtures and commands.

#### Phase 8 hardening and release boundary

All application-owned input retention, packet parsing, target expansion, worker concurrency, connection starts, per-host connections, target lifetimes, and network-operation lifetimes have explicit limits. Established connections now wake on context cancellation as well as absolute deadlines, cancellation callbacks are stopped or joined before teardown, and the worker pool joins every production goroutine. Explicit local inputs are regular files with format-specific size caps, and untrusted report/network text is escaped in terminal views.

The release target builds version-injected, CGO-disabled binaries for macOS, Linux, and Windows on amd64 and arm64, generates SHA-256 checksums, and bundles first- and third-party notices plus the complete reviewed dependency license texts. The race suite and all five in-memory fuzz targets passed. The modern/legacy Docker fixtures, shell syntax, loopback port publication, internal network, no-credential behavior, cleanup, and expected policy assertions are covered by integration tests. The Phase 8 development host did not provide Docker or a compatible container runtime, so the container command's live execution remains a release-CI verification requirement rather than an implementation gap.

## Defensive review — 2026-08-04

The repository-wide defensive review confirmed and fixed the following issues:

- KEXINIT construction now rejects oversized programmatic name-lists before joining or allocating them, and packet framing rejects oversized payloads before integer arithmetic.
- The raw KEX reader now handles the transport messages permitted before KEXINIT without assuming the next packet must be KEXINIT, while enforcing strict structure, count, aggregate-byte, packet, and deadline bounds.
- Target/specification collections, DNS filtering, probe pipelines, evidence-dependent probe inputs, policy aggregation, observations, host keys, findings, errors, and loaded report structures now have independent bounds. Known observation IDs also enforce their value kind and producing probe.
- Policy loading performs a linear preflight before YAML scalar resolution and node construction, rejecting pathological numeric runs, line counts, and preliminary flow nesting. The policy fuzz target runs with one worker so a slow parser case cannot multiply CPU pressure across the host.
- Nested JSON union members reject unknown fields, known observation domains are checked, and report/probe/target completion statuses cannot claim completeness when their errors or child results contradict it.
- `@revoked` known_hosts entries are distinct from mismatches. The input is read through a bounded descriptor and parsed from a private snapshot, avoiding path replacement between inspection and parsing.
- Comparison now distinguishes an unchanged host key whose known_hosts state changed from an actual key-identity change. Terminal output also escapes probe names and units in addition to previously escaped untrusted fields.
- The default policy matches a dedicated successful-`none` Boolean rather than trusting the server-supplied method list, narrows its claim to one username/connection, and describes legacy MAC exposure without implying a successful cryptographic attack. Banner and password findings retain explicit non-vulnerability caveats.

Verification on this host passed `gofmt`, `go vet ./...`, `staticcheck`, `go test -count=1 ./...`, `go test -race -count=1 ./...`, `go mod verify`, `govulncheck`, the release-style local build, the loopback integration package, and all five configured fuzz targets for ten seconds each. `govulncheck` found no reachable symbol or imported-package vulnerabilities; it reported the known module-level `x/crypto/openpgp` advisory, but sshscope does not import that package and the advisory has no fixed version. The Docker/Compose OpenSSH fixture could not be executed because no compatible container runtime was installed. The operating-system resolver still materializes its answer before sshscope can filter it, and upstream standard-library/`x/crypto/ssh` cryptographic parsing and allocations remain bounded only through those packages' public APIs and the enclosing connection deadline.

## Known limitations

- Finding thresholds, saved-report rendering, and semantic comparison are implemented. Comparison output is terminal-only in schema version `1`; a machine-readable comparison schema has not been committed.
- The module path is provisional.
- `net.Resolver` materializes the operating system resolver's answer before returning it; sshscope caps all retained and copied address slices, but cannot impose an internal allocation limit on the platform resolver itself.
- The standard library and `x/crypto/ssh` own internal DNS and cryptographic-handshake allocations; sshscope bounds the inputs and lifetimes exposed through their public APIs but cannot independently cap every internal allocation.
- Release artifacts are checksummed but unsigned, contain no SBOM, and are not guaranteed bit-for-bit reproducible across Go toolchain versions. The Docker test base image is version-tagged rather than digest-pinned.
- Docker integration requires a local Docker daemon and Compose plugin; the in-process integration suite remains available without Docker.
- A banner is untrusted self-identification and cannot establish package, patch, or backport status. A timeout establishes only that one bounded attempt timed out.
- Banner and KEXINIT observations come from separate connections; conditional server configuration or connection-specific behavior can make them differ.
- Host-key collection is capped at eight distinct advertised key families. Algorithms unsupported by the current SSH client or keys omitted from a changed per-connection proposal are reported as partial evidence.
- Authentication methods are conditional observations for one username, source, and initial state. Methods available only after partial success are intentionally not exercised or reported.
- The embedded default policy is a conservative baseline, not a substitute for organization-specific cryptographic, trust, and authentication requirements. Custom policies replace rather than merge with that baseline.
- Comparisons intentionally do not report removals when one side lacks the relevant observation; this prevents incomplete scans from being presented as configuration changes but can hide drift until both reports contain comparable evidence.
- The ambient development shell has no Go binary on `PATH`; local verification currently uses a checksum-verified temporary Go 1.26.5 toolchain.
