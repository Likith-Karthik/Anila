# sshscope

`sshscope` is a low-impact, black-box SSH security auditing CLI for authorized defensive assessments. The Phase 3 build resolves a bounded scope, tests TCP reachability, reads the SSH identification exchange and the server's initial KEXINIT proposal, and emits terminal or canonical JSON reports without credentials.

## Authorization and safety

Only scan systems you are authorized to assess. Public IP targets produce a non-interactive notice on stderr. `--authorized` and `--scope-reference` document operator intent in the report; they never bypass target limits, timeouts, connection limits, or rate controls.

The project does not implement password guessing, username enumeration, credential attacks, brute force, exploitation, authentication flooding, denial-of-service checks, Internet-wide scanning, interception, or man-in-the-middle behavior. Phase 3 performs at most three sequential connection attempts per resolved endpoint: reachability, banner collection, and a bounded KEXINIT exchange. The KEX probe sends one identification string and one initial client KEXINIT, reads one server KEXINIT, and closes before cryptographic key exchange. Retries are disabled.

## Installation and development

Go 1.26 or newer is required.

```sh
make lint
make test
make test-race
make integration-test
make build
./bin/sshscope version
```

The only direct dependencies are Cobra for CLI behavior and `golang.org/x/time/rate` for cancellation-aware global rate limiting.

## Phase 3 examples

```sh
sshscope scan example.com
sshscope scan example.com:2222
sshscope scan --targets targets.txt
sshscope scan 192.0.2.0/29 --authorized --scope-reference lab-001
sshscope scan example.com --format json --output report.json
```

The default safety settings are 10 workers, three active connections per resolved IP, five connection starts per second, a ten-second target deadline, a four-second operation timeout, no retries, and at most 256 resolved targets. Non-bypassable ceilings cap those settings at 64 workers, 16 per-host connections, 1,000 starts per second, five minutes per target, one minute per operation, and 4,096 targets. CIDRs are rejected before expansion if they exceed the remaining scope. Target files are limited to 1 MiB and 4 KiB per line.

Use `sshscope scan --help` for the current flag reference. `report`, `compare`, and `policy validate` remain unavailable until their implementation phases.

## Architecture

```text
Cobra CLI
  -> target parser and bounded target-file reader
  -> CIDR scope validator and DNS resolver
  -> bounded scan worker pool
  -> shared rate/per-host connection gate
  -> TCP probe, SSH banner probe, then bounded KEXINIT probe
  -> evidence validation and normalization
  -> canonicalizer
  -> terminal or JSON renderer
```

Network probes collect observations and typed operational errors. They never assign severity. Policy evaluation and findings begin in Phase 6.

## Probe behavior

The TCP probe performs one connection attempt and immediately closes a successful connection. A timeout means only that the attempt timed out; it is not proof that SSH is disabled.

The banner probe opens a separate connection after TCP reachability succeeds. It reads only through the server identification line. Every line is bounded to 255 bytes, at most 20 pre-banner lines are retained, total input is capped at 8 KiB, and the operation has a deadline. Banner software text is untrusted self-identification—not verified package, patch, or backport information—and is never used to create CVE claims.

The KEX probe opens a third connection. It retains any packet bytes buffered while reading identification, sends a minimal standards-shaped client KEXINIT, and parses exactly one unencrypted server packet. Packet length is validated before allocation and capped at 64 KiB. All ten SSH name-lists are independently capped at 16 KiB and 1,024 entries; malformed framing, padding, duplicates, empty names, and trailing data are rejected. The report preserves server order for KEX, host-key, cipher, MAC, compression, and language lists, plus observable extension markers, `first_kex_packet_follows`, and the reserved field. No host key is accepted and no cryptographic primitive or key exchange is implemented in this phase.

## Phase 3 report schema

JSON is the canonical report. It includes schema/tool versions, timestamps, non-secret scan settings, authorization metadata, resolved targets, ordered probe results, normalized observations, typed errors, and complete/partial/failed status. Durations use strings such as `"4ms"`. Target, observation, probe, finding, and error collections are deterministically ordered without changing server-supplied list order.

Terminal output summarizes reachability, latency, identification, advertised KEX and host-key algorithm counts, partial-probe warnings, and finding totals. Concrete host keys, authentication methods, and policy findings are clearly marked as unavailable in Phase 3.

## Tests

```sh
make test
make test-race
make integration-test
make fuzz FUZZTIME=10s
```

The integration test binds an identification-and-KEXINIT fixture to `127.0.0.1` only. Fuzz targets cover identification, packet framing, name-lists, and KEXINIT payloads entirely in memory and perform no network operations.

## Known limitations

Phase 3 does not collect concrete host keys or authentication methods and does not evaluate policy. The `--audit-user`, `--no-auth-probe`, `--known-hosts`, `--policy`, and `--fail-on` settings are retained for the final interface but do not activate later-phase behavior yet. Banner and KEX evidence come from separate connections and a server may vary its response by connection or client identification.

An unauthenticated external scanner cannot reliably determine root-login configuration, password strength, account-lockout policy, PAM details, full MFA behavior, authorized-key contents, patch/backport status, local file permissions, user privilege levels, or post-authentication restrictions.

Observed authentication methods, once implemented, may depend on username, source address, PAM, conditional SSH configuration, and authentication state. A future host-key change will be reported as a change or trust-file mismatch—not automatic proof of an attack.

See [IMPLEMENTATION.md](IMPLEMENTATION.md) for the phased plan and current engineering risks.
