# sshscope

`sshscope` is a low-impact, black-box SSH security auditing CLI for authorized defensive assessments. The Phase 4 build resolves a bounded scope, tests TCP reachability, reads the SSH identification and initial KEXINIT proposal, collects concrete public host keys through controlled handshakes, and emits terminal or canonical JSON reports without credentials.

## Authorization and safety

Only scan systems you are authorized to assess. Public IP targets produce a non-interactive notice on stderr. `--authorized` and `--scope-reference` document operator intent in the report; they never bypass target limits, timeouts, connection limits, or rate controls.

The project does not implement password guessing, username enumeration, credential attacks, brute force, exploitation, authentication flooding, denial-of-service checks, Internet-wide scanning, interception, or man-in-the-middle behavior. Phase 4 performs the three Phase 3 attempts plus at most eight controlled host-key handshakes selected from the server's advertised key types. RSA signature aliases are collapsed to one key family. Every host-key handshake deliberately terminates in the verified host-key callback before any user-authentication request. Retries are disabled.

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

The direct dependencies are Cobra for CLI behavior, `golang.org/x/time/rate` for cancellation-aware global rate limiting, and `golang.org/x/crypto/ssh` for controlled SSH handshakes and OpenSSH known_hosts parsing.

## Phase 4 examples

```sh
sshscope scan example.com
sshscope scan example.com:2222
sshscope scan --targets targets.txt
sshscope scan 192.0.2.0/29 --authorized --scope-reference lab-001
sshscope scan example.com --format json --output report.json
sshscope scan example.com --known-hosts ~/.ssh/known_hosts
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
  -> TCP probe, SSH banner probe, bounded KEXINIT probe
  -> controlled host-key handshakes selected from KEX evidence
  -> evidence validation and normalization
  -> canonicalizer
  -> terminal or JSON renderer
```

Network probes collect observations and typed operational errors. They never assign severity. Policy evaluation and findings begin in Phase 6.

## Probe behavior

The TCP probe performs one connection attempt and immediately closes a successful connection. A timeout means only that the attempt timed out; it is not proof that SSH is disabled.

The banner probe opens a separate connection after TCP reachability succeeds. It reads only through the server identification line. Every line is bounded to 255 bytes, at most 20 pre-banner lines are retained, total input is capped at 8 KiB, and the operation has a deadline. Banner software text is untrusted self-identification—not verified package, patch, or backport information—and is never used to create CVE claims.

The KEX probe opens a third connection. It retains any packet bytes buffered while reading identification, sends a minimal standards-shaped client KEXINIT, and parses exactly one unencrypted server packet. Packet length is validated before allocation and capped at 64 KiB. All ten SSH name-lists are independently capped at 16 KiB and 1,024 entries; malformed framing, padding, duplicates, empty names, and trailing data are rejected. The report preserves server order for KEX, host-key, cipher, MAC, compression, and language lists, plus observable extension markers, `first_kex_packet_follows`, and the reserved field. This raw probe does not accept a host key or implement cryptography; the separate Phase 4 probe delegates its controlled handshake to `x/crypto/ssh`.

The host-key probe consumes a defensive copy of the server's advertised host-key algorithms and performs at most eight additional handshakes for distinct key families. The SSH library verifies the server's handshake signature and invokes the collection callback; sshscope records the selected algorithm, public-key type, SHA-256 fingerprint, meaningful key size, certificate state, and observable certificate-authority fingerprint, then returns a deliberate stop error before authentication. Unsupported or failed key types produce partial-probe errors without discarding keys already collected.

Without `--known-hosts`, collected keys are explicitly marked `not_checked`. With an explicitly supplied OpenSSH file, each key is classified as `match`, `mismatch`, or `new`. A mismatch is evidence for later policy evaluation, not automatic proof of interception or attack. The file is loaded once before network scanning; malformed or unreadable files fail before connections begin.

## Phase 4 report schema

JSON is the canonical report. It includes schema/tool versions, timestamps, non-secret scan settings, authorization metadata, resolved targets, ordered probe results, normalized observations, typed errors, and complete/partial/failed status. Durations use strings such as `"4ms"`. Target, observation, probe, finding, and error collections are deterministically ordered without changing server-supplied list order.

Terminal output summarizes reachability, latency, identification, advertised algorithm counts, host-key fingerprints and known_hosts states, partial-probe warnings, and finding totals. Authentication methods and policy findings are clearly marked as unavailable in Phase 4.

## Tests

```sh
make test
make test-race
make integration-test
make fuzz FUZZTIME=10s
```

The integration test binds an identification, KEXINIT, and signed SSH host-key fixture to `127.0.0.1` only. It verifies a known_hosts match and asserts that no server authentication callback runs. Fuzz targets cover identification, packet framing, name-lists, and KEXINIT payloads entirely in memory and perform no network operations.

## Known limitations

Phase 4 does not collect authentication methods and does not evaluate policy. The `--audit-user`, `--no-auth-probe`, `--policy`, and `--fail-on` settings are retained for the final interface but do not activate later-phase behavior yet. Banner, KEX, and host-key evidence come from separate connections, so conditional server configuration may vary between observations. Host-key collection is capped at eight distinct advertised key families; unsupported client algorithms and servers that change proposals between connections may yield partial evidence.

An unauthenticated external scanner cannot reliably determine root-login configuration, password strength, account-lockout policy, PAM details, full MFA behavior, authorized-key contents, patch/backport status, local file permissions, user privilege levels, or post-authentication restrictions.

Observed authentication methods, once implemented, may depend on username, source address, PAM, conditional SSH configuration, and authentication state. A future host-key change will be reported as a change or trust-file mismatch—not automatic proof of an attack.

See [IMPLEMENTATION.md](IMPLEMENTATION.md) for the phased plan and current engineering risks.
