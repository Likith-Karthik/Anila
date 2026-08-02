# sshscope

`sshscope` is a low-impact, black-box SSH security auditing CLI for authorized defensive assessments. The Phase 7 build resolves a bounded scope, collects SSH transport, host-key, and optional authentication-surface evidence, evaluates a strict configurable policy, emits deterministic reports, and compares saved results without credentials.

## Authorization and safety

Only scan systems you are authorized to assess. Public IP targets produce a non-interactive notice on stderr. `--authorized` and `--scope-reference` document operator intent in the report; they never bypass target limits, timeouts, connection limits, or rate controls.

The project does not implement password guessing, username enumeration, credential attacks, brute force, exploitation, authentication flooding, denial-of-service checks, Internet-wide scanning, interception, or man-in-the-middle behavior. Phase 5 performs the three initial attempts, at most eight host-key handshakes selected from advertised key types, and at most one authentication connection per endpoint. That final connection sends exactly one standard `none` request for one configured audit username and stops before any credential-bearing method. `--no-auth-probe` omits it entirely. Retries are disabled.

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

The direct dependencies are Cobra for CLI behavior, `golang.org/x/time/rate` for cancellation-aware global rate limiting, `golang.org/x/crypto/ssh` for controlled SSH handshakes and OpenSSH known_hosts parsing, and `gopkg.in/yaml.v3` for strict policy decoding.

## Phase 7 examples

```sh
sshscope scan example.com
sshscope scan example.com:2222
sshscope scan --targets targets.txt
sshscope scan 192.0.2.0/29 --authorized --scope-reference lab-001
sshscope scan example.com --format json --output report.json
sshscope scan example.com --known-hosts ~/.ssh/known_hosts
sshscope scan example.com --audit-user sshscope-audit
sshscope scan example.com --no-auth-probe
sshscope scan example.com --policy organization-policy.yaml
sshscope scan example.com --fail-on medium
sshscope policy validate organization-policy.yaml
sshscope report report.json
sshscope report report.json --format json --output canonical.json
sshscope compare previous.json current.json
```

The default safety settings are 10 workers, three active connections per resolved IP, five connection starts per second, a ten-second target deadline, a four-second operation timeout, no retries, and at most 256 resolved targets. Non-bypassable ceilings cap those settings at 64 workers, 16 per-host connections, 1,000 starts per second, five minutes per target, one minute per operation, and 4,096 targets. CIDRs are rejected before expansion if they exceed the remaining scope. Target files are limited to 1 MiB and 4 KiB per line.

Use `sshscope scan --help` for the current flag reference. Finding thresholds support `critical`, `high`, `medium`, and `never`.

## Architecture

```text
Cobra CLI
  -> target parser and bounded target-file reader
  -> CIDR scope validator and DNS resolver
  -> bounded scan worker pool
  -> shared rate/per-host connection gate
  -> TCP probe, SSH banner probe, bounded KEXINIT probe
  -> controlled host-key handshakes selected from KEX evidence
  -> optional single none-authentication observation pinned to collected key
  -> evidence validation and normalization
  -> immutable policy evaluation and evidence-linked findings
  -> canonicalizer
  -> terminal or JSON renderer
```

Network probes collect observations and typed operational errors. They never assign severity; only policy rules create findings.

## Probe behavior

The TCP probe performs one connection attempt and immediately closes a successful connection. A timeout means only that the attempt timed out; it is not proof that SSH is disabled.

The banner probe opens a separate connection after TCP reachability succeeds. It reads only through the server identification line. Every line is bounded to 255 bytes, at most 20 pre-banner lines are retained, total input is capped at 8 KiB, and the operation has a deadline. Banner software text is untrusted self-identification—not verified package, patch, or backport information—and is never used to create CVE claims.

The KEX probe opens a third connection. It retains any packet bytes buffered while reading identification, sends a minimal standards-shaped client KEXINIT, and parses exactly one unencrypted server packet. Packet length is validated before allocation and capped at 64 KiB. All ten SSH name-lists are independently capped at 16 KiB and 1,024 entries; malformed framing, padding, duplicates, empty names, and trailing data are rejected. The report preserves server order for KEX, host-key, cipher, MAC, compression, and language lists, plus observable extension markers, `first_kex_packet_follows`, and the reserved field. This raw probe does not accept a host key or implement cryptography; the separate Phase 4 probe delegates its controlled handshake to `x/crypto/ssh`.

The host-key probe consumes a defensive copy of the server's advertised host-key algorithms and performs at most eight additional handshakes for distinct key families. The SSH library verifies the server's handshake signature and invokes the collection callback; sshscope records the selected algorithm, public-key type, SHA-256 fingerprint, meaningful key size, certificate state, and observable certificate-authority fingerprint, then returns a deliberate stop error before authentication. Unsupported or failed key types produce partial-probe errors without discarding keys already collected.

Without `--known-hosts`, collected keys are explicitly marked `not_checked`. With an explicitly supplied OpenSSH file, each key is classified as `match`, `mismatch`, or `new`. A mismatch is evidence for later policy evaluation, not automatic proof of interception or attack. The file is loaded once before network scanning; malformed or unreadable files fail before connections begin.

The authentication probe opens one final connection only when enabled. It pins that connection to a SHA-256 host-key fingerprint collected by the preceding probe, requests SSH user authentication, sends the protocol's initial `none` method for `--audit-user`, copies the first advertised method list, and aborts through the SSH client's authentication callback. Its authentication-method list is deliberately empty, so no password, public key, keyboard-interactive response, GSSAPI token, or other credential can be submitted. If a server accepts `none`, the observation is recorded as `none` and the connection is closed without opening a channel.

## Policy format

An omitted `--policy` uses the versioned YAML ruleset embedded in the executable. A custom file replaces that default for the invocation and is loaded, bounded, validated, and compiled before target resolution or network activity. Policy files are limited to 1 MiB, one YAML document, 1,024 rules, bounded condition trees, and known schema fields; aliases and unknown observation fields are rejected.

Each condition has exactly one operator. Supported operators are `equals`, `not_equals`, `contains`, `contains_any`, `contains_all`, `prefix`, `suffix`, `regex`, `exists`, `not_exists`, `greater_than`, `at_least`, `less_than`, `at_most`, `all`, `any`, and `not`. Equality operands retain YAML string, Boolean, or numeric types. String-list membership is exact; `contains` on a scalar string is substring matching. Regexes use Go's RE2 syntax.

```yaml
version: 1
rules:
  - id: ORG-KEX-001
    title: Disallowed key exchange offered
    severity: high
    confidence: high
    description: The server offered an algorithm disallowed by organizational policy.
    match:
      field: ssh.kex.algorithms
      contains_any: [diffie-hellman-group1-sha1]
    recommendation: Remove the disallowed algorithm from the server configuration.
```

To add a rule, copy this shape, choose a unique whitespace-free ID, reference a normalized field emitted in JSON, select one type-compatible operator, and run `sshscope policy validate POLICY.yaml`. The embedded baseline covers SSH version 1, legacy and SHA-1 algorithms, CBC and obsolete ciphers, weak host keys and MACs, small RSA keys, `none`, contextual password exposure, explicit known_hosts mismatch, and informational banner disclosure. It deliberately makes no banner-derived CVE claims and treats observed password authentication as context rather than an inherent vulnerability.

## Phase 7 report schema and exits

JSON schema version `1` is the canonical report. It includes schema/tool versions, timestamps, non-secret scan settings, authorization metadata, resolved targets, ordered probe results, normalized observations, findings, typed errors, and complete/partial/failed status. Durations use strings such as `"4ms"`. Target, observation, probe, concrete host-key, finding, evidence-reference, and error collections are deterministically ordered without changing server-supplied algorithm preference lists.

Saved reports are limited to 64 MiB and loaded with unknown-field rejection, single-JSON-value enforcement, schema and domain validation, duplicate endpoint/observation/finding checks, and finding-evidence provenance validation. `sshscope report` renders a saved report as terminal output or canonical JSON.

Terminal output summarizes collected evidence, groups findings by severity, includes recommendations and affected values, reports severity totals, and explains the applicable process result:

- `0`: the scan completed meaningfully and no finding met the configured threshold.
- `1`: at least one finding met the configured threshold.
- `2`: command, configuration, policy, or report input was invalid.
- `3`: the scan or output operation could not be meaningfully completed.
- `130`: execution was interrupted.

Failed-scan exit 3 takes precedence over findings. Output is written before a finding-related exit 1 is returned, so automation can retain the report that explains the failure. `sshscope report` reproduces the saved report's threshold outcome.

## Report comparison

`sshscope compare OLD.json NEW.json` shows added and removed targets, host-key changes, added and removed algorithms, new and resolved findings, finding-severity changes, authentication-method changes, and banner changes. Targets are matched by resolved endpoint; algorithm and authentication lists are compared as sets, so server preference reordering alone is not reported as an addition or removal.

When either report lacks a relevant observation, comparison does not claim that values were removed. Banner text remains untrusted self-identification, and host-key changes are reported as changes rather than automatic evidence of an attack.

## Tests

```sh
make test
make test-race
make integration-test
make fuzz FUZZTIME=10s
```

The integration test binds an identification, KEXINIT, signed host-key, and authentication fixture to `127.0.0.1` only. It verifies a known_hosts match, exactly one `none` attempt for the configured audit username, ordered method collection, zero credential callbacks, expected embedded-policy findings, saved-report rendering, and a no-change comparison. Golden and shuffled-input tests protect deterministic schema-version-1 JSON. Fuzz targets cover identification, packet framing, name-lists, KEXINIT payloads, and policy YAML entirely in memory and perform no network operations.

## Known limitations

Custom policies replace rather than merge with the embedded baseline. The baseline is conservative and cannot express every organization's cryptographic, trust, or authentication requirements. Comparison output is currently terminal-only; there is no committed machine-readable comparison schema.

Banner, KEX, host-key, and authentication evidence come from separate connections, so conditional server configuration may vary between observations. Host-key collection is capped at eight distinct advertised key families; unsupported client algorithms and servers that change proposals between connections may yield partial evidence.

Observed authentication methods are only the server's response to the first `none` request for one username, source address, and connection state. They may vary with `Match` rules, PAM, account state, source restrictions, or username, and they do not reveal methods offered only after a partial multi-factor success. Absence from this initial list does not prove a method is globally disabled.

An unauthenticated external scanner cannot reliably determine root-login configuration, password strength, account-lockout policy, PAM details, full MFA behavior, authorized-key contents, patch/backport status, local file permissions, user privilege levels, or post-authentication restrictions.

A host-key change is reported as an observation or explicit trust-file mismatch—not automatic proof of an attack.

Comparison suppresses apparent removals when either side lacks the corresponding observation. This avoids turning incomplete evidence into a configuration claim, but it means drift is visible only when both reports contain comparable evidence.

See [IMPLEMENTATION.md](IMPLEMENTATION.md) for the phased plan and current engineering risks.
