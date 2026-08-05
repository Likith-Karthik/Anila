package policy

import (
	"context"
	"strings"
)

const defaultPolicyYAML = `
version: 1
rules:
  - id: SSH-001
    title: SSH version 1 protocol advertised
    severity: critical
    confidence: high
    description: The SSH identification string advertises protocol version 1.
    match:
      field: ssh.protocol_version
      equals: "1.99"
    recommendation: Disable SSH protocol version 1 compatibility.
  - id: SSH-002
    title: Legacy key exchange algorithm offered
    severity: high
    confidence: high
    description: The server offered a legacy key exchange algorithm.
    match:
      field: ssh.kex.algorithms
      contains_any: ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"]
    recommendation: Remove legacy SHA-1 key exchange algorithms from the server configuration.
  - id: SSH-003
    title: Legacy host-key algorithm offered
    severity: high
    confidence: high
    description: The server offered a legacy SHA-1 host-key algorithm.
    match:
      field: ssh.host_key.algorithms
      contains_any: ["ssh-rsa", "ssh-dss"]
    recommendation: Prefer Ed25519 or RSA SHA-2 host-key algorithms.
  - id: SSH-004
    title: Weak RSA host key observed
    severity: high
    confidence: high
    description: An observed RSA host key is smaller than 2048 bits.
    match:
      field: ssh.host_keys.rsa_bits
      less_than: 2048
    recommendation: Replace weak RSA host keys with at least 3072-bit RSA or Ed25519 keys.
  - id: SSH-005
    title: known_hosts mismatch observed
    severity: high
    confidence: high
    description: A supplied known_hosts file contains a different key for this endpoint.
    match:
      field: ssh.host_keys.known_hosts_status
      equals: mismatch
    recommendation: Investigate the host-key change before trusting this endpoint.
  - id: SSH-006
    title: Revoked host key observed
    severity: critical
    confidence: high
    description: A supplied known_hosts file marks the observed host key as revoked.
    match:
      field: ssh.host_keys.known_hosts_status
      equals: revoked
    recommendation: Remove the revoked key from service and investigate endpoint identity.
  - id: SSH-007
    title: CBC cipher offered
    severity: medium
    confidence: high
    description: The server offered a CBC-mode cipher.
    match:
      any:
        - field: ssh.ciphers.client_to_server
          suffix: "-cbc"
        - field: ssh.ciphers.server_to_client
          suffix: "-cbc"
    recommendation: Disable CBC ciphers and prefer modern AEAD or CTR-mode ciphers.
  - id: SSH-008
    title: Legacy MAC offered
    severity: medium
    confidence: high
    description: The server offered a legacy MAC algorithm.
    match:
      any:
        - field: ssh.macs.client_to_server
          contains_any: ["hmac-md5", "hmac-sha1-96", "hmac-md5-96"]
        - field: ssh.macs.server_to_client
          contains_any: ["hmac-md5", "hmac-sha1-96", "hmac-md5-96"]
    recommendation: Remove legacy MAC algorithms from the server configuration.
  - id: SSH-009
    title: Authentication without credentials accepted
    severity: critical
    confidence: high
    description: The server accepted the initial none authentication request for the configured audit username.
    match:
      field: ssh.auth_none_accepted
      equals: true
    recommendation: Disable credentialless SSH authentication for the affected account and verify authorization boundaries.
  - id: SSH-010
    title: Password authentication advertised
    severity: low
    confidence: medium
    description: The server advertised password authentication for the configured audit username.
    match:
      field: ssh.auth_methods_observed
      contains: password
    recommendation: Consider disabling password authentication where key-based or federated access is required.
  - id: SSH-011
    title: Banner discloses SSH software
    severity: info
    confidence: low
    description: The banner exposes self-reported software information; this is not verified package or patch evidence.
    match:
      field: ssh.software_version
      exists: true
    recommendation: Treat banner versions as untrusted inventory hints only.
`

// LoadDefault returns the embedded baseline defensive policy.
func LoadDefault(ctx context.Context) (Document, error) {
	return (YAMLLoader{}).Load(ctx, strings.NewReader(defaultPolicyYAML))
}
