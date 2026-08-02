// Package evidence defines normalized facts collected from remote endpoints.
package evidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

// Confidence describes evidence quality independently from finding severity.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// ValueKind identifies the populated member of Value.
type ValueKind string

const (
	ValueBoolean  ValueKind = "boolean"
	ValueString   ValueKind = "string"
	ValueNumber   ValueKind = "number"
	ValueStrings  ValueKind = "strings"
	ValueHostKeys ValueKind = "host_keys"
	ValueKEX      ValueKind = "kex_proposal"
)

// HostKey is normalized public host-key evidence.
type HostKey struct {
	Algorithm           string           `json:"algorithm"`
	FingerprintSHA256   string           `json:"fingerprint_sha256"`
	PublicKeyType       string           `json:"public_key_type"`
	Bits                int              `json:"bits,omitempty"`
	Certificate         bool             `json:"certificate"`
	CAFingerprintSHA256 string           `json:"ca_fingerprint_sha256,omitempty"`
	KnownHostsStatus    KnownHostsStatus `json:"known_hosts_status"`
}

// KnownHostsStatus distinguishes collection from explicit trust-file checks.
type KnownHostsStatus string

const (
	KnownHostsNotChecked KnownHostsStatus = "not_checked"
	KnownHostsNew        KnownHostsStatus = "new"
	KnownHostsMatch      KnownHostsStatus = "match"
	KnownHostsMismatch   KnownHostsStatus = "mismatch"
)

// KEXProposal preserves server preference order in every algorithm list.
type KEXProposal struct {
	KeyExchanges              []string `json:"key_exchanges"`
	ServerHostKeys            []string `json:"server_host_keys"`
	CiphersClientToServer     []string `json:"ciphers_client_to_server"`
	CiphersServerToClient     []string `json:"ciphers_server_to_client"`
	MACsClientToServer        []string `json:"macs_client_to_server"`
	MACsServerToClient        []string `json:"macs_server_to_client"`
	CompressionClientToServer []string `json:"compression_client_to_server"`
	CompressionServerToClient []string `json:"compression_server_to_client"`
	LanguagesClientToServer   []string `json:"languages_client_to_server"`
	LanguagesServerToClient   []string `json:"languages_server_to_client"`
	Extensions                []string `json:"extensions"`
	FirstKEXPacketFollows     bool     `json:"first_kex_packet_follows"`
	Reserved                  uint32   `json:"reserved"`
}

// Value is a closed, typed union for normalized observation values. Kind says
// which member is populated, avoiding unstructured maps at package boundaries.
type Value struct {
	Kind     ValueKind    `json:"kind"`
	Boolean  *bool        `json:"boolean,omitempty"`
	String   *string      `json:"string,omitempty"`
	Number   *float64     `json:"number,omitempty"`
	Unit     string       `json:"unit,omitempty"`
	Strings  []string     `json:"strings,omitempty"`
	HostKeys []HostKey    `json:"host_keys,omitempty"`
	KEX      *KEXProposal `json:"kex_proposal,omitempty"`
}

type encodedValue struct {
	Kind     ValueKind       `json:"kind"`
	Boolean  json.RawMessage `json:"boolean,omitempty"`
	String   json.RawMessage `json:"string,omitempty"`
	Number   json.RawMessage `json:"number,omitempty"`
	Unit     string          `json:"unit,omitempty"`
	Strings  json.RawMessage `json:"strings,omitempty"`
	HostKeys json.RawMessage `json:"host_keys,omitempty"`
	KEX      json.RawMessage `json:"kex_proposal,omitempty"`
}

// MarshalJSON writes only the active union member while preserving empty lists.
func (v Value) MarshalJSON() ([]byte, error) {
	if err := v.Validate(); err != nil {
		return nil, err
	}
	encoded := encodedValue{Kind: v.Kind, Unit: v.Unit}
	var err error
	switch v.Kind {
	case ValueBoolean:
		encoded.Boolean, err = json.Marshal(*v.Boolean)
	case ValueString:
		encoded.String, err = json.Marshal(*v.String)
	case ValueNumber:
		encoded.Number, err = json.Marshal(*v.Number)
	case ValueStrings:
		encoded.Strings, err = json.Marshal(v.Strings)
	case ValueHostKeys:
		encoded.HostKeys, err = json.Marshal(v.HostKeys)
	case ValueKEX:
		encoded.KEX, err = json.Marshal(v.KEX)
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(encoded)
}

// UnmarshalJSON restores exactly one typed union member.
func (v *Value) UnmarshalJSON(data []byte) error {
	var encoded encodedValue
	if err := json.Unmarshal(data, &encoded); err != nil {
		return err
	}
	present := 0
	for _, raw := range []json.RawMessage{encoded.Boolean, encoded.String, encoded.Number, encoded.Strings, encoded.HostKeys, encoded.KEX} {
		if len(raw) > 0 {
			present++
		}
	}
	if present != 1 {
		return fmt.Errorf("encoded observation value must contain exactly one member, got %d", present)
	}
	decoded := Value{Kind: encoded.Kind, Unit: encoded.Unit}
	var err error
	switch encoded.Kind {
	case ValueBoolean:
		err = json.Unmarshal(encoded.Boolean, &decoded.Boolean)
	case ValueString:
		err = json.Unmarshal(encoded.String, &decoded.String)
	case ValueNumber:
		err = json.Unmarshal(encoded.Number, &decoded.Number)
	case ValueStrings:
		err = json.Unmarshal(encoded.Strings, &decoded.Strings)
	case ValueHostKeys:
		err = json.Unmarshal(encoded.HostKeys, &decoded.HostKeys)
	case ValueKEX:
		err = json.Unmarshal(encoded.KEX, &decoded.KEX)
	default:
		return fmt.Errorf("unsupported value kind %q", encoded.Kind)
	}
	if err != nil {
		return fmt.Errorf("decode %s observation value: %w", encoded.Kind, err)
	}
	if err := decoded.Validate(); err != nil {
		return err
	}
	*v = decoded
	return nil
}

// ErrorInfo is safe-to-report error information attached to an observation.
type ErrorInfo struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// Observation is a normalized externally observed fact. Probes do not attach
// severity or make policy judgments.
type Observation struct {
	ID         string     `json:"id"`
	Value      Value      `json:"value"`
	Probe      string     `json:"probe"`
	ObservedAt time.Time  `json:"observed_at"`
	Confidence Confidence `json:"confidence"`
	Raw        string     `json:"raw,omitempty"`
	Error      *ErrorInfo `json:"error,omitempty"`
}

// Validate checks the closed-union and provenance invariants required by the
// policy engine. It does not make security judgments about observed values.
func (o Observation) Validate() error {
	var errs []error
	if o.ID == "" {
		errs = append(errs, errors.New("observation ID is required"))
	}
	if o.Probe == "" {
		errs = append(errs, errors.New("observation probe is required"))
	}
	if o.ObservedAt.IsZero() {
		errs = append(errs, errors.New("observation timestamp is required"))
	}
	if !o.Confidence.Valid() {
		errs = append(errs, fmt.Errorf("invalid observation confidence %q", o.Confidence))
	}
	if err := o.Value.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("invalid observation value: %w", err))
	}
	if o.Error != nil && (o.Error.Kind == "" || o.Error.Message == "") {
		errs = append(errs, errors.New("observation error requires kind and message"))
	}
	return errors.Join(errs...)
}

// Valid reports whether the confidence value is supported.
func (c Confidence) Valid() bool {
	return c == ConfidenceHigh || c == ConfidenceMedium || c == ConfidenceLow
}

// Validate enforces that exactly the member named by Kind is populated.
func (v Value) Validate() error {
	populated := 0
	if v.Boolean != nil {
		populated++
	}
	if v.String != nil {
		populated++
	}
	if v.Number != nil {
		populated++
	}
	if v.Strings != nil {
		populated++
	}
	if v.HostKeys != nil {
		populated++
	}
	if v.KEX != nil {
		populated++
	}
	if populated != 1 {
		return fmt.Errorf("exactly one value member must be populated, got %d", populated)
	}

	validKind := false
	switch v.Kind {
	case ValueBoolean:
		validKind = v.Boolean != nil
	case ValueString:
		validKind = v.String != nil
	case ValueNumber:
		validKind = v.Number != nil
	case ValueStrings:
		validKind = v.Strings != nil
	case ValueHostKeys:
		validKind = v.HostKeys != nil
	case ValueKEX:
		validKind = v.KEX != nil
	default:
		return fmt.Errorf("unsupported value kind %q", v.Kind)
	}
	if !validKind {
		return fmt.Errorf("value kind %q does not match populated member", v.Kind)
	}
	if v.Kind != ValueNumber && v.Unit != "" {
		return errors.New("units are only valid for numeric observation values")
	}
	if v.Number != nil && (math.IsNaN(*v.Number) || math.IsInf(*v.Number, 0)) {
		return errors.New("numeric observation values must be finite")
	}
	for i, key := range v.HostKeys {
		if err := key.Validate(); err != nil {
			return fmt.Errorf("host key %d: %w", i, err)
		}
	}
	return nil
}

// Validate checks normalized host-key identity and trust-comparison state.
func (k HostKey) Validate() error {
	var errs []error
	if k.Algorithm == "" {
		errs = append(errs, errors.New("host-key algorithm is required"))
	}
	if k.FingerprintSHA256 == "" {
		errs = append(errs, errors.New("host-key SHA-256 fingerprint is required"))
	}
	if k.PublicKeyType == "" {
		errs = append(errs, errors.New("host-key public-key type is required"))
	}
	if k.Bits < 0 {
		errs = append(errs, errors.New("host-key size must not be negative"))
	}
	if k.Certificate && k.CAFingerprintSHA256 == "" {
		errs = append(errs, errors.New("host certificate requires a CA fingerprint"))
	}
	if !k.Certificate && k.CAFingerprintSHA256 != "" {
		errs = append(errs, errors.New("non-certificate host key must not have a CA fingerprint"))
	}
	if k.KnownHostsStatus != KnownHostsNotChecked && k.KnownHostsStatus != KnownHostsNew &&
		k.KnownHostsStatus != KnownHostsMatch && k.KnownHostsStatus != KnownHostsMismatch {
		errs = append(errs, fmt.Errorf("unsupported known_hosts status %q", k.KnownHostsStatus))
	}
	return errors.Join(errs...)
}

// Constructors keep pointer-valued scalar creation consistent at call sites.
func BooleanValue(value bool) Value {
	return Value{Kind: ValueBoolean, Boolean: &value}
}

func StringValue(value string) Value {
	return Value{Kind: ValueString, String: &value}
}

func NumberValue(value float64) Value {
	return Value{Kind: ValueNumber, Number: &value}
}

// MeasurementValue creates a numeric value with an explicit unit.
func MeasurementValue(value float64, unit string) Value {
	return Value{Kind: ValueNumber, Number: &value, Unit: unit}
}

func StringsValue(values []string) Value {
	if values == nil {
		values = []string{}
	}
	return Value{Kind: ValueStrings, Strings: values}
}

// HostKeysValue creates a host-key list value, preserving collection order.
func HostKeysValue(keys []HostKey) Value {
	if keys == nil {
		keys = []HostKey{}
	}
	return Value{Kind: ValueHostKeys, HostKeys: keys}
}

const (
	ObservationTCPReachable              = "tcp.reachable"
	ObservationTCPLatency                = "tcp.latency"
	ObservationBannerRaw                 = "ssh.banner.raw"
	ObservationBannerPreLines            = "ssh.banner.pre_lines"
	ObservationProtocolVersion           = "ssh.protocol_version"
	ObservationSoftwareVersion           = "ssh.software_version"
	ObservationSoftwareComment           = "ssh.software_comment"
	ObservationKEXAlgorithms             = "ssh.kex.algorithms"
	ObservationHostKeyAlgorithms         = "ssh.host_key.algorithms"
	ObservationCiphersClientToServer     = "ssh.ciphers.client_to_server"
	ObservationCiphersServerToClient     = "ssh.ciphers.server_to_client"
	ObservationMACsClientToServer        = "ssh.macs.client_to_server"
	ObservationMACsServerToClient        = "ssh.macs.server_to_client"
	ObservationCompressionClientToServer = "ssh.compression.client_to_server"
	ObservationCompressionServerToClient = "ssh.compression.server_to_client"
	ObservationLanguagesClientToServer   = "ssh.languages.client_to_server"
	ObservationLanguagesServerToClient   = "ssh.languages.server_to_client"
	ObservationFirstKEXPacketFollows     = "ssh.kex.first_packet_follows"
	ObservationKEXReserved               = "ssh.kex.reserved"
	ObservationProtocolExtensions        = "ssh.protocol_extensions"
	ObservationHostKeys                  = "ssh.host_keys"
	ObservationAuthMethods               = "ssh.auth_methods_observed"
)
