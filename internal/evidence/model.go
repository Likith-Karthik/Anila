// Package evidence defines normalized facts collected from remote endpoints.
package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

const (
	MaximumObservationStringBytes = 16 * 1024
	MaximumObservationListValues  = 1024
	MaximumObservationListBytes   = 64 * 1024
	MaximumObservedHostKeys       = 8
	maximumObservationNameBytes   = 128
	maximumObservationRawBytes    = 16 * 1024
	maximumObservationErrorBytes  = 4 * 1024
	maximumUnitBytes              = 64
	maximumSSHNameListBytes       = 16 * 1024
	maximumAuthMethods            = 64
	maximumAuthMethodBytes        = 128
	maximumPreBannerLines         = 20
	maximumPreBannerBytes         = 8 * 1024
	maximumBannerLineBytes        = 255
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
	KnownHostsRevoked    KnownHostsStatus = "revoked"
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
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&encoded); err != nil {
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
		err = strictUnmarshalJSON(encoded.Boolean, &decoded.Boolean)
	case ValueString:
		err = strictUnmarshalJSON(encoded.String, &decoded.String)
	case ValueNumber:
		err = strictUnmarshalJSON(encoded.Number, &decoded.Number)
	case ValueStrings:
		err = strictUnmarshalJSON(encoded.Strings, &decoded.Strings)
	case ValueHostKeys:
		err = strictUnmarshalJSON(encoded.HostKeys, &decoded.HostKeys)
	case ValueKEX:
		err = strictUnmarshalJSON(encoded.KEX, &decoded.KEX)
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

func strictUnmarshalJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("JSON value must contain exactly one value")
	}
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
	} else if len(o.ID) > maximumObservationNameBytes {
		errs = append(errs, errors.New("observation ID is oversized"))
	}
	if o.Probe == "" {
		errs = append(errs, errors.New("observation probe is required"))
	} else if len(o.Probe) > maximumObservationNameBytes {
		errs = append(errs, errors.New("observation probe is oversized"))
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
	if expected, known := expectedValueKind(o.ID); known && o.Value.Kind != expected {
		errs = append(errs, fmt.Errorf("observation %q requires value kind %q", o.ID, expected))
	}
	if expected, known := expectedProbe(o.ID); known && o.Probe != expected {
		errs = append(errs, fmt.Errorf("observation %q must originate from probe %q", o.ID, expected))
	}
	if err := validateObservationDomain(o); err != nil {
		errs = append(errs, err)
	}
	if len(o.Raw) > maximumObservationRawBytes {
		errs = append(errs, errors.New("observation raw evidence is oversized"))
	}
	if o.Error != nil {
		if o.Error.Kind == "" || o.Error.Message == "" {
			errs = append(errs, errors.New("observation error requires kind and message"))
		}
		if len(o.Error.Kind) > maximumObservationNameBytes || len(o.Error.Message) > maximumObservationErrorBytes {
			errs = append(errs, errors.New("observation error information is oversized"))
		}
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
	if len(v.Unit) > maximumUnitBytes {
		return errors.New("observation unit is oversized")
	}
	if v.Number != nil && (math.IsNaN(*v.Number) || math.IsInf(*v.Number, 0)) {
		return errors.New("numeric observation values must be finite")
	}
	if v.String != nil && len(*v.String) > MaximumObservationStringBytes {
		return fmt.Errorf("string observation exceeds %d bytes", MaximumObservationStringBytes)
	}
	if v.Strings != nil {
		if err := validateBoundedStrings(v.Strings, MaximumObservationListValues, MaximumObservationListBytes, MaximumObservationStringBytes, "string observation list"); err != nil {
			return err
		}
	}
	if len(v.HostKeys) > MaximumObservedHostKeys {
		return fmt.Errorf("host-key observation exceeds %d keys", MaximumObservedHostKeys)
	}
	for i, key := range v.HostKeys {
		if err := key.Validate(); err != nil {
			return fmt.Errorf("host key %d: %w", i, err)
		}
	}
	if v.KEX != nil {
		if err := v.KEX.Validate(); err != nil {
			return fmt.Errorf("invalid KEX proposal: %w", err)
		}
	}
	return nil
}

// Validate bounds every list retained in a structured KEX proposal.
func (p KEXProposal) Validate() error {
	for index, values := range [][]string{
		p.KeyExchanges, p.ServerHostKeys,
		p.CiphersClientToServer, p.CiphersServerToClient,
		p.MACsClientToServer, p.MACsServerToClient,
		p.CompressionClientToServer, p.CompressionServerToClient,
		p.LanguagesClientToServer, p.LanguagesServerToClient,
		p.Extensions,
	} {
		if err := validateSSHNameList(values, MaximumObservationListValues, maximumSSHNameListBytes, MaximumObservationStringBytes); err != nil {
			return fmt.Errorf("name-list %d: %w", index, err)
		}
	}
	return nil
}

// Validate checks normalized host-key identity and trust-comparison state.
func (k HostKey) Validate() error {
	var errs []error
	if k.Algorithm == "" {
		errs = append(errs, errors.New("host-key algorithm is required"))
	} else if len(k.Algorithm) > MaximumObservationStringBytes {
		errs = append(errs, errors.New("host-key algorithm is oversized"))
	}
	if k.FingerprintSHA256 == "" {
		errs = append(errs, errors.New("host-key SHA-256 fingerprint is required"))
	} else if len(k.FingerprintSHA256) > MaximumObservationStringBytes {
		errs = append(errs, errors.New("host-key fingerprint is oversized"))
	}
	if k.PublicKeyType == "" {
		errs = append(errs, errors.New("host-key public-key type is required"))
	} else if len(k.PublicKeyType) > MaximumObservationStringBytes {
		errs = append(errs, errors.New("host-key public-key type is oversized"))
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
	if len(k.CAFingerprintSHA256) > MaximumObservationStringBytes {
		errs = append(errs, errors.New("host certificate CA fingerprint is oversized"))
	}
	if k.KnownHostsStatus != KnownHostsNotChecked && k.KnownHostsStatus != KnownHostsNew &&
		k.KnownHostsStatus != KnownHostsMatch && k.KnownHostsStatus != KnownHostsMismatch &&
		k.KnownHostsStatus != KnownHostsRevoked {
		errs = append(errs, fmt.Errorf("unsupported known_hosts status %q", k.KnownHostsStatus))
	}
	return errors.Join(errs...)
}

func expectedValueKind(id string) (ValueKind, bool) {
	switch id {
	case ObservationTCPReachable, ObservationFirstKEXPacketFollows, ObservationAuthNoneAccepted:
		return ValueBoolean, true
	case ObservationTCPLatency, ObservationKEXReserved:
		return ValueNumber, true
	case ObservationBannerRaw, ObservationProtocolVersion, ObservationSoftwareVersion, ObservationSoftwareComment:
		return ValueString, true
	case ObservationBannerPreLines, ObservationKEXAlgorithms, ObservationHostKeyAlgorithms,
		ObservationCiphersClientToServer, ObservationCiphersServerToClient,
		ObservationMACsClientToServer, ObservationMACsServerToClient,
		ObservationCompressionClientToServer, ObservationCompressionServerToClient,
		ObservationLanguagesClientToServer, ObservationLanguagesServerToClient,
		ObservationProtocolExtensions, ObservationAuthMethods:
		return ValueStrings, true
	case ObservationHostKeys:
		return ValueHostKeys, true
	default:
		return "", false
	}
}

func expectedProbe(id string) (string, bool) {
	switch id {
	case ObservationTCPReachable, ObservationTCPLatency:
		return "tcp", true
	case ObservationBannerRaw, ObservationBannerPreLines, ObservationProtocolVersion, ObservationSoftwareVersion, ObservationSoftwareComment:
		return "banner", true
	case ObservationKEXAlgorithms, ObservationHostKeyAlgorithms,
		ObservationCiphersClientToServer, ObservationCiphersServerToClient,
		ObservationMACsClientToServer, ObservationMACsServerToClient,
		ObservationCompressionClientToServer, ObservationCompressionServerToClient,
		ObservationLanguagesClientToServer, ObservationLanguagesServerToClient,
		ObservationFirstKEXPacketFollows, ObservationKEXReserved, ObservationProtocolExtensions:
		return "kex", true
	case ObservationHostKeys:
		return "hostkey", true
	case ObservationAuthMethods, ObservationAuthNoneAccepted:
		return "auth", true
	default:
		return "", false
	}
}

func validateObservationDomain(observation Observation) error {
	switch observation.ID {
	case ObservationTCPLatency:
		if observation.Value.Number != nil && (*observation.Value.Number < 0 || observation.Value.Unit != "milliseconds") {
			return errors.New("TCP latency must be a non-negative millisecond measurement")
		}
	case ObservationKEXReserved:
		if observation.Value.Number != nil {
			value := *observation.Value.Number
			if value < 0 || value > math.MaxUint32 || math.Trunc(value) != value || observation.Value.Unit != "" {
				return errors.New("KEX reserved value must be an unsigned 32-bit integer")
			}
		}
	case ObservationBannerRaw, ObservationProtocolVersion, ObservationSoftwareVersion, ObservationSoftwareComment:
		if observation.Value.String != nil && len(*observation.Value.String) > maximumBannerLineBytes {
			return fmt.Errorf("banner-derived observation exceeds %d bytes", maximumBannerLineBytes)
		}
	case ObservationBannerPreLines:
		return validateBoundedStrings(observation.Value.Strings, maximumPreBannerLines, maximumPreBannerBytes, maximumBannerLineBytes, "pre-banner lines")
	case ObservationKEXAlgorithms, ObservationHostKeyAlgorithms,
		ObservationCiphersClientToServer, ObservationCiphersServerToClient,
		ObservationMACsClientToServer, ObservationMACsServerToClient,
		ObservationCompressionClientToServer, ObservationCompressionServerToClient,
		ObservationLanguagesClientToServer, ObservationLanguagesServerToClient,
		ObservationProtocolExtensions:
		return validateSSHNameList(observation.Value.Strings, MaximumObservationListValues, maximumSSHNameListBytes, MaximumObservationStringBytes)
	case ObservationAuthMethods:
		return validateSSHNameList(observation.Value.Strings, maximumAuthMethods, MaximumObservationListBytes, maximumAuthMethodBytes)
	case ObservationHostKeys:
		if len(observation.Value.HostKeys) > MaximumObservedHostKeys {
			return fmt.Errorf("host-key observation exceeds %d keys", MaximumObservedHostKeys)
		}
		seen := make(map[string]struct{}, len(observation.Value.HostKeys))
		for _, key := range observation.Value.HostKeys {
			if _, exists := seen[key.FingerprintSHA256]; exists {
				return fmt.Errorf("host-key observation contains duplicate fingerprint %q", key.FingerprintSHA256)
			}
			seen[key.FingerprintSHA256] = struct{}{}
		}
	}
	return nil
}

func validateBoundedStrings(values []string, maximumValues, maximumBytes, maximumValueBytes int, label string) error {
	if len(values) > maximumValues {
		return fmt.Errorf("%s exceeds %d values", label, maximumValues)
	}
	total := 0
	for index, value := range values {
		if len(value) > maximumValueBytes {
			return fmt.Errorf("%s value %d exceeds %d bytes", label, index, maximumValueBytes)
		}
		if len(value) > maximumBytes-total {
			return fmt.Errorf("%s exceeds %d bytes", label, maximumBytes)
		}
		total += len(value)
	}
	return nil
}

func validateSSHNameList(values []string, maximumValues, maximumBytes, maximumValueBytes int) error {
	if err := validateBoundedStrings(values, maximumValues, maximumBytes, maximumValueBytes, "SSH name-list"); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(values))
	encodedBytes := 0
	for index, value := range values {
		additional := len(value)
		if index > 0 {
			additional++
		}
		if additional > maximumBytes-encodedBytes {
			return fmt.Errorf("SSH name-list exceeds %d encoded bytes", maximumBytes)
		}
		encodedBytes += additional
		if value == "" {
			return fmt.Errorf("SSH name-list value %d is empty", index)
		}
		for _, character := range []byte(value) {
			if character < 0x21 || character > 0x7e || character == ',' {
				return fmt.Errorf("SSH name-list value %d contains an invalid byte", index)
			}
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("SSH name-list contains duplicate %q", value)
		}
		seen[value] = struct{}{}
	}
	return nil
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
	ObservationAuthNoneAccepted          = "ssh.auth_none_accepted"
)
