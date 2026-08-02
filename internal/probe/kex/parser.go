package kex

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/sshscope/sshscope/internal/evidence"
)

const (
	maximumNameListBytes = 16 * 1024
	maximumNamesPerList  = 1024
)

var (
	ErrInvalidKEXINIT  = errors.New("invalid SSH_MSG_KEXINIT")
	ErrInvalidNameList = errors.New("invalid SSH name-list")
)

// ParseKEXINIT parses exactly one KEXINIT payload and rejects trailing data.
func ParseKEXINIT(payload []byte) (evidence.KEXProposal, error) {
	var proposal evidence.KEXProposal
	if len(payload) < 1+16 || payload[0] != MessageKEXINIT {
		if len(payload) > 0 {
			return proposal, fmt.Errorf("%w: got message %d", ErrUnexpectedMessage, payload[0])
		}
		return proposal, fmt.Errorf("%w: empty payload", ErrUnexpectedMessage)
	}
	cursor := payload[17:] // Message number plus the opaque 16-byte cookie.
	lists := []*[]string{
		&proposal.KeyExchanges,
		&proposal.ServerHostKeys,
		&proposal.CiphersClientToServer,
		&proposal.CiphersServerToClient,
		&proposal.MACsClientToServer,
		&proposal.MACsServerToClient,
		&proposal.CompressionClientToServer,
		&proposal.CompressionServerToClient,
		&proposal.LanguagesClientToServer,
		&proposal.LanguagesServerToClient,
	}
	for index, destination := range lists {
		parsed, remainder, err := parseNameListField(cursor)
		if err != nil {
			return evidence.KEXProposal{}, fmt.Errorf("%w: name-list %d: %v", ErrInvalidKEXINIT, index, err)
		}
		*destination = parsed
		cursor = remainder
	}
	if len(cursor) != 5 {
		return evidence.KEXProposal{}, fmt.Errorf("%w: expected 5 trailing bytes, got %d", ErrInvalidKEXINIT, len(cursor))
	}
	proposal.FirstKEXPacketFollows = cursor[0] != 0
	proposal.Reserved = binary.BigEndian.Uint32(cursor[1:])
	proposal.Extensions = observableExtensions(proposal.KeyExchanges)
	return proposal, nil
}

// ParseNameList validates the SSH name-list data type while preserving order.
func ParseNameList(value []byte) ([]string, error) {
	if len(value) > maximumNameListBytes {
		return nil, fmt.Errorf("%w: exceeds %d bytes", ErrInvalidNameList, maximumNameListBytes)
	}
	if len(value) == 0 {
		return []string{}, nil
	}
	parts := strings.Split(string(value), ",")
	if len(parts) > maximumNamesPerList {
		return nil, fmt.Errorf("%w: too many names", ErrInvalidNameList)
	}
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("%w: empty name", ErrInvalidNameList)
		}
		for _, character := range []byte(part) {
			if character < 0x21 || character > 0x7e || character == ',' {
				return nil, fmt.Errorf("%w: non-printable or separator byte", ErrInvalidNameList)
			}
		}
		if _, exists := seen[part]; exists {
			return nil, fmt.Errorf("%w: duplicate name %q", ErrInvalidNameList, part)
		}
		seen[part] = struct{}{}
	}
	return parts, nil
}

func parseNameListField(input []byte) ([]string, []byte, error) {
	if len(input) < 4 {
		return nil, nil, ErrTruncatedPacket
	}
	length := binary.BigEndian.Uint32(input[:4])
	if length > maximumNameListBytes || uint64(length) > uint64(len(input)-4) {
		return nil, nil, ErrInvalidNameList
	}
	parsed, err := ParseNameList(input[4 : 4+int(length)])
	if err != nil {
		return nil, nil, err
	}
	return parsed, input[4+int(length):], nil
}

func observableExtensions(algorithms []string) []string {
	extensions := make([]string, 0, 2)
	for _, algorithm := range algorithms {
		if strings.HasPrefix(algorithm, "ext-info-") || strings.HasPrefix(algorithm, "kex-strict-") {
			extensions = append(extensions, algorithm)
		}
	}
	return extensions
}
