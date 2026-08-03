package kex

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/sshscope/sshscope/internal/evidence"
)

// MarshalKEXINIT encodes the KEXINIT payload used by this probe and loopback
// fixtures. It does not implement key exchange or any cryptographic primitive.
func MarshalKEXINIT(proposal evidence.KEXProposal, cookie [16]byte) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.Grow(1024)
	buffer.WriteByte(MessageKEXINIT)
	buffer.Write(cookie[:])
	for _, list := range [][]string{
		proposal.KeyExchanges,
		proposal.ServerHostKeys,
		proposal.CiphersClientToServer,
		proposal.CiphersServerToClient,
		proposal.MACsClientToServer,
		proposal.MACsServerToClient,
		proposal.CompressionClientToServer,
		proposal.CompressionServerToClient,
		proposal.LanguagesClientToServer,
		proposal.LanguagesServerToClient,
	} {
		encodedLength, err := encodedNameListLength(list)
		if err != nil {
			return nil, err
		}
		encoded := make([]byte, 0, encodedLength)
		for index, name := range list {
			if index > 0 {
				encoded = append(encoded, ',')
			}
			encoded = append(encoded, name...)
		}
		if _, err := ParseNameList(encoded); err != nil {
			return nil, err
		}
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(encoded)))
		buffer.Write(length[:])
		buffer.Write(encoded)
	}
	if proposal.FirstKEXPacketFollows {
		buffer.WriteByte(1)
	} else {
		buffer.WriteByte(0)
	}
	var reserved [4]byte
	binary.BigEndian.PutUint32(reserved[:], proposal.Reserved)
	buffer.Write(reserved[:])
	if buffer.Len() > DefaultMaxPacketLength {
		return nil, fmt.Errorf("%w: encoded KEXINIT is too large", ErrInvalidKEXINIT)
	}
	return buffer.Bytes(), nil
}

func encodedNameListLength(list []string) (int, error) {
	if len(list) > maximumNamesPerList {
		return 0, fmt.Errorf("%w: too many names", ErrInvalidNameList)
	}
	total := 0
	for index, name := range list {
		additional := len(name)
		if index > 0 {
			additional++
		}
		if additional > maximumNameListBytes-total {
			return 0, fmt.Errorf("%w: exceeds %d bytes", ErrInvalidNameList, maximumNameListBytes)
		}
		total += additional
	}
	return total, nil
}
