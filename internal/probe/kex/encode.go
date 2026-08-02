package kex

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

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
		encoded := []byte(strings.Join(list, ","))
		if _, err := ParseNameList(encoded); err != nil {
			return nil, err
		}
		if len(encoded) > maximumNameListBytes {
			return nil, ErrInvalidNameList
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
