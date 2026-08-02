// Package kex implements the minimal unencrypted SSH transport handling needed
// to observe a server's initial SSH_MSG_KEXINIT proposal.
package kex

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	MessageKEXINIT         = 20
	DefaultMaxPacketLength = 64 * 1024
	unencryptedBlockSize   = 8
)

var (
	ErrInvalidPacketLength = errors.New("invalid SSH packet length")
	ErrInvalidPadding      = errors.New("invalid SSH packet padding")
	ErrTruncatedPacket     = errors.New("truncated SSH packet")
	ErrUnexpectedMessage   = errors.New("unexpected SSH message")
)

// ReadPacket validates and returns the payload of one unencrypted SSH binary
// packet. It allocates only after validating the four-byte length field.
func ReadPacket(reader io.Reader, maximum uint32) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("packet reader is required")
	}
	if maximum < 12 || maximum > DefaultMaxPacketLength {
		return nil, errors.New("invalid maximum SSH packet length")
	}
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, fmt.Errorf("%w: packet header: %w", ErrTruncatedPacket, err)
	}
	packetLength := binary.BigEndian.Uint32(header[:])
	if packetLength < 12 || packetLength > maximum || (packetLength+4)%unencryptedBlockSize != 0 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidPacketLength, packetLength)
	}
	packet := make([]byte, int(packetLength))
	if _, err := io.ReadFull(reader, packet); err != nil {
		return nil, fmt.Errorf("%w: packet body: %w", ErrTruncatedPacket, err)
	}
	paddingLength := int(packet[0])
	if paddingLength < 4 || paddingLength >= len(packet) {
		return nil, fmt.Errorf("%w: padding length %d", ErrInvalidPadding, paddingLength)
	}
	payloadLength := len(packet) - 1 - paddingLength
	if payloadLength < 1 {
		return nil, fmt.Errorf("%w: packet has no payload", ErrInvalidPadding)
	}
	payload := make([]byte, payloadLength)
	copy(payload, packet[1:1+payloadLength])
	return payload, nil
}

// MarshalPacket frames one unencrypted SSH payload with random padding. It is
// used only for the client's initial KEXINIT and deterministic test fixtures.
func MarshalPacket(payload []byte, randomness io.Reader) ([]byte, error) {
	if len(payload) == 0 {
		return nil, errors.New("SSH packet payload is empty")
	}
	if randomness == nil {
		return nil, errors.New("SSH packet padding source is required")
	}
	paddingLength := unencryptedBlockSize - ((4 + 1 + len(payload)) % unencryptedBlockSize)
	if paddingLength < 4 {
		paddingLength += unencryptedBlockSize
	}
	packetLength := 1 + len(payload) + paddingLength
	if packetLength > DefaultMaxPacketLength {
		return nil, ErrInvalidPacketLength
	}
	packet := make([]byte, 4+packetLength)
	binary.BigEndian.PutUint32(packet[:4], uint32(packetLength))
	packet[4] = byte(paddingLength)
	copy(packet[5:], payload)
	if _, err := io.ReadFull(randomness, packet[5+len(payload):]); err != nil {
		return nil, fmt.Errorf("generate SSH packet padding: %w", err)
	}
	return packet, nil
}
