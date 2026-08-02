package kex

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestPacketRoundTrip(t *testing.T) {
	payload := []byte{MessageKEXINIT, 1, 2, 3}
	packet, err := MarshalPacket(payload, bytes.NewReader(make([]byte, 32)))
	if err != nil {
		t.Fatalf("MarshalPacket() = %v", err)
	}
	got, err := ReadPacket(bytes.NewReader(packet), DefaultMaxPacketLength)
	if err != nil {
		t.Fatalf("ReadPacket() = %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("ReadPacket() = %x, want %x", got, payload)
	}
}

func TestReadPacketRejectsInvalidFraming(t *testing.T) {
	valid, err := MarshalPacket([]byte{MessageKEXINIT}, bytes.NewReader(make([]byte, 32)))
	if err != nil {
		t.Fatalf("MarshalPacket() = %v", err)
	}
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"truncated header", []byte{0, 0}, ErrTruncatedPacket},
		{"short length", packetWithLength(11), ErrInvalidPacketLength},
		{"excessive length", packetWithLength(DefaultMaxPacketLength + 1), ErrInvalidPacketLength},
		{"misaligned length", packetWithLength(13), ErrInvalidPacketLength},
		{"truncated body", valid[:len(valid)-1], ErrTruncatedPacket},
		{"short padding", replaceByte(valid, 4, 3), ErrInvalidPadding},
		{"excessive padding", replaceByte(valid, 4, valid[3]), ErrInvalidPadding},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadPacket(bytes.NewReader(tt.data), DefaultMaxPacketLength)
			if !errors.Is(err, tt.want) {
				t.Fatalf("ReadPacket() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func packetWithLength(length uint32) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, length)
	return data
}

func replaceByte(input []byte, index int, value byte) []byte {
	result := append([]byte(nil), input...)
	result[index] = value
	return result
}

func FuzzReadPacket(f *testing.F) {
	valid, _ := MarshalPacket([]byte{MessageKEXINIT}, bytes.NewReader(make([]byte, 32)))
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 12})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ReadPacket(bytes.NewReader(input), DefaultMaxPacketLength)
	})
}
