package kex

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sshscope/sshscope/internal/evidence"
)

func TestParseNameList(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
		err   bool
	}{
		{"empty", "", []string{}, false},
		{"ordered", "zeta,alpha,beta", []string{"zeta", "alpha", "beta"}, false},
		{"empty member", "alpha,,beta", nil, true},
		{"duplicate", "alpha,alpha", nil, true},
		{"space", "alpha,bad name", nil, true},
		{"control", "alpha,\x00", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseNameList([]byte(tt.input))
			if tt.err {
				if err == nil {
					t.Fatal("ParseNameList() = nil error")
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseNameList() = %v, %v", got, err)
			}
		})
	}
}

func TestParseKEXINITFixture(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "kexinit", "modern.b64"))
	if err != nil {
		t.Fatalf("ReadFile() = %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatalf("DecodeString() = %v", err)
	}
	proposal, err := ParseKEXINIT(payload)
	if err != nil {
		t.Fatalf("ParseKEXINIT() = %v", err)
	}
	if proposal.KeyExchanges[0] != "curve25519-sha256" || proposal.Reserved != 7 || !proposal.FirstKEXPacketFollows {
		t.Fatalf("ParseKEXINIT() = %+v", proposal)
	}
}

func TestKEXINITRoundTripPreservesOrder(t *testing.T) {
	want := fixtureProposal()
	payload, err := MarshalKEXINIT(want, [16]byte{1, 2, 3})
	if err != nil {
		t.Fatalf("MarshalKEXINIT() = %v", err)
	}
	got, err := ParseKEXINIT(payload)
	if err != nil {
		t.Fatalf("ParseKEXINIT() = %v", err)
	}
	want.Extensions = []string{"ext-info-s", "kex-strict-s-v00@openssh.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseKEXINIT() = %+v, want %+v", got, want)
	}
}

func TestMarshalKEXINITRejectsOversizedListsBeforeJoining(t *testing.T) {
	proposal := fixtureProposal()
	proposal.KeyExchanges = make([]string, maximumNamesPerList+1)
	for index := range proposal.KeyExchanges {
		proposal.KeyExchanges[index] = "a"
	}
	if _, err := MarshalKEXINIT(proposal, [16]byte{}); !errors.Is(err, ErrInvalidNameList) {
		t.Fatalf("MarshalKEXINIT() error = %v, want %v", err, ErrInvalidNameList)
	}

	proposal = fixtureProposal()
	proposal.KeyExchanges = []string{strings.Repeat("a", maximumNameListBytes+1)}
	if _, err := MarshalKEXINIT(proposal, [16]byte{}); !errors.Is(err, ErrInvalidNameList) {
		t.Fatalf("MarshalKEXINIT() oversized name error = %v, want %v", err, ErrInvalidNameList)
	}
}

func TestParseKEXINITRejectsMalformedPayloads(t *testing.T) {
	valid, err := MarshalKEXINIT(fixtureProposal(), [16]byte{})
	if err != nil {
		t.Fatalf("MarshalKEXINIT() = %v", err)
	}
	badLength := append([]byte(nil), valid...)
	for index := 17; index < 21; index++ {
		badLength[index] = 0xff
	}
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"empty", nil, ErrUnexpectedMessage},
		{"wrong message", append([]byte{21}, valid[1:]...), ErrUnexpectedMessage},
		{"truncated", valid[:len(valid)-1], ErrInvalidKEXINIT},
		{"bad name-list length", badLength, ErrInvalidKEXINIT},
		{"trailing", append(append([]byte(nil), valid...), 0), ErrInvalidKEXINIT},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseKEXINIT(tt.data)
			if !errors.Is(err, tt.want) {
				t.Fatalf("ParseKEXINIT() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func fixtureProposal() evidence.KEXProposal {
	return evidence.KEXProposal{
		KeyExchanges:              []string{"curve25519-sha256", "ext-info-s", "kex-strict-s-v00@openssh.com"},
		ServerHostKeys:            []string{"ssh-ed25519", "rsa-sha2-512"},
		CiphersClientToServer:     []string{"chacha20-poly1305@openssh.com", "aes128-ctr"},
		CiphersServerToClient:     []string{"aes128-ctr", "chacha20-poly1305@openssh.com"},
		MACsClientToServer:        []string{"hmac-sha2-256", "hmac-sha1"},
		MACsServerToClient:        []string{"hmac-sha2-512"},
		CompressionClientToServer: []string{"none", "zlib@openssh.com"},
		CompressionServerToClient: []string{"none"},
		LanguagesClientToServer:   []string{},
		LanguagesServerToClient:   []string{"en-US"},
		FirstKEXPacketFollows:     true,
		Reserved:                  7,
	}
}

func FuzzParseNameList(f *testing.F) {
	for _, seed := range []string{"", "curve25519-sha256", "a,b", "a,,b", strings.Repeat("x", maximumNameListBytes+1)} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ParseNameList(input)
	})
}

func FuzzParseKEXINIT(f *testing.F) {
	valid, _ := MarshalKEXINIT(fixtureProposal(), [16]byte{})
	f.Add(valid)
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 64))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ParseKEXINIT(input)
	})
}
