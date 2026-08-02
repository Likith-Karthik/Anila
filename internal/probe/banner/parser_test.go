package banner

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseIdentificationBufferedRetainsPacketBytes(t *testing.T) {
	packet := []byte{0, 0, 0, 12, 10, 20, 0, 0}
	input := append([]byte("SSH-2.0-fixture\r\n"), packet...)
	buffered := bufio.NewReaderSize(bytes.NewReader(input), 512)
	if _, err := ParseIdentificationBuffered(buffered, DefaultLimits()); err != nil {
		t.Fatalf("ParseIdentificationBuffered() = %v", err)
	}
	remaining, err := io.ReadAll(buffered)
	if err != nil {
		t.Fatalf("ReadAll() = %v", err)
	}
	if !bytes.Equal(remaining, packet) {
		t.Fatalf("remaining bytes = %x, want %x", remaining, packet)
	}
}

func TestParseIdentification(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantRaw     string
		wantProto   string
		wantSoft    string
		wantComment string
		wantPre     int
		wantErr     error
	}{
		{"modern", "SSH-2.0-OpenSSH_9.9\r\n", "SSH-2.0-OpenSSH_9.9", "2.0", "OpenSSH_9.9", "", 0, nil},
		{"comment", "SSH-2.0-dropbear_2024.86 embedded system\r\n", "SSH-2.0-dropbear_2024.86 embedded system", "2.0", "dropbear_2024.86", "embedded system", 0, nil},
		{"pre-banner", "notice one\r\nnotice two\nSSH-1.99-test\r\n", "SSH-1.99-test", "1.99", "test", "", 2, nil},
		{"truncated", "SSH-2.0-test", "", "", "", "", 0, ErrNoIdentification},
		{"bad protocol", "SSH-two-test\r\n", "", "", "", "", 0, ErrInvalidFormat},
		{"control", "SSH-2.0-test\x00bad\r\n", "", "", "", "", 0, ErrInvalidFormat},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIdentification(strings.NewReader(tt.input), DefaultLimits())
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseIdentification() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseIdentification() = %v", err)
			}
			if got.Raw != tt.wantRaw || got.ProtocolVersion != tt.wantProto || got.SoftwareVersion != tt.wantSoft || got.Comment != tt.wantComment || len(got.PreBannerLines) != tt.wantPre {
				t.Fatalf("ParseIdentification() = %+v", got)
			}
		})
	}
}

func TestParseIdentificationFixtures(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		protocol string
		preLines int
	}{
		{"modern", "modern.txt", "2.0", 0},
		{"pre-banner", "prebanner.txt", "1.99", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "banners", tt.file))
			if err != nil {
				t.Fatalf("ReadFile() = %v", err)
			}
			got, err := ParseIdentification(bytes.NewReader(data), DefaultLimits())
			if err != nil {
				t.Fatalf("ParseIdentification() = %v", err)
			}
			if got.ProtocolVersion != tt.protocol || len(got.PreBannerLines) != tt.preLines {
				t.Fatalf("ParseIdentification() = %+v", got)
			}
		})
	}
}

func TestParseIdentificationLimits(t *testing.T) {
	limits := Limits{MaxLineBytes: 32, MaxPreBannerLines: 1, MaxTotalBytes: 64}
	tests := []struct {
		name   string
		input  string
		limits Limits
		want   error
	}{
		{"oversized line", strings.Repeat("x", 33) + "\n", limits, ErrLineTooLong},
		{"too many pre-lines", "one\ntwo\nSSH-2.0-test\r\n", Limits{MaxLineBytes: 32, MaxPreBannerLines: 1, MaxTotalBytes: 64}, ErrTooManyPreLines},
		{"total", strings.Repeat("a", 30) + "\n" + strings.Repeat("b", 30) + "\nSSH-2.0-test\n", Limits{MaxLineBytes: 32, MaxPreBannerLines: 10, MaxTotalBytes: 64}, ErrTotalLimit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseIdentification(strings.NewReader(tt.input), tt.limits)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func FuzzParseIdentification(f *testing.F) {
	for _, seed := range []string{"SSH-2.0-test\r\n", "notice\nSSH-1.99-old\r\n", "", strings.Repeat("x", 300)} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ParseIdentification(bytes.NewReader(input), DefaultLimits())
	})
}
