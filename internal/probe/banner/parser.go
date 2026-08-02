// Package banner implements bounded SSH server-identification collection.
package banner

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

var (
	ErrLineTooLong      = errors.New("SSH identification line exceeds limit")
	ErrTooManyPreLines  = errors.New("too many SSH pre-identification lines")
	ErrTotalLimit       = errors.New("SSH identification input exceeds total limit")
	ErrNoIdentification = errors.New("SSH identification line was not received")
	ErrInvalidFormat    = errors.New("invalid SSH identification format")
)

// Limits bounds all reads performed by ParseIdentification.
type Limits struct {
	MaxLineBytes      int
	MaxPreBannerLines int
	MaxTotalBytes     int
}

// DefaultLimits are deliberately small relative to the target timeout. RFC
// 4253 limits the identification string to 255 bytes including CRLF.
func DefaultLimits() Limits {
	return Limits{MaxLineBytes: 255, MaxPreBannerLines: 20, MaxTotalBytes: 8192}
}

// Identification is the parsed, externally supplied server identification.
type Identification struct {
	Raw             string
	ProtocolVersion string
	SoftwareVersion string
	Comment         string
	PreBannerLines  []string
}

// ParseIdentification reads through the first SSH identification line and no
// further. It never performs an unbounded allocation or network operation.
func ParseIdentification(reader io.Reader, limits Limits) (Identification, error) {
	if reader == nil {
		return Identification{PreBannerLines: []string{}}, errors.New("identification reader is required")
	}
	return ParseIdentificationBuffered(bufio.NewReaderSize(reader, limits.MaxLineBytes+1), limits)
}

// ParseIdentificationBuffered retains bytes read ahead by bufio.Reader so a
// caller can continue with binary SSH transport packets on the same stream.
func ParseIdentificationBuffered(buffered *bufio.Reader, limits Limits) (Identification, error) {
	identification := Identification{PreBannerLines: []string{}}
	if buffered == nil {
		return identification, errors.New("identification reader is required")
	}
	if limits.MaxLineBytes < 8 || limits.MaxPreBannerLines < 0 || limits.MaxTotalBytes < limits.MaxLineBytes {
		return identification, errors.New("invalid identification limits")
	}
	total := 0
	for {
		line, err := buffered.ReadSlice('\n')
		total += len(line)
		if total > limits.MaxTotalBytes {
			return identification, ErrTotalLimit
		}
		if errors.Is(err, bufio.ErrBufferFull) || len(line) > limits.MaxLineBytes {
			return identification, ErrLineTooLong
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return identification, ErrNoIdentification
			}
			return identification, fmt.Errorf("read SSH identification: %w", err)
		}
		line = line[:len(line)-1]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if !utf8.Valid(line) || containsUnsafeControl(line) {
			return identification, ErrInvalidFormat
		}
		text := string(line)
		if !strings.HasPrefix(text, "SSH-") {
			if len(identification.PreBannerLines) >= limits.MaxPreBannerLines {
				return identification, ErrTooManyPreLines
			}
			identification.PreBannerLines = append(identification.PreBannerLines, text)
			continue
		}
		parsed, err := parseIdentificationLine(text)
		parsed.PreBannerLines = identification.PreBannerLines
		return parsed, err
	}
}

func parseIdentificationLine(line string) (Identification, error) {
	identification := Identification{Raw: line, PreBannerLines: []string{}}
	remainder := strings.TrimPrefix(line, "SSH-")
	separator := strings.IndexByte(remainder, '-')
	if separator < 1 || separator == len(remainder)-1 {
		return identification, ErrInvalidFormat
	}
	protocol := remainder[:separator]
	softwareAndComment := remainder[separator+1:]
	if !validProtocolVersion(protocol) {
		return identification, ErrInvalidFormat
	}
	software := softwareAndComment
	comment := ""
	if space := strings.IndexByte(softwareAndComment, ' '); space >= 0 {
		software = softwareAndComment[:space]
		comment = strings.TrimLeft(softwareAndComment[space+1:], " ")
	}
	if software == "" || strings.ContainsAny(software, " \t") {
		return identification, ErrInvalidFormat
	}
	identification.ProtocolVersion = protocol
	identification.SoftwareVersion = software
	identification.Comment = comment
	return identification, nil
}

func validProtocolVersion(version string) bool {
	if version == "" || version[0] == '.' || version[len(version)-1] == '.' {
		return false
	}
	for _, character := range version {
		if (character < '0' || character > '9') && character != '.' {
			return false
		}
	}
	return true
}

func containsUnsafeControl(value []byte) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
