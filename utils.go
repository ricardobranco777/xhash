package main

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"golang.org/x/crypto/blake2b"
	"hash"
	"strings"
)

// Wrapper for the Blake2 New() methods that need an optional key for MAC
func blake2_(f func([]byte) (hash.Hash, error), key []byte) hash.Hash {
	h, err := f(key)
	if err != nil {
		logger.Fatal(err)
	}
	return h
}

func initHash(h *Checksum) {
	switch h.hash {
	case crypto.BLAKE2b_256:
		h.Hash = blake2_(blake2b.New256, macKey)
	case crypto.BLAKE2b_384:
		h.Hash = blake2_(blake2b.New384, macKey)
	case crypto.BLAKE2b_512:
		h.Hash = blake2_(blake2b.New512, macKey)
	default:
		if macKey != nil {
			h.Hash = hmac.New(h.hash.New, macKey)
		} else {
			h.Hash = h.hash.New()
		}
	}
}

func getChosen() []*Checksum {
	checksums := make([]*Checksum, len(chosen))
	for i := range chosen {
		checksums[i] = &Checksum{hash: chosen[i].hash}
	}
	return checksums
}

// *sum escapes filenames with backslash & newline
func escapeFilename(filename string) (string, string) {
	if opts.zero {
		return "", filename
	}
	var replace = map[string]string{
		"\r": "\\r",
		"\n": "\\n",
	}
	prefix := ""
	if strings.ContainsAny(filename, "\\\r\n") {
		filename = strings.ReplaceAll(filename, "\\", "\\\\")
		for s, ss := range replace {
			filename = strings.ReplaceAll(filename, s, ss)
		}
		if !opts.gnu {
			prefix = "\\"
		}
	}
	return prefix, filename
}

// *sum escapes filenames with backslash & newline
func unescapeFilename(filename string) string {
	if opts.zero {
		return filename
	}
	var replace = map[string]string{
		"\\\\": "\\",
		"\\r":  "\r",
		"\\n":  "\n",
	}
	for s, ss := range replace {
		filename = strings.ReplaceAll(filename, s, ss)
	}
	return filename
}

// Used to support the --format option
func unescape(str string) string {
	var replace = map[string]string{
		"\\\\": "\\",
		"\\r":  "\r",
		"\\n":  "\n",
		"\\t":  "\t",
		"\\0":  "\x00",
	}
	for s, ss := range replace {
		str = strings.ReplaceAll(str, s, ss)
	}
	return str
}

// scanLinesZ is a split function like bufio.ScanLines for NUL-terminated lines
func scanLinesZ(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, '\x00'); i >= 0 {
		// We have a full NUL-terminated line.
		return i + 1, data[0:i], nil
	}
	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), data, nil
	}
	// Request more data.
	return 0, nil, nil
}
