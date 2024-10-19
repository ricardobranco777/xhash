package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/hmac"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"hash"
	"io"
	"log"
	"strconv"

	blake3 "github.com/zeebo/blake3"
)

// Wrapper for the Blake2 New() methods that need an optional key for MAC
func blake2(f func([]byte) (hash.Hash, error), key []byte) hash.Hash {
	h, err := f(key)
	if err != nil {
		log.Fatal(err)
	}
	return h
}

func initHash(h *Checksum) {
	switch h.hash {
	case BLAKE3:
		if macKey != nil {
			var err error
			h.Hash, err = blake3.NewKeyed(macKey)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			h.Hash = blake3.New()
		}
	case crypto.BLAKE2s_256:
		h.Hash = blake2(blake2s.New256, macKey)
	case crypto.BLAKE2b_256:
		h.Hash = blake2(blake2b.New256, macKey)
	case crypto.BLAKE2b_384:
		h.Hash = blake2(blake2b.New384, macKey)
	case crypto.BLAKE2b_512:
		h.Hash = blake2(blake2b.New512, macKey)
	default:
		if macKey != nil {
			h.Hash = hmac.New(h.hash.New, macKey)
		} else {
			h.Hash = h.hash.New()
		}
	}
}

// *sum escapes filenames with backslash & newline
func escapeFilename(filename string) string {
	if len(filename) > 0 {
		s := strconv.Quote(filename)
		filename = s[1 : len(s)-1]
	}
	return filename
}

// *sum escapes filenames with backslash & newline
func unescapeFilename(filename string) string {
	if s, err := strconv.Unquote(`"` + filename + `"`); err != nil {
		return filename
	} else {
		return s
	}
}

// Used to support the --format option
func unescape(str string) string {
	if s, err := strconv.Unquote(`"` + str + `"`); err != nil {
		return str
	} else {
		return s
	}
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

// Get scanner for NUL or CR/NL terminated lines
func getScanner(f io.Reader) *bufio.Scanner {
	if opts.zero {
		scanner := bufio.NewScanner(f)
		scanner.Split(scanLinesZ)
		return scanner
	}

	const peekSize = 4200 // Longer than PATH_MAX

	peek := make([]byte, peekSize)
	n, err := f.Read(peek)
	if err != nil && err != io.EOF {
		log.Fatal(err)
		return nil
	}

	var splitFunc bufio.SplitFunc
	// Detect if line is NUL terminated
	if bytes.IndexByte(peek[:n], 0) != -1 {
		splitFunc = scanLinesZ
	} else {
		splitFunc = bufio.ScanLines
	}

	scanner := bufio.NewScanner(io.MultiReader(bytes.NewReader(peek[:n]), f))
	scanner.Split(splitFunc)

	return scanner
}
