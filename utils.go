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

func equal(sum []byte, csum []byte) bool {
	if macKey != nil {
		return hmac.Equal(sum, csum)
	}
	return bytes.Equal(sum, csum)
}

// *sum escapes filenames with backslash & newline
func escapeFilename(filename string) (prefix string, result string) {
	if strings.ContainsAny(filename, "\n\\") {
		return "\\", strings.Replace(strings.Replace(filename, "\\", "\\\\", -1), "\n", "\\n", -1)
	} else {
		return "", filename
	}
}

// *sum escapes filenames with backslash & newline
func unescapeFilename(filename string) string {
	return strings.Replace(strings.Replace(filename, "\\\\", "\\", -1), "\\n", "\n", -1)
}
