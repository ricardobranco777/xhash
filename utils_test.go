package main

import (
	"crypto"
	"testing"
)

func Test_initHash(t *testing.T) {
	hashes := []*Checksum{{hash: crypto.SHA256}, {hash: crypto.SHA512}}
	for _, h := range hashes {
		initHash(h)
		if h == nil {
			t.Errorf("initHash(%v) = nil", h)
		}
	}
}

func Test_escapeFilename(t *testing.T) {
	xwant := map[string]string{
		"abc":     "abc",
		"a\\c":    "a\\\\c",
		"a\nc":    "a\\nc",
		"a\\b\nc": "a\\\\b\\nc",
		"a\nb\\c": "a\\nb\\\\c",
	}
	for str, want := range xwant {
		got := escapeFilename(str)
		if got != want {
			t.Errorf("escapeFilename(%q) got %q; want %q", str, got, want)
		}
	}
}

func Test_unescapeFilename(t *testing.T) {
	xwant := map[string]string{
		"abc":        "abc",
		"a\\\\c":     "a\\c",
		"a\\nc":      "a\nc",
		"a\\\\b\\nc": "a\\b\nc",
		"a\\nb\\\\c": "a\nb\\c",
	}
	for str, want := range xwant {
		got := unescapeFilename(str)
		if got != want {
			t.Errorf("unescapeFilename(%q) got %q; want %q", str, got, want)
		}
	}
}
