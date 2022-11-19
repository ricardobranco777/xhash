package main

import (
	"crypto"
	"strings"
	"testing"
)

func Test_initHash(t *testing.T) {
	oldChosen := chosen
	chosen = []*Checksum{{hash: crypto.SHA256}, {hash: crypto.SHA512}}
	defer func() { chosen = oldChosen }()

	for _, h := range getChosen() {
		initHash(h)
		if h == nil {
			t.Errorf("initHash(%v) = nil", h)
		}
	}
}

func Test_initHashes(t *testing.T) {
	oldChosen := chosen
	chosen = []*Checksum{{hash: crypto.SHA256}, {hash: crypto.SHA512}}
	defer func() { chosen = oldChosen }()

	checksums := getChosen()
	initHashes(checksums)
	for _, h := range checksums {
		if h == nil {
			t.Errorf("initHash(%v) = nil", h)
		}
	}
}

func Test_getChosen(t *testing.T) {
	got := getChosen()
	if len(got) != 1 && got[0].hash != crypto.SHA256 {
		t.Errorf("getChosen() = %v; want %v", got[0].hash, crypto.SHA256)
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
		prefix, got := escapeFilename(str)
		if strings.ContainsAny(str, "\\\n") && prefix != "\\" {
			t.Errorf("prefix in str %q got %q; want: \\", str, prefix)
		}
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
