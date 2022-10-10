package main

import (
	"crypto"
	"strings"
	"testing"
)

func Test_initHash(t *testing.T) {
	oldChosen := chosen
	chosen = []*Checksum{&Checksum{hash: crypto.SHA256}, &Checksum{hash: crypto.SHA512}}
	defer func() { chosen = oldChosen }()

	for _, h := range getChosen() {
		initHash(h)
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
	xstr := map[string]string{
		"abc":     "abc",
		"a\\c":    "a\\\\c",
		"a\nc":    "a\\nc",
		"a\\b\nc": "a\\\\b\\nc",
	}
	for str := range xstr {
		prefix, got := escapeFilename(str)
		if strings.ContainsAny(str, "\"\n") && prefix != "\\" {
			t.Errorf("prefix in str %s: %s; want: \\", str, prefix)
		}
		if got != xstr[str] {
			t.Errorf("escapeFilename(%s) = %s; want %s", str, got, xstr[str])
		}
	}
}

func Test_unescapeFilename(t *testing.T) {
	xstr := map[string]string{
		"abc":        "abc",
		"a\\\\c":     "a\\c",
		"a\\nc":      "a\nc",
		"a\\\\b\\nc": "a\\b\nc",
	}
	for str := range xstr {
		got := unescapeFilename(str)
		if got != xstr[str] {
			t.Errorf("unescapeFilename(%s) = %s; want %s", str, got, xstr[str])
		}
	}
}
