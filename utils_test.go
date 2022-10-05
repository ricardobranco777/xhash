package main

import (
	"strings"
	"testing"
)

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
