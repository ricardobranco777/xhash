package main

import (
	"golang.org/x/exp/slices"
	"os"
	"sort"
	"strings"
	"testing"
)

import flag "github.com/spf13/pflag"

func Test_inputFromArgs(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	xinput := [][]string{
		[]string{"xhash", "/etc/passwd"},
		[]string{"xhash", "/etc/passwd", "/etc/services"},
	}

	for _, xstr := range xinput {
		var got []string
		os.Args = xstr
		flag.Parse()
		for input := range inputFromArgs(nil) {
			if input.checksums != nil {
				panic(input.checksums)
			}
			got = append(got, input.file)
		}
		xstr = xstr[1:] // Strip progname
		sort.Sort(sort.StringSlice(got))
		if !slices.Equal(xstr, got) {
			t.Errorf("inputFromArgs(%q) got %v, want %v", xstr, got, xstr)
		}
	}
}

func Test_inputFromFile(t *testing.T) {
	xinput := map[string][]string{
		"/etc/passwd":                      []string{"/etc/passwd"},
		"/etc/passwd\n/etc/services":       []string{"/etc/passwd", "/etc/services"},
		"/etc/passwd\n/etc/services\n":     []string{"/etc/passwd", "/etc/services"},
		"\n/etc/passwd\n/etc/services\n\n": []string{"/etc/passwd", "/etc/services"},
		"/etc/passwd\r\n/etc/services\r\n": []string{"/etc/passwd", "/etc/services"},
	}

	for str := range xinput {
		reader := ReadCloser{strings.NewReader(str)}
		var got []string
		for input := range inputFromFile(reader) {
			if input.checksums != nil {
				panic(input.checksums)
			}
			got = append(got, input.file)
		}
		sort.Sort(sort.StringSlice(got))
		if !slices.Equal(xinput[str], got) {
			t.Errorf("inputFromFile(%q) got %v, want %v", str, got, xinput[str])
		}
	}
}
