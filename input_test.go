package main

import (
	"io"
	"io/fs"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
)

import flag "github.com/spf13/pflag"

func Test_inputFromArgs(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs; flag.Parse() }()

	xwant := [][]string{
		{"xhash", "/etc/passwd"},
		{"xhash", "/etc/passwd", "/etc/services"},
	}

	for _, want := range xwant {
		var got []string
		os.Args = want
		flag.Parse()
		for input := range inputFromArgs(nil) {
			if input.checksums != nil {
				panic(input.checksums)
			}
			got = append(got, input.file)
		}
		want = want[1:] // Strip progname
		sort.Strings(got)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("inputFromArgs(%q) got %v, want %v", want, got, want)
		}
	}
}

func Test_inputFromDir(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs; flag.Parse() }()

	fsys = fstest.MapFS{
		"file.go":          &fstest.MapFile{},
		"folder/file1.go":  {},
		"folder2/file2.go": {},
		"folder2/file3.go": {},
		"folder3/file4.go": {Mode: fs.ModeSymlink},
	}
	defer func() { fsys = nil }()

	var want []string
	for f := range fsys {
		want = append(want, f)
	}
	sort.Strings(want)

	os.Args = []string{"progname", "."}
	flag.Parse()

	// Test without -L option
	var got []string
	for input := range inputFromDir(nil) {
		got = append(got, input.file)
	}
	sort.Strings(got)

	if !reflect.DeepEqual(got, want[:len(want)-1]) {
		t.Errorf("#1 inputFromDir() got %v; want %v", got, want)
	}

	// Test with -L option
	oldSymlinks := opts.symlinks
	opts.symlinks = true
	defer func() { opts.symlinks = oldSymlinks }()

	got = nil
	for input := range inputFromDir(nil) {
		got = append(got, input.file)
	}
	sort.Strings(got)

	if !reflect.DeepEqual(got, want) {
		t.Errorf("#2 inputFromDir() got %v; want %v", got, want)
	}
}

func Test_inputFromFile(t *testing.T) {
	xwant := map[string][]string{
		"/etc/passwd":                      {"/etc/passwd"},
		"/etc/passwd\n/etc/services":       {"/etc/passwd", "/etc/services"},
		"/etc/passwd\n/etc/services\n":     {"/etc/passwd", "/etc/services"},
		"\n/etc/passwd\n/etc/services\n\n": {"/etc/passwd", "/etc/services"},
		"/etc/passwd\r\n/etc/services\r\n": {"/etc/passwd", "/etc/services"},
	}

	for input, want := range xwant {
		for _, str := range []string{input, strings.ReplaceAll(strings.ReplaceAll(input, "\r\n", "\x00"), "\n", "\x00")} {
			reader := io.NopCloser(strings.NewReader(str))
			var got []string
			for input := range inputFromFile(reader) {
				if input.checksums != nil {
					panic(input.checksums)
				}
				got = append(got, input.file)
			}
			sort.Strings(got)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("inputFromFile(%q) got %v; want %v", str, got, want)
			}
		}
	}
}
