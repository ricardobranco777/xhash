package main

import (
	"io"
	"io/fs"
	"reflect"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
)

func Test_inputFromArgs(t *testing.T) {
	xwant := [][]string{
		{"xhash", "/etc/passwd"},
		{"xhash", "/etc/passwd", "/etc/services"},
	}

	for _, want := range xwant {
		var got []string
		sort.Strings(want)
		for input := range inputFromArgs(want) {
			if input.checksums != nil {
				panic(input.checksums)
			}
			got = append(got, input.file)
		}
		sort.Strings(got)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("inputFromArgs(%q) got %v, want %v", want, got, want)
		}
	}
}

func Test_inputFromDir(t *testing.T) {
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

	// Test without -L option
	var got []string
	for input := range inputFromDir([]string{"."}, false) {
		got = append(got, input.file)
	}
	sort.Strings(got)

	if !reflect.DeepEqual(got, want[:len(want)-1]) {
		t.Errorf("#1 inputFromDir() got %v; want %v", got, want)
	}

	// Test with -L option
	got = nil
	for input := range inputFromDir([]string{"."}, true) {
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
			for input := range inputFromFile(reader, false) {
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
