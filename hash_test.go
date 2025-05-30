package main

import (
	"bytes"
	"crypto"
	"io"
	"reflect"
	"strings"
	"testing"
)

var xchecksum = map[string][]*Checksum{
	"": {
		{
			hash: crypto.MD5,
			csum: []byte{0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e},
		},
		{
			hash: crypto.SHA256,
			csum: []byte{0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55},
		},
	},
}

var hmacKey = []byte{0xab, 0xcd}
var xhmac = map[string][]*Checksum{
	"": {
		{
			hash: crypto.MD5,
			csum: []byte{0xe2, 0x60, 0xf5, 0x76, 0xe1, 0xa6, 0xd2, 0x8b, 0x65, 0x9f, 0xba, 0x8f, 0xa8, 0xc7, 0x09, 0x4e},
		},
		{
			hash: crypto.SHA256,
			csum: []byte{0x6a, 0xcf, 0xf2, 0x42, 0x29, 0xa6, 0xef, 0x2c, 0x5f, 0x26, 0xc0, 0xca, 0xf7, 0xdf, 0xb6, 0x0c, 0x85, 0xd9, 0xc5, 0xbe, 0x9f, 0xe1, 0x94, 0x26, 0xaa, 0x97, 0xb0, 0xac, 0xe1, 0x82, 0x94, 0x76},
		},
	},
}

func testIt(t *testing.T, funcname string, f func(io.ReadCloser, []*Checksum) ([]*Checksum, Size)) {
	// SHA256("The quick brown fox jumps over the lazy dog")
	foxString := "The quick brown fox jumps over the lazy dog"
	foxSha256 := []byte{0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92}

	for checksum := range xchecksum {
		reader := io.NopCloser(strings.NewReader(checksum))
		got, _ := f(reader, xchecksum[checksum][:1])
		if !reflect.DeepEqual(got, xchecksum[checksum][:1]) {
			t.Errorf("%s(%q) got %v, want %v", funcname, checksum, got, xchecksum[checksum][:1])
		}
	}

	// Test with nil (should default to SHA-256)
	reader := io.NopCloser(strings.NewReader(foxString))
	got, _ := f(reader, nil)
	if got[0].hash != crypto.SHA256 || !bytes.Equal(got[0].sum, foxSha256) {
		t.Errorf("%s(%q) got %v, want %v", funcname, foxString, got[0].sum, foxSha256)
	}

	// Test HMAC
	oldKey := macKey
	macKey = hmacKey
	defer func() { macKey = oldKey }()

	for checksum := range xhmac {
		reader := io.NopCloser(strings.NewReader(checksum))
		want := xhmac[checksum][:1]
		got, _ := f(reader, want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s(%q) got %v, want %v", funcname, checksum, got, want)
		}
	}
}

func testIt2(t *testing.T, funcname string, f func(io.ReadCloser, []*Checksum) ([]*Checksum, Size)) {
	for checksum, want := range xchecksum {
		reader := io.NopCloser(strings.NewReader(checksum))
		got, _ := f(reader, want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s(%q) got %v, want %v", funcname, checksum, got, want)
		}
	}

	// Test HMAC
	oldKey := macKey
	macKey = hmacKey
	defer func() { macKey = oldKey }()

	for checksum, want := range xhmac {
		reader := io.NopCloser(strings.NewReader(checksum))
		got, _ := f(reader, want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s(%q) got %v, want %v", funcname, checksum, got, want)
		}
	}
}

func Test_hashF(t *testing.T) {
	testIt(t, "hashF", hashF)
	testIt2(t, "hashF", hashF)
}

func BenchmarkHashes(b *testing.B) {
	buf := make([]byte, 16384)

	for _, h := range hashes {
		checksum := &Checksum{hash: h}
		name := h.String()
		if h == BLAKE3 {
			name = "BLAKE3"
		}
		b.Run(name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				initHash(checksum)
				if _, err := checksum.Write(buf); err != nil {
					panic(err)
				}
				checksum.sum = checksum.Sum(nil)
			}
		})
	}
}
