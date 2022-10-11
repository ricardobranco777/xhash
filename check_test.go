package main

import (
	"bytes"
	"crypto"
	"golang.org/x/exp/slices"
	"strings"
	"testing"
)

func Test_bestHash(t *testing.T) {
	got := bestHash([]*Checksum{
		&Checksum{hash: crypto.SHA256},
		&Checksum{hash: crypto.SHA512_256},
	}, 0)
	if got.hash != crypto.SHA256 {
		t.Errorf("got %v; want %v", got.hash, crypto.SHA256)
	}
	got = bestHash([]*Checksum{
		&Checksum{hash: crypto.MD5},
		&Checksum{hash: crypto.SHA256},
	}, 0)
	if got.hash != crypto.SHA256 {
		t.Errorf("got %v; want %v", got.hash, crypto.SHA256)
	}
}

func Test_bestHashes(t *testing.T) {
	got := bestHashes([]*Checksum{
		&Checksum{hash: crypto.SHA256},
		&Checksum{hash: crypto.SHA512_256},
	})
	if len(got) != 1 || got[0].hash != crypto.SHA256 {
		t.Errorf("got %v; want %v", got[0].hash, crypto.SHA256)
	}
	got = bestHashes([]*Checksum{
		&Checksum{hash: crypto.MD5},
		&Checksum{hash: crypto.SHA1},
		&Checksum{hash: crypto.SHA256},
	})
	if len(got) != 1 || got[0].hash != crypto.SHA256 {
		t.Errorf("got %v; want %v", got[0].hash, crypto.SHA256)
	}
	got = bestHashes([]*Checksum{
		&Checksum{hash: crypto.MD5},
		&Checksum{hash: crypto.SHA1},
	})
	if len(got) != 2 || got[0].hash != crypto.SHA1 || got[1].hash != crypto.MD5 {
		t.Errorf("got %v; want %v", got, "I want it all")
	}
}

func Test_isChosen(t *testing.T) {
	if !isChosen(crypto.SHA256) {
		t.Errorf("ischosen(%v) = false; want true", crypto.SHA256)
	}
}

func Test_parseLine(t *testing.T) {
	lineno := uint64(1)
	xinput := map[string]*Checksums{
		"44301b466258398bfee1c974a4a40831  /etc/passwd": &Checksums{
			file: "/etc/passwd",
			checksums: []*Checksum{
				&Checksum{
					hash: crypto.MD5,
					csum: []byte{0x44, 0x30, 0x1b, 0x46, 0x62, 0x58, 0x39, 0x8b, 0xfe, 0xe1, 0xc9, 0x74, 0xa4, 0xa4, 0x08, 0x31},
				},
			},
		},
		"MD5(/etc/passwd) = 44301b466258398bfee1c974a4a40832": &Checksums{
			file: "/etc/passwd",
			checksums: []*Checksum{
				&Checksum{
					hash: crypto.MD5,
					csum: []byte{0x44, 0x30, 0x1b, 0x46, 0x62, 0x58, 0x39, 0x8b, 0xfe, 0xe1, 0xc9, 0x74, 0xa4, 0xa4, 0x08, 0x32},
				},
			},
		},
		"MD5(/etc/passwd)= 44301b466258398bfee1c974a4a40833": &Checksums{
			file: "/etc/passwd",
			checksums: []*Checksum{
				&Checksum{
					hash: crypto.MD5,
					csum: []byte{0x44, 0x30, 0x1b, 0x46, 0x62, 0x58, 0x39, 0x8b, 0xfe, 0xe1, 0xc9, 0x74, 0xa4, 0xa4, 0x08, 0x33},
				},
			},
		},
	}
	oldChosen := chosen
	defer func() { chosen = oldChosen }()
	chosen = nil

	for line := range xinput {
		got := parseLine(line, lineno)
		if got == nil {
			panic("nil")
		}
		if got.file != xinput[line].file || !slices.EqualFunc(got.checksums, xinput[line].checksums, func(s1, s2 *Checksum) bool {
			return s1.hash == s2.hash && bytes.Equal(s1.csum, s2.csum)
		}) {
			t.Errorf("parseLine(%q) got %v, want %v", line, got, xinput[line])
		}
	}
}

func Test_inputFromCheck(t *testing.T) {
	xinput := map[string]*Checksums{
		"44301b466258398bfee1c974a4a40831  /etc/passwd": &Checksums{
			file: "/etc/passwd",
			checksums: []*Checksum{
				&Checksum{
					hash: crypto.MD5,
					csum: []byte{0x44, 0x30, 0x1b, 0x46, 0x62, 0x58, 0x39, 0x8b, 0xfe, 0xe1, 0xc9, 0x74, 0xa4, 0xa4, 0x08, 0x31},
				},
			},
		},
		"MD5(/etc/passwd) = 44301b466258398bfee1c974a4a40832\nSHA256(/etc/passwd) = fab8488def7282a75f223a062ec37acc5e35177d0645a9aaf0dc6ca27ae18dbf": &Checksums{
			file: "/etc/passwd",
			checksums: []*Checksum{
				&Checksum{
					hash: crypto.SHA256,
					csum: []byte{0xfa, 0xb8, 0x48, 0x8d, 0xef, 0x72, 0x82, 0xa7, 0x5f, 0x22, 0x3a, 0x06, 0x2e, 0xc3, 0x7a, 0xcc, 0x5e, 0x35, 0x17, 0x7d, 0x06, 0x45, 0xa9, 0xaa, 0xf0, 0xdc, 0x6c, 0xa2, 0x7a, 0xe1, 0x8d, 0xbf},
				},
			},
		},
		"SHA256(/etc/passwd)= fab8488def7282a75f223a062ec37acc5e35177d0645a9aaf0dc6ca27ae18dbf\nSHA512-256(/etc/passwd) = 946097b17deb2745bb78a1a62bc35a14d2a39218514a16764880fff12b26b2fb\n": &Checksums{
			file: "/etc/passwd",
			checksums: []*Checksum{
				&Checksum{
					hash: crypto.SHA256,
					csum: []byte{0xfa, 0xb8, 0x48, 0x8d, 0xef, 0x72, 0x82, 0xa7, 0x5f, 0x22, 0x3a, 0x06, 0x2e, 0xc3, 0x7a, 0xcc, 0x5e, 0x35, 0x17, 0x7d, 0x06, 0x45, 0xa9, 0xaa, 0xf0, 0xdc, 0x6c, 0xa2, 0x7a, 0xe1, 0x8d, 0xbf},
				},
			},
		},
	}
	oldChosen := chosen
	defer func() { chosen = oldChosen }()
	chosen = nil

	for line := range xinput {
		reader := ReadCloser{strings.NewReader(line)}
		for got := range inputFromCheck(reader) {
			if got == nil {
				panic("nil")
			}
			if got.file != xinput[line].file || !slices.EqualFunc(got.checksums, xinput[line].checksums, func(s1, s2 *Checksum) bool {
				return s1.hash == s2.hash && bytes.Equal(s1.csum, s2.csum)
			}) {
				t.Errorf("parseLine(%q) got %v, want %v", line, got, xinput[line])
			}
		}
	}
}
