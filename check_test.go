package main

import (
	"crypto"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
)

func Test_bestHash(t *testing.T) {
	got := bestHash([]*Checksum{
		{hash: crypto.SHA256},
		{hash: crypto.SHA512_256},
	}, 0)
	if got.hash != crypto.SHA512_256 {
		t.Errorf("got %v; want %v", got.hash, crypto.SHA512_256)
	}
	got = bestHash([]*Checksum{
		{hash: crypto.MD5},
		{hash: crypto.SHA256},
	}, 0)
	if got.hash != crypto.SHA256 {
		t.Errorf("got %v; want %v", got.hash, crypto.SHA256)
	}
}

func Test_bestHashes(t *testing.T) {
	got := bestHashes([]*Checksum{
		{hash: crypto.SHA256},
		{hash: crypto.SHA512_256},
	})
	if len(got) != 1 || got[0].hash != crypto.SHA512_256 {
		t.Errorf("got %v; want %v", got[0].hash, crypto.SHA512_256)
	}
	got = bestHashes([]*Checksum{
		{hash: crypto.MD5},
		{hash: crypto.SHA1},
		{hash: crypto.SHA256},
	})
	if len(got) != 1 || got[0].hash != crypto.SHA256 {
		t.Errorf("got %v; want %v", got[0].hash, crypto.SHA256)
	}
	got = bestHashes([]*Checksum{
		{hash: crypto.MD5},
		{hash: crypto.SHA1},
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
	xwant := map[string]*Checksums{
		"44301b466258398bfee1c974a4a40831  /etc/passwd": {
			file: "/etc/passwd",
			checksums: []*Checksum{
				{
					hash: crypto.MD5,
					csum: []byte{0x44, 0x30, 0x1b, 0x46, 0x62, 0x58, 0x39, 0x8b, 0xfe, 0xe1, 0xc9, 0x74, 0xa4, 0xa4, 0x08, 0x31},
				},
			},
		},
		"MD5 (/etc/passwd) = 44301b466258398bfee1c974a4a40832": {
			file: "/etc/passwd",
			checksums: []*Checksum{
				{
					hash: crypto.MD5,
					csum: []byte{0x44, 0x30, 0x1b, 0x46, 0x62, 0x58, 0x39, 0x8b, 0xfe, 0xe1, 0xc9, 0x74, 0xa4, 0xa4, 0x08, 0x32},
				},
			},
		},
		"MD5(/etc/passwd)= 44301b466258398bfee1c974a4a40833": {
			file: "/etc/passwd",
			checksums: []*Checksum{
				{
					hash: crypto.MD5,
					csum: []byte{0x44, 0x30, 0x1b, 0x46, 0x62, 0x58, 0x39, 0x8b, 0xfe, 0xe1, 0xc9, 0x74, 0xa4, 0xa4, 0x08, 0x33},
				},
			},
		},
		"\\44301b466258398bfee1c974a4a40834  /etc/\\npasswd": {
			file: "/etc/\npasswd",
			checksums: []*Checksum{
				{
					hash: crypto.MD5,
					csum: []byte{0x44, 0x30, 0x1b, 0x46, 0x62, 0x58, 0x39, 0x8b, 0xfe, 0xe1, 0xc9, 0x74, 0xa4, 0xa4, 0x08, 0x34},
				},
			},
		},
	}
	oldChosen := chosen
	defer func() { chosen = oldChosen }()
	chosen = nil

	for line, want := range xwant {
		got := parseLine(line, lineno)
		if got == nil {
			panic("nil")
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("parseLine(%q) got %v, want %v", line, got, want)
		}
	}
}

func Test_inputFromCheck(t *testing.T) {
	xinput := map[string][]*Checksums{
		"44301b466258398bfee1c974a4a40831  /etc/passwd": {
			{
				file: "/etc/passwd",
				checksums: []*Checksum{
					{
						hash: crypto.MD5,
						csum: []byte{0x44, 0x30, 0x1b, 0x46, 0x62, 0x58, 0x39, 0x8b, 0xfe, 0xe1, 0xc9, 0x74, 0xa4, 0xa4, 0x08, 0x31},
					},
				},
			},
		},
		"MD5 (/etc/passwd) = 44301b466258398bfee1c974a4a40832\nSHA256(/etc/passwd) = fab8488def7282a75f223a062ec37acc5e35177d0645a9aaf0dc6ca27ae18dbf": {
			{
				file: "/etc/passwd",
				checksums: []*Checksum{
					{
						hash: crypto.SHA256,
						csum: []byte{0xfa, 0xb8, 0x48, 0x8d, 0xef, 0x72, 0x82, 0xa7, 0x5f, 0x22, 0x3a, 0x06, 0x2e, 0xc3, 0x7a, 0xcc, 0x5e, 0x35, 0x17, 0x7d, 0x06, 0x45, 0xa9, 0xaa, 0xf0, 0xdc, 0x6c, 0xa2, 0x7a, 0xe1, 0x8d, 0xbf},
					},
				},
			},
		},
		"SHA256 (/etc/passwd)= fab8488def7282a75f223a062ec37acc5e35177d0645a9aaf0dc6ca27ae18dbf\nSHA512-256(/etc/passwd) = 946097b17deb2745bb78a1a62bc35a14d2a39218514a16764880fff12b26b2fb\n": {
			{
				file: "/etc/passwd",
				checksums: []*Checksum{
					{
						hash: crypto.SHA512_256,
						csum: []byte{0x94, 0x60, 0x97, 0xb1, 0x7d, 0xeb, 0x27, 0x45, 0xbb, 0x78, 0xa1, 0xa6, 0x2b, 0xc3, 0x5a, 0x14, 0xd2, 0xa3, 0x92, 0x18, 0x51, 0x4a, 0x16, 0x76, 0x48, 0x80, 0xff, 0xf1, 0x2b, 0x26, 0xb2, 0xfb},
					},
				},
			},
		},
		"MD5 (/etc/passwd) = 44301b466258398bfee1c974a4a40831\nSHA1 (/etc/passwd) = 5a9695f925c683e7a4f6fce8ca006529e6bd6b9f\n": {
			{
				file: "/etc/passwd",
				checksums: []*Checksum{
					{
						hash: crypto.MD5,
						csum: []byte{0x44, 0x30, 0x1b, 0x46, 0x62, 0x58, 0x39, 0x8b, 0xfe, 0xe1, 0xc9, 0x74, 0xa4, 0xa4, 0x08, 0x31},
					},
					{
						hash: crypto.SHA1,
						csum: []byte{0x5a, 0x96, 0x95, 0xf9, 0x25, 0xc6, 0x83, 0xe7, 0xa4, 0xf6, 0xfc, 0xe8, 0xca, 0x00, 0x65, 0x29, 0xe6, 0xbd, 0x6b, 0x9f},
					},
				},
			},
		},
		"44301b466258398bfee1c974a4a40831  /etc/passwd\n5a9695f925c683e7a4f6fce8ca006529e6bd6b9f  /etc/passwd\n3975f0d8c4e1ecb25f035edfb1ba27ac  /etc/services\na0d7a229bf049f7fe17e8445226236e4024535d0  /etc/services\n": {
			{
				file: "/etc/passwd",
				checksums: []*Checksum{
					{
						hash: crypto.MD5,
						csum: []byte{0x44, 0x30, 0x1b, 0x46, 0x62, 0x58, 0x39, 0x8b, 0xfe, 0xe1, 0xc9, 0x74, 0xa4, 0xa4, 0x08, 0x31},
					},
					{
						hash: crypto.SHA1,
						csum: []byte{0x5a, 0x96, 0x95, 0xf9, 0x25, 0xc6, 0x83, 0xe7, 0xa4, 0xf6, 0xfc, 0xe8, 0xca, 0x00, 0x65, 0x29, 0xe6, 0xbd, 0x6b, 0x9f},
					},
				},
			},
			{
				file: "/etc/services",
				checksums: []*Checksum{
					{
						hash: crypto.MD5,
						csum: []byte{0x39, 0x75, 0xf0, 0xd8, 0xc4, 0xe1, 0xec, 0xb2, 0x5f, 0x03, 0x5e, 0xdf, 0xb1, 0xba, 0x27, 0xac},
					},
					{
						hash: crypto.SHA1,
						csum: []byte{0xa0, 0xd7, 0xa2, 0x29, 0xbf, 0x04, 0x9f, 0x7f, 0xe1, 0x7e, 0x84, 0x45, 0x22, 0x62, 0x36, 0xe4, 0x02, 0x45, 0x35, 0xd0},
					},
				},
			},
		},
	}
	oldChosen := chosen
	defer func() { chosen = oldChosen }()
	chosen = nil

	for input, want := range xinput {
		for _, str := range []string{input} {
			reader := io.NopCloser(strings.NewReader(str))
			for got := range inputFromCheck(reader) {
				// Goroutines may return randomized stuff so swap if needed
				i := 0
				if len(want) > 1 && got.file != want[0].file {
					i = 1
				}
				if len(got.checksums) > 1 && got.checksums[0].hash != want[i].checksums[0].hash {
					got.checksums[0], got.checksums[1] = got.checksums[1], got.checksums[0]
				}
				if !reflect.DeepEqual(got, want[i]) {
					fmt.Printf("line: %q\ngot: %v\nwant:%v\n", str, got, want[i])
					t.Errorf("inputFromCheck(%q) got %v, want %v", str, got.checksums[0], want[i].checksums[0])
				}
			}
		}
	}
}
