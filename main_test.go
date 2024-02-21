package main

import (
	"crypto"
	"log"
	"strings"
	"testing"
	"text/template"
)

func Test_getOutput(t *testing.T) {
	results := &Checksums{
		file: "/etc/passwd",
		checksums: []*Checksum{
			{
				hash: crypto.MD5,
				sum:  []byte{0x44, 0x30, 0x1b, 0x46, 0x62, 0x58, 0x39, 0x8b, 0xfe, 0xe1, 0xc9, 0x74, 0xa4, 0xa4, 0x08, 0x31},
			},
			{
				hash: crypto.SHA256,
				sum:  []byte{0xfa, 0xb8, 0x48, 0x8d, 0xef, 0x72, 0x82, 0xa7, 0x5f, 0x22, 0x3a, 0x06, 0x2e, 0xc3, 0x7a, 0xcc, 0x5e, 0x35, 0x17, 0x7d, 0x06, 0x45, 0xa9, 0xaa, 0xf0, 0xdc, 0x6c, 0xa2, 0x7a, 0xe1, 0x8d, 0xbf},
			},
		},
	}

	templates := map[string]string{
		// OpenSSL dgst
		"{{range .}}{{.Name}}({{.File}}) = {{.Sum}}\n{{end}}": "MD5(/etc/passwd) = 44301b466258398bfee1c974a4a40831\nSHA256(/etc/passwd) = fab8488def7282a75f223a062ec37acc5e35177d0645a9aaf0dc6ca27ae18dbf\n",
		// BSD digest
		"{{range .}}{{.Name}} ({{.File}}) = {{.Sum}}\n{{end}}": "MD5 (/etc/passwd) = 44301b466258398bfee1c974a4a40831\nSHA256 (/etc/passwd) = fab8488def7282a75f223a062ec37acc5e35177d0645a9aaf0dc6ca27ae18dbf\n",
		// md5sum et al
		"{{range .}}{{.Sum}}  {{.File}}\n{{end}}": "44301b466258398bfee1c974a4a40831  /etc/passwd\nfab8488def7282a75f223a062ec37acc5e35177d0645a9aaf0dc6ca27ae18dbf  /etc/passwd\n",
	}

	for str, want := range templates {
		format := template.New(str)
		format, err := format.Parse(str)
		if err != nil {
			log.Fatal(err)
		}
		b := new(strings.Builder)
		format.Execute(b, getOutput(results))
		if b.String() != want {
			t.Errorf("got %v; want %v", b.String(), want)
		}
	}

	for str, want := range templates {
		str = strings.ReplaceAll(strings.ReplaceAll(str, "\r\n", "\x00"), "\n", "\x00")
		want = strings.ReplaceAll(strings.ReplaceAll(want, "\r\n", "\x00"), "\n", "\x00")
		format := template.New(str)
		format, err := format.Parse(str)
		if err != nil {
			log.Fatal(err)
		}
		b := new(strings.Builder)
		format.Execute(b, getOutput(results))
		if b.String() != want {
			t.Errorf("got %v; want %v", b.String(), want)
		}
	}

}
