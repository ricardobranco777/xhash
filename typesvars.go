package main

import (
	"crypto"
	"hash"
	"io"
	"log"
	"regexp"
	"testing/fstest"
	"text/template"
)

type Algorithm struct {
	check bool
	name  string
}

type Checksum struct {
	hash crypto.Hash
	hash.Hash
	written int64
	sum     []byte
	csum    []byte // Used by the -c option
}

type Checksums struct {
	file      string
	checksums []*Checksum
}

type Output struct {
	Name string
	File string
	Sum  string
}

var hashes = []crypto.Hash{
	crypto.BLAKE2b_256,
	crypto.BLAKE2b_384,
	crypto.BLAKE2b_512,
	//crypto.MD4,
	crypto.MD5,
	crypto.SHA1,
	crypto.SHA224,
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
	crypto.SHA512_224,
	crypto.SHA512_256,
	crypto.SHA3_224,
	crypto.SHA3_256,
	crypto.SHA3_384,
	crypto.SHA3_512,
}

var (
	algorithms map[crypto.Hash]*Algorithm
	chosen     []*Checksum
	format     = template.New("format")
	fsys       fstest.MapFS
	logger     *log.Logger
	macKey     []byte
	bsdFormat  string = "{{range .}}{{.Name}} ({{.File}}) = {{.Sum }}\n{{end}}"
	gnuFormat  string = "{{range .}}{{.Sum}}  {{.File}}\n{{end}}"
)

var opts struct {
	all       bool
	check     string
	format    string
	dummy     bool // Used to support unsupported options
	gnu       bool
	input     string
	ignore    bool
	key       string
	size      bool
	symlinks  bool // Used by the -r option
	quiet     bool // Used by the -c option
	recursive bool
	status    bool // Used by the -c option
	strict    bool // Used by the -c option
	str       bool
	tag       bool
	verbose   bool // Used by the -c option
	version   bool
	warn      bool // Used by the -c option
	zero      bool
}

var stats struct {
	invalid    uint64
	unmatched  uint64
	unreadable uint64
}

// Used by the -c option

var regex = struct {
	bsd, gnu *regexp.Regexp
}{
	regexp.MustCompile(`^([A-Z]+[a-z0-9-]*) ?\((.*?)\) ?= ([0-9a-f]{16,})$`), // Format used by OpenSSL dgst and *BSD md5, et al
	regexp.MustCompile(`^[\\]?([0-9a-f]{16,}) [ \*](.*)$`),                   // Format used by md5sum, et al
}

var (
	insecure  = []crypto.Hash{crypto.MD4, crypto.MD5, crypto.RIPEMD160, crypto.SHA1}
	size2hash = map[int]string{128: "SHA512", 96: "SHA384", 64: "SHA256", 56: "SHA224", 40: "SHA1", 32: "MD5"}
)

var name2Hash = map[string]crypto.Hash{
	"SHA512t256": crypto.SHA512_256,  // Used by FreeBSD's md5
	"BLAKE2b":    crypto.BLAKE2b_512, // Used by GNU coreutils's btsum
}

// io.ReadCloser compatible interface used for mocking
type ReadCloser struct {
	io.Reader
}

func (r ReadCloser) Close() error {
	return nil
}
