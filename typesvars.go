package main

import (
	"crypto"
	"hash"
	"io"
	"log"
	"regexp"
)

type Algorithm struct {
	check bool
	name  string
}

type Checksum struct {
	hash crypto.Hash
	hash.Hash
	sum  []byte
	csum []byte // Used only by the -c option
}

type Checksums struct {
	file      string
	checksums []*Checksum
}

var (
	algorithms map[crypto.Hash]*Algorithm
	chosen     []*Checksum
	logger     *log.Logger
	macKey     []byte
)

var opts struct {
	all       bool
	bsd       bool
	check     string
	gnu       bool
	input     string
	ignore    bool
	key       string
	quiet     bool // Used by the -c option
	recursive bool
	status    bool // Used by the -c option
	strict    bool // Used by the -c option
	str       bool
	verbose   bool // Used by the -c option
	version   bool
	warn      bool // Used by the -c option
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
	name2Hash map[string]crypto.Hash
	size2hash = map[int]string{128: "SHA512", 96: "SHA384", 64: "SHA256", 56: "SHA224", 40: "SHA1", 32: "MD5"}
)

// io.ReadCloser compatible interface used for mocking
type ReadCloser struct {
	io.Reader
}

func (r ReadCloser) Close() error {
	return nil
}
