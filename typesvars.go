package main

import (
	"crypto"
	"hash"
	"regexp"
	"testing/fstest"
	"text/template"
)

// Algorithm type used for tracking algorithms in command line flags
type Algorithm struct {
	check bool
	name  string
}

// Checksum type to hold a checksum
type Checksum struct {
	hash crypto.Hash
	hash.Hash
	written int64
	sum     []byte
	csum    []byte // Used by the -c option
}

// Checksums type to hold the checksums for a file
type Checksums struct {
	file      string
	checksums []*Checksum
}

// Output type with available fields
type Output struct {
	Name string
	File string
	Sum  string
}

// Size type for file size
type Size int

// Constants for sizes
const (
	_       = iota
	KB Size = 1 << (10 * iota)
	MB
	GB
	TB
)

// Constants for hashes not in stdlib
const (
	_ crypto.Hash = 30 + iota // Don't conflict with https://pkg.go.dev/crypto#Hash
	BLAKE3
)

// Keep alphabetically sorted
var hashes = []crypto.Hash{
	crypto.BLAKE2b_256,
	//crypto.BLAKE2b_384,
	crypto.BLAKE2b_512,
	BLAKE3,
	//crypto.MD4,
	crypto.MD5,
	crypto.SHA1,
	//crypto.SHA224,
	crypto.SHA256,
	//crypto.SHA384,
	crypto.SHA512,
	//crypto.SHA512_224,
	crypto.SHA512_256,
	//crypto.SHA3_224,
	crypto.SHA3_256,
	//crypto.SHA3_384,
	crypto.SHA3_512,
}

var (
	algorithms map[crypto.Hash]*Algorithm
	chosen     []*Checksum
	format     = template.New("format")
	fsys       fstest.MapFS
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

// Choose the fastest and more secure.
var better = []crypto.Hash{
	BLAKE3,
	crypto.BLAKE2b_512,
	//crypto.BLAKE2b_384,
	crypto.BLAKE2b_256,
	crypto.SHA512, // SHA512 is faster than SHA256 on some architectures
	//crypto.SHA384,
	crypto.SHA512_256, // Truncated SHA512 has security against length extension attacks
	crypto.SHA256,
	//crypto.SHA512_224, // Truncated SHA512 has security against length extension attacks
	//crypto.SHA224,
	// SHA-3 are slow
	crypto.SHA3_256,
	//crypto.SHA3_224,
	crypto.SHA3_512,
	//crypto.SHA3_384,
	// These are insecure
	crypto.SHA1,
	crypto.MD5,
	crypto.MD4,
}

var regex = struct {
	bsd, gnu *regexp.Regexp
}{
	// Format used by OpenSSL dgst, BSD digest & Solaris digest
	// NOTE: The backslash is added by ourselves if escape the filename
	regexp.MustCompile(`(?s)^([A-Za-z]+[a-z0-9-]*) ?\((.*?)\) ?= ([0-9a-f]{16,})$`),
	// Format used by GNU *sum
	regexp.MustCompile(`(?s)^\\?([0-9a-f]{16,}) [ \*](.*)$`),
}

var (
	insecure  = []crypto.Hash{crypto.MD4, crypto.MD5, crypto.RIPEMD160, crypto.SHA1}
	size2hash = map[int]string{128: "SHA512", 96: "SHA384", 64: "SHA256", 56: "SHA224", 40: "SHA1", 32: "MD5"}
)

var name2Hash = map[string]crypto.Hash{
	"SHA512t256": crypto.SHA512_256,  // Used by FreeBSD's md5
	"BLAKE2b":    crypto.BLAKE2b_512, // Used by GNU coreutils's btsum
}
