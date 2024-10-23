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

// Constants for hashes not in stdlib
const (
	_ crypto.Hash = 30 + iota // Don't conflict with https://pkg.go.dev/crypto#Hash
	BLAKE3
)

// Keep alphabetically sorted
var hashes = []crypto.Hash{
	crypto.BLAKE2b_256,
	crypto.BLAKE2b_384,
	crypto.BLAKE2b_512,
	crypto.BLAKE2s_256,
	BLAKE3,
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
	macKey     []byte
	bsdFormat  string = "{{range .}}{{.Name}} ({{.File}}) = {{.Sum }}\n{{end}}"
	gnuFormat  string = "{{range .}}{{.Sum}}  {{.File}}\n{{end}}"
)

var opts struct {
	all            bool
	base64         bool
	check          string
	format         string
	dummy          bool // Used to support unsupported options
	gnu            bool
	input          string
	ignore         bool
	key            string
	size           bool
	followSymlinks bool // Used by the -r option
	quiet          bool // Used by the -c option
	recursive      bool
	status         bool // Used by the -c option
	strict         bool // Used by the -c option
	str            bool
	tag            bool
	verbose        bool // Used by the -c option
	version        bool
	warn           bool // Used by the -c option
	zero           bool
}

// Used by the -c option

type ErrorAction int

const (
	ErrorIgnore ErrorAction = iota
	ErrorWarn
	ErrorExit
)

// Choose the fastest and more secure.
var better = []crypto.Hash{
	BLAKE3,
	crypto.BLAKE2b_512,
	crypto.BLAKE2b_384,
	crypto.BLAKE2b_256,
	crypto.SHA512, // SHA512 is faster than SHA256 on some architectures
	crypto.SHA384,
	crypto.SHA512_256, // Truncated SHA512 has security against length extension attacks
	crypto.SHA256,
	crypto.SHA512_224, // Truncated SHA512 has security against length extension attacks
	crypto.SHA224,
	// SHA-3 are slow
	crypto.SHA3_256,
	crypto.SHA3_224,
	crypto.SHA3_512,
	crypto.SHA3_384,
	// These are insecure
	crypto.SHA1,
	crypto.MD5,
	crypto.MD4,
}

var regex = struct {
	base64, bsd, gnu *regexp.Regexp
}{
	regexp.MustCompile(`^[g-zG-Z/+]`),
	// Format used by OpenSSL dgst, BSD digest & Solaris digest
	// NOTE: The backslash is added by ourselves if escape the filename
	regexp.MustCompile(`(?s)^([A-Za-z]+[a-z0-9-]*) ?\((.*?)\) ?= ([0-9a-zA-Z/+]{16,}={0,2})$`),
	// Format used by GNU *sum
	regexp.MustCompile(`(?s)^\\?([0-9a-zA-Z/+]{16,}={0,2}) [ \*](.*)$`),
}

var (
	insecure  = []crypto.Hash{crypto.MD4, crypto.MD5, crypto.RIPEMD160, crypto.SHA1}
	size2hash = map[int]string{
		crypto.SHA512.Size(): "SHA512",
		crypto.SHA384.Size(): "SHA384",
		crypto.SHA256.Size(): "SHA256",
		crypto.SHA224.Size(): "SHA224",
		crypto.SHA1.Size():   "SHA1",
		crypto.MD5.Size():    "MD5",
	}
)

var name2Hash = map[string]crypto.Hash{
	"BLAKE2b":     crypto.BLAKE2b_512, // Used by GNU coreutils's btsum
	"BLAKE2s":     crypto.BLAKE2s_256, // Used by NetBSD
	"BLAKE2B-512": crypto.BLAKE2b_512, // Used by OpenSSL's dgst
	"BLAKE2S-256": crypto.BLAKE2s_256, // Used by OpenSSL's dgst
	"SHA2-224":    crypto.SHA224,      // Used by OpenSSL's dgst
	"SHA2-256":    crypto.SHA256,      // Used by OpenSSL's dgst
	"SHA2-384":    crypto.SHA384,      // Used by OpenSSL's dgst
	"SHA2-512":    crypto.SHA512,      // Used by OpenSSL's dgst
	"SHA3-224":    crypto.SHA3_224,    // Used by OpenSSL's dgst
	"SHA3-256":    crypto.SHA3_256,    // Used by OpenSSL's dgst
	"SHA3-384":    crypto.SHA3_384,    // Used by OpenSSL's dgst
	"SHA3-512":    crypto.SHA3_512,    // Used by OpenSSL's dgst
	"SHA512t256":  crypto.SHA512_256,  // Used by FreeBSD's md5
}
