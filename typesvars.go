package main

import (
	"crypto"
	"hash"
	"log"
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

type Info struct {
	file      string
	checksums []*Checksum
}

var (
	algorithms map[crypto.Hash]*Algorithm
	chosen     []*Checksum
	logger     *log.Logger
	macKey     []byte
	name2Hash  map[string]crypto.Hash
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
	symlinks  bool // Used by the -r option
	verbose   bool // Used by the -c option
	version   bool
	warn      bool // Used by the -c option
}

var stats struct {
	invalid    uint64
	unmatched  uint64
	unreadable uint64
}
