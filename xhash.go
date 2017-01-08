// (C) 2016 by Ricardo Branco
//
// MIT License
//
// v0.5
//
// TODO:
// + Support -c option like md5sum(1)
// + Use different output formats for display

package main

import (
	"bufio"
	"crypto"
	"crypto/hmac"
	/*
		_ "crypto/md5"
		_ "crypto/sha1"
		_ "crypto/sha256"
		_ "crypto/sha512"
	*/
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/ricardobranco777/dgst/blake2b"
	"github.com/ricardobranco777/dgst/blake2s"
	_ "github.com/ricardobranco777/dgst/md4"
	_ "github.com/ricardobranco777/dgst/md5"
	_ "github.com/ricardobranco777/dgst/ripemd160"
	_ "github.com/ricardobranco777/dgst/sha1"
	_ "github.com/ricardobranco777/dgst/sha256"
	_ "github.com/ricardobranco777/dgst/sha512"
	/*
		"golang.org/x/crypto/blake2b"
		"golang.org/x/crypto/blake2s"
		_ "golang.org/x/crypto/md4"
		_ "golang.org/x/crypto/ripemd160"
	*/
	_ "golang.org/x/crypto/sha3"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const (
	BLAKE2b256 = 100 + iota
	BLAKE2b384
	BLAKE2b512
	BLAKE2s256
)

var hashes = []*struct {
	hash crypto.Hash
	name string
	sum  string
	hash.Hash
	size int
}{
	{name: "BLAKE2b256",
		hash: BLAKE2b256,
		size: 32},
	{name: "BLAKE2b384",
		hash: BLAKE2b384,
		size: 48},
	{name: "BLAKE2b512",
		hash: BLAKE2b512,
		size: 64},
	{name: "BLAKE2s256",
		hash: BLAKE2s256,
		size: 32},
	{name: "MD4",
		hash: crypto.MD4,
		size: 16},
	{name: "MD5",
		hash: crypto.MD5,
		size: 16},
	{name: "RIPEMD160",
		hash: crypto.RIPEMD160,
		size: 20},
	{name: "SHA1",
		hash: crypto.SHA1,
		size: 20},
	{name: "SHA224",
		hash: crypto.SHA224,
		size: 28},
	{name: "SHA256",
		hash: crypto.SHA256,
		size: 32},
	{name: "SHA384",
		hash: crypto.SHA384,
		size: 48},
	{name: "SHA512",
		hash: crypto.SHA512,
		size: 64},
	{name: "SHA512-224",
		hash: crypto.SHA512_224,
		size: 28},
	{name: "SHA512-256",
		hash: crypto.SHA512_256,
		size: 32},
	{name: "SHA3-224",
		hash: crypto.SHA3_224,
		size: 28},
	{name: "SHA3-256",
		hash: crypto.SHA3_256,
		size: 32},
	{name: "SHA3-384",
		hash: crypto.SHA3_384,
		size: 48},
	{name: "SHA3-512",
		hash: crypto.SHA3_512,
		size: 64},
}

var progname string

var done chan error

var zeroFlag *bool

func main() {
	progname = path.Base(os.Args[0])

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] [-s STRING...]|[FILE... DIRECTORY...]\n\n", progname)
		flag.PrintDefaults()
	}

	chosen := make(map[crypto.Hash]*bool)
	for i := range hashes {
		name := strings.ToLower(hashes[i].name)
		chosen[hashes[i].hash] = flag.Bool(name, false, fmt.Sprintf("%s algorithm", name))
	}

	var all, isString *bool
	all = flag.Bool("all", false, "all algorithms")
	isString = flag.Bool("s", false, "treat arguments as strings")
	zeroFlag = flag.Bool("0", false, "lines are terminated by a null character by using the -c or -i options")

	var files strFlag
	flag.Var(&files, "i", "read pathnames from file")

	var mac_key []byte
	var hexkey strFlag
	flag.Var(&hexkey, "key", "key for HMAC (in hexadecimal)")

	var size_hashes = map[int]*struct {
		hashes []crypto.Hash
		set    *bool
	}{
		128: {}, 160: {}, 224: {}, 256: {}, 384: {}, 512: {},
	}

	for h := range hashes {
		if hashes[h].hash.Available() {
			size_hashes[hashes[h].size*8].hashes = append(size_hashes[hashes[h].size*8].hashes, hashes[h].hash)
		}
	}

	for size := range size_hashes {
		sizeStr := strconv.Itoa(size)
		if len(size_hashes[size].hashes) > 0 {
			size_hashes[size].set = flag.Bool(sizeStr, false, "all "+sizeStr+" bits algorithms")
		}
	}

	flag.Parse()

	if hexkey.value != nil {
		key, err := hex.DecodeString(*hexkey.value)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %s: Invalid hexadecimal key: %v\n", progname, *hexkey.value)
			os.Exit(1)
		}
		mac_key = key
	}

	for size := range size_hashes {
		if !*(size_hashes[size].set) {
			continue
		}
		for _, h := range size_hashes[size].hashes {
			*chosen[h] = true
		}
	}

	if !(*all || choices(chosen)) {
		*all = true
	}

	for h := range chosen {
		if (*all && *chosen[h]) || !(*all || *chosen[h]) {
			removeHash(h)
		}
		delete(chosen, h)
	}

	for i := 0; ; i++ {
		if i >= len(hashes) {
			break
		}
		switch hashes[i].hash {
		case BLAKE2b256:
			hashes[i].Hash = blake2_(blake2b.New256, mac_key)
		case BLAKE2b384:
			hashes[i].Hash = blake2_(blake2b.New384, mac_key)
		case BLAKE2b512:
			hashes[i].Hash = blake2_(blake2b.New512, mac_key)
		case BLAKE2s256:
			hashes[i].Hash = blake2_(blake2s.New256, mac_key)
		default:
			if !hashes[i].hash.Available() {
				removeHash(hashes[i].hash)
				i--
				continue
			}
			if mac_key != nil {
				hashes[i].Hash = hmac.New(hashes[i].hash.New, mac_key)
			} else {
				hashes[i].Hash = hashes[i].hash.New()
			}
		}
	}

	if len(hashes) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	var errors bool

	if files.value != nil {
		done = make(chan error, len(hashes))
		defer close(done)

		errors = hash_fromFile(*files.value)
	} else if flag.NArg() == 0 {
		hash_stdin()
		os.Exit(0)
	}

	if *isString {
		for _, s := range flag.Args() {
			hash_string(s)
		}
	} else {
		done = make(chan error, len(hashes))
		defer close(done)

		for _, pathname := range flag.Args() {
			errors = hash_pathname(pathname)
		}
	}

	if errors {
		os.Exit(1)
	}
}

type strFlag struct {
	value *string
}

func (f *strFlag) Set(value string) error {
	f.value = &value
	return nil
}

func (f *strFlag) String() string {
	if f.value != nil {
		return *f.value
	}
	return ""
}

func removeHash(h crypto.Hash) {
	i := -1
	for i = range hashes {
		if hashes[i].hash == h {
			break
		}
	}
	copy(hashes[i:], hashes[i+1:])
	hashes[len(hashes)-1] = nil // item will be garbage-collected
	hashes = hashes[:len(hashes)-1]
}

// Wrapper for the Blake2 New() methods that needs an optional for MAC
func blake2_(f func([]byte) (hash.Hash, error), key []byte) hash.Hash {
	h, err := f(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s: %v", progname, err)
		os.Exit(1)
	}
	return h
}

// Returns true if at least some algorithm was specified on the command line
func choices(chosen map[crypto.Hash]*bool) bool {
	for h := range chosen {
		if *chosen[h] {
			return true
		}
	}
	return false
}

func display() {
	for i := range hashes {
		fmt.Println(hashes[i].sum)
	}
}

func hash_string(str string) {
	var wg sync.WaitGroup
	wg.Add(len(hashes))
	for h := range hashes {
		go func(h int) {
			defer wg.Done()
			hashes[h].Write([]byte(str))
			hashes[h].sum = fmt.Sprintf("%s(\"%s\") = %x", hashes[h].name, str, hashes[h].Sum(nil))
			hashes[h].Reset()
		}(h)
	}
	wg.Wait()
	display()
}

func hash_fromFile(file string) (errors bool) {
	var terminator string = "\n"
	if *zeroFlag {
		terminator = "\x00"
	}

	f, err := os.Open(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v", progname, err)
	}
	defer f.Close()

	inputReader := bufio.NewReader(f)
	for {
		pathname, err := inputReader.ReadString(terminator[0])
		if err == io.EOF {
			return
		}
		pathname = strings.TrimRight(pathname, terminator)
		errors = hash_pathname(pathname)
	}

	return
}

func hash_pathname(pathname string) (errors bool) {
	info, err := os.Stat(pathname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progname, err)
		errors = true
	} else if info.IsDir() {
		errors = hash_dir(pathname)
	} else {
		errors = hash_file(pathname)
	}
	return
}

func hash_file(filename string) (errors bool) {
	for h := range hashes {
		go func(h int) {
			f, err := os.Open(filename)
			if err != nil {
				done <- err
				return
			}
			defer f.Close()

			if _, err := io.Copy(hashes[h], f); err != nil {
				done <- err
				return
			}
			hashes[h].sum = fmt.Sprintf("%s(%s) = %x", hashes[h].name, filename, hashes[h].Sum(nil))
			hashes[h].Reset()
			done <- nil
		}(h)
	}
	for range hashes {
		err := <-done
		if err != nil {
			if !errors {
				fmt.Fprintf(os.Stderr, "%s: %v\n", progname, err)
			}
			errors = true
		}
	}
	if !errors {
		display()
	}
	return
}

func visit(path string, f os.FileInfo, err error) error {
	if err != nil && !os.IsPermission(err) {
		return err
	}
	if f.Mode().IsRegular() {
		hash_file(path)
	}
	return nil
}

func hash_dir(dir string) bool {
	err := filepath.Walk(dir, visit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progname, err)
		return false
	}
	return true
}

func hash_stdin() (errors bool) {
	for h := range hashes {
		go func(h int) {
			if _, err := io.Copy(hashes[h], os.Stdin); err != nil {
				done <- err
				return
			}
			hashes[h].sum = fmt.Sprintf("%s() = %x", hashes[h].name, hashes[h].Sum(nil))
			hashes[h].Reset()
			done <- nil
		}(h)
	}
	for range hashes {
		err := <-done
		if err != nil {
			if !errors {
				fmt.Fprintf(os.Stderr, "%s: %v\n", progname, err)
			}
			errors = true
		}
	}
	if !errors {
		display()
	}
	return
}
