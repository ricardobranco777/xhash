// (C) 2016 by Ricardo Branco
//
// MIT License
//
// v0.3.3
//
// TODO:
// + Support HMAC
// + Read filenames from file
// + Support -c option like md5sum(1)
// + Use getopt
// + Use different output formats for display

package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"flag"
	"fmt"
	ossl_blake2b "github.com/ricardobranco777/dgst/blake2b"
	ossl_blake2s "github.com/ricardobranco777/dgst/blake2s"
	ossl_md4 "github.com/ricardobranco777/dgst/md4"
	ossl_md5 "github.com/ricardobranco777/dgst/md5"
	ossl_ripemd160 "github.com/ricardobranco777/dgst/ripemd160"
	ossl_sha1 "github.com/ricardobranco777/dgst/sha1"
	ossl_sha256 "github.com/ricardobranco777/dgst/sha256"
	ossl_sha512 "github.com/ricardobranco777/dgst/sha512"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var hashes = map[string]*struct {
	sum string
	hash.Hash
	size int
}{
	"BLAKE2b256": {"", nil, 32},
	"BLAKE2b384": {"", nil, 48},
	"BLAKE2b512": {"", nil, 64},
	"BLAKE2s256": {"", nil, 32},
	"MD4":        {"", nil, 16},
	"MD5":        {"", nil, 16},
	"RIPEMD160":  {"", nil, 20},
	"SHA1":       {"", nil, 20},
	"SHA224":     {"", nil, 28},
	"SHA256":     {"", nil, 32},
	"SHA384":     {"", nil, 48},
	"SHA512":     {"", nil, 64},
	"SHA512-224": {"", nil, 28},
	"SHA512-256": {"", nil, 32},
	"SHA3-224":   {"", nil, 28},
	"SHA3-256":   {"", nil, 32},
	"SHA3-384":   {"", nil, 48},
	"SHA3-512":   {"", nil, 64},
}

// The keys to the above dictionary in sorted order
var keys []string

var progname string

var done chan error

func main() {
	progname = path.Base(os.Args[0])

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] [-s STRING...]|[FILE... DIRECTORY...]\n\n", progname)
		flag.PrintDefaults()
	}

	chosen := make(map[string]*bool)
	for h := range hashes {
		chosen[h] = flag.Bool(strings.ToLower(h), false, fmt.Sprintf("%s algorithm", h))
	}

	var all, ossl, isString *bool
	all = flag.Bool("all", false, "all algorithms")
	ossl = flag.Bool("ossl", false, "use OpenSSL")
	isString = flag.Bool("s", false, "treat arguments as strings")

	var size_hashes = map[int]*struct {
		hashes []string
		set    *bool
	}{
		128: {},
		160: {},
		224: {},
		256: {},
		384: {},
		512: {},
	}

	for h := range hashes {
		size_hashes[hashes[h].size*8].hashes = append(size_hashes[hashes[h].size*8].hashes, h)
	}

	for size := range size_hashes {
		sizeStr := strconv.Itoa(size)
		if len(size_hashes[size].hashes) > 0 {
			size_hashes[size].set = flag.Bool(sizeStr, false, "all "+sizeStr+" bits algorithms")
		}
	}
	var sha3Opt, sha2Opt, blake2Opt *bool
	sha3Opt = flag.Bool("sha3", false, "all SHA-3 algorithms")
	sha2Opt = flag.Bool("sha2", false, "all SHA-2 algorithms")
	blake2Opt = flag.Bool("blake2", false, "all BLAKE2 algorithms")

	flag.Parse()

	for size := range size_hashes {
		if !*(size_hashes[size].set) {
			continue
		}
		for _, h := range size_hashes[size].hashes {
			*chosen[h] = true
		}
	}

	if *sha3Opt {
		for h := range hashes {
			if strings.HasPrefix(h, "SHA3-") {
				*chosen[h] = true
			}
		}
	}
	if *sha2Opt {
		for h := range hashes {
			if strings.HasPrefix(h, "SHA2") || strings.HasPrefix(h, "SHA384") || strings.HasPrefix(h, "SHA512") {
				*chosen[h] = true
			}
		}
	}
	if *blake2Opt {
		for h := range hashes {
			if strings.HasPrefix(h, "BLAKE2") {
				*chosen[h] = true
			}
		}
	}

	if !(*all || choices(chosen)) {
		*all = true
	}

	for h := range chosen {
		if (*all && *chosen[h]) || !(*all || *chosen[h]) {
			delete(hashes, h)
		}
	}

	for k := range hashes {
		keys = append(keys, k)
		switch k {
		case "BLAKE2b256":
			if *ossl {
				hashes[k].Hash = blake2_(ossl_blake2b.New256)
			} else {
				hashes[k].Hash = blake2_(blake2b.New256)
			}
		case "BLAKE2b384":
			if *ossl {
				hashes[k].Hash = blake2_(ossl_blake2b.New384)
			} else {
				hashes[k].Hash = blake2_(blake2b.New384)
			}
		case "BLAKE2b512":
			if *ossl {
				hashes[k].Hash = blake2_(ossl_blake2b.New512)
			} else {
				hashes[k].Hash = blake2_(blake2b.New512)
			}
		case "BLAKE2s256":
			if *ossl {
				hashes[k].Hash = blake2_(ossl_blake2s.New256)
			} else {
				hashes[k].Hash = blake2_(blake2s.New256)
			}
		case "MD4":
			if *ossl {
				hashes[k].Hash = ossl_md4.New()
			} else {
				hashes[k].Hash = md4.New()
			}
		case "MD5":
			if *ossl {
				hashes[k].Hash = ossl_md5.New()
			} else {
				hashes[k].Hash = md5.New()
			}
		case "RIPEMD160":
			if *ossl {
				hashes[k].Hash = ossl_ripemd160.New()
			} else {
				hashes[k].Hash = ripemd160.New()
			}
		case "SHA1":
			if *ossl {
				hashes[k].Hash = ossl_sha1.New()
			} else {
				hashes[k].Hash = sha1.New()
			}
		case "SHA224":
			if *ossl {
				hashes[k].Hash = ossl_sha256.New224()
			} else {
				hashes[k].Hash = sha256.New224()
			}
		case "SHA256":
			if *ossl {
				hashes[k].Hash = ossl_sha256.New()
			} else {
				hashes[k].Hash = sha256.New()
			}
		case "SHA384":
			if *ossl {
				hashes[k].Hash = ossl_sha512.New384()
			} else {
				hashes[k].Hash = sha512.New384()
			}
		case "SHA512":
			if *ossl {
				hashes[k].Hash = ossl_sha512.New()
			} else {
				hashes[k].Hash = sha512.New()
			}
		case "SHA512-224":
			hashes[k].Hash = sha512.New512_224()
		case "SHA512-256":
			hashes[k].Hash = sha512.New512_256()
		case "SHA3-224":
			hashes[k].Hash = sha3.New224()
		case "SHA3-256":
			hashes[k].Hash = sha3.New256()
		case "SHA3-384":
			hashes[k].Hash = sha3.New384()
		case "SHA3-512":
			hashes[k].Hash = sha3.New512()
		}
	}

	sort.Strings(keys)

	if len(hashes) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	if flag.NArg() == 0 {
		hash_stdin()
		os.Exit(0)
	}

	var errors bool

	if *isString {
		for _, s := range flag.Args() {
			hash_string(s)
		}
	} else {
		done = make(chan error, len(hashes))
		defer close(done)

		for _, pathname := range flag.Args() {
			info, err := os.Stat(pathname)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", progname, err)
				errors = true
			} else if info.IsDir() {
				errors = hash_dir(pathname)
			} else {
				errors = hash_file(pathname)
			}
		}
	}

	if errors {
		os.Exit(1)
	}
}

// Wrapper for the Blake2 New() methods that needs an optional for MAC
func blake2_(f func([]byte) (hash.Hash, error)) hash.Hash {
	h, _ := f(nil)
	return h
}

// Returns true if at least some algorithm was specified on the command line
func choices(chosen map[string]*bool) bool {
	for h := range chosen {
		if *chosen[h] {
			return true
		}
	}
	return false
}

func display() {
	for _, k := range keys {
		fmt.Println(hashes[k].sum)
	}
}

func hash_string(str string) {
	var wg sync.WaitGroup
	wg.Add(len(hashes))
	for h := range hashes {
		go func(h string) {
			defer wg.Done()
			hashes[h].Write([]byte(str))
			hashes[h].sum = fmt.Sprintf("%s(\"%s\") = %x", h, str, hashes[h].Sum(nil))
			hashes[h].Reset()
		}(h)
	}
	wg.Wait()
	display()
}

func hash_file(filename string) (errors bool) {
	for h := range hashes {
		go func(h string) {
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
			hashes[h].sum = fmt.Sprintf("%s(%s) = %x", h, filename, hashes[h].Sum(nil))
			hashes[h].Reset()
			done <- nil
		}(h)
	}
	for range hashes {
		err := <-done
		if err != nil {
			if (!errors) {
				fmt.Fprintf(os.Stderr, "%s: %v\n", progname, err)
			}
			errors = true
		}
	}
	if (!errors) {
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
		go func(h string) {
			if _, err := io.Copy(hashes[h], os.Stdin); err != nil {
				done <- err
				return
			}
			hashes[h].sum = fmt.Sprintf("%s() = %x", h, hashes[h].Sum(nil))
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
	if (!errors) {
		display()
	}
	return
}
