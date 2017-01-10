// (C) 2016 by Ricardo Branco
//
// MIT License
//
// v0.6.4
//
// TODO:
// + Support -c option like md5sum(1)

package main

/*
#cgo CFLAGS: -I/usr/include
#cgo LDFLAGS: -lcrypto -L/usr/lib
#include <openssl/crypto.h>

#if OPENSSL_VERSION_NUMBER >> 20 & 0xff
// This function was renamed in OpenSSL 1.1.0
#undef SSLeay_version
char * SSLeay_version(int t) {
	return OpenSSL_version(t);
}
char * SSLeay_version(int t);
#endif
*/
import "C"

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
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"text/template"
)

const version = "0.6.4"

const (
	BLAKE2b256 = 100 + iota
	BLAKE2b384
	BLAKE2b512
	BLAKE2s256
)

var hashes = []*struct {
	hash   crypto.Hash
	Name   string
	File   string
	Digest string
	hash.Hash
	size int
}{
	{Name: "BLAKE2b256",
		hash: BLAKE2b256,
		size: 32},
	{Name: "BLAKE2b384",
		hash: BLAKE2b384,
		size: 48},
	{Name: "BLAKE2b512",
		hash: BLAKE2b512,
		size: 64},
	{Name: "BLAKE2s256",
		hash: BLAKE2s256,
		size: 32},
	{Name: "MD4",
		hash: crypto.MD4,
		size: 16},
	{Name: "MD5",
		hash: crypto.MD5,
		size: 16},
	{Name: "RIPEMD160",
		hash: crypto.RIPEMD160,
		size: 20},
	{Name: "SHA1",
		hash: crypto.SHA1,
		size: 20},
	{Name: "SHA224",
		hash: crypto.SHA224,
		size: 28},
	{Name: "SHA256",
		hash: crypto.SHA256,
		size: 32},
	{Name: "SHA384",
		hash: crypto.SHA384,
		size: 48},
	{Name: "SHA512",
		hash: crypto.SHA512,
		size: 64},
	{Name: "SHA3-224",
		hash: crypto.SHA3_224,
		size: 28},
	{Name: "SHA3-256",
		hash: crypto.SHA3_256,
		size: 32},
	{Name: "SHA3-384",
		hash: crypto.SHA3_384,
		size: 48},
	{Name: "SHA3-512",
		hash: crypto.SHA3_512,
		size: 64},
}

var progname string

var done chan error

var tmpl = template.New("tmpl")

var zeroFlag *bool

func main() {
	progname = path.Base(os.Args[0])

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] [-s STRING...]|[FILE... DIRECTORY...]\n\n", progname)
		flag.PrintDefaults()
	}

	chosen := make(map[crypto.Hash]*bool)
	for i := range hashes {
		name := strings.ToLower(hashes[i].Name)
		chosen[hashes[i].hash] = flag.Bool(name, false, fmt.Sprintf("%s algorithm", name))
	}

	all := flag.Bool("all", false, "all algorithms")
	isString := flag.Bool("s", false, "treat arguments as strings")
	versionFlag := flag.Bool("version", false, "show version and exit")
	zeroFlag = flag.Bool("0", false, "lines are terminated by a null character")

	var iFlag strFlag
	flag.Var(&iFlag, "i", "read pathnames from file (use '-i \"\"' to read from standard input)")

	var template string
	flag.StringVar(&template, "format", "{{.Name}}({{.File}}) = {{.Digest}}", "output format")

	var macKey []byte
	var keyFlag strFlag
	flag.Var(&keyFlag, "key", "key for HMAC (in hexadecimal). If key starts with '/' read key from specified pathname")

	sizeHashes := map[int]*struct {
		hashes []crypto.Hash
		set    *bool
	}{
		128: {}, 160: {}, 224: {}, 256: {}, 384: {}, 512: {},
	}

	for h := range hashes {
		if hashes[h].hash.Available() {
			sizeHashes[hashes[h].size*8].hashes = append(sizeHashes[hashes[h].size*8].hashes, hashes[h].hash)
		}
	}

	for size := range sizeHashes {
		sizeStr := strconv.Itoa(size)
		if len(sizeHashes[size].hashes) > 0 {
			sizeHashes[size].set = flag.Bool(sizeStr, false, "all "+sizeStr+" bits algorithms")
		}
	}

	flag.Parse()

	if *versionFlag {
		fmt.Printf("%s v%s %s %s %s\n", progname, version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		fmt.Printf("Supported hashes:")
		for h := range hashes {
			switch hashes[h].hash {
			case BLAKE2b256, BLAKE2b384, BLAKE2b512, BLAKE2s256:
				fmt.Printf(" %s", hashes[h].Name)
			default:
				if hashes[h].hash.Available() {
					fmt.Printf(" %s", hashes[h].Name)
				}
			}
		}
		fmt.Println()
		fmt.Printf("%s %s\n", C.GoString(C.SSLeay_version(0)), C.GoString(C.SSLeay_version(2)))
		os.Exit(0)
	}

	if keyFlag.value != nil {
		var err error
		if strings.HasPrefix(*keyFlag.value, "/") {
			macKey, err = ioutil.ReadFile(*keyFlag.value)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: %s: %v\n", progname, *keyFlag.value)
				os.Exit(1)
			}
		} else {
			macKey, err = hex.DecodeString(*keyFlag.value)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: %s: Invalid hexadecimal key: %v\n", progname, *keyFlag.value)
				os.Exit(1)
			}
		}
	}

	template += "\n"
	if (*zeroFlag) {
		template += "\x00"
	}
	template = "{{range .}}" + template + "{{end}}"
	var err error
	tmpl, err = tmpl.Parse(template)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s: Invalid template: %v\n", progname, template)
		os.Exit(1)
	}

	for size := range sizeHashes {
		if !*(sizeHashes[size].set) {
			continue
		}
		for _, h := range sizeHashes[size].hashes {
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
			hashes[i].Hash = blake2_(blake2b.New256, macKey)
		case BLAKE2b384:
			hashes[i].Hash = blake2_(blake2b.New384, macKey)
		case BLAKE2b512:
			hashes[i].Hash = blake2_(blake2b.New512, macKey)
		case BLAKE2s256:
			hashes[i].Hash = blake2_(blake2s.New256, macKey)
		default:
			if !hashes[i].hash.Available() {
				removeHash(hashes[i].hash)
				i--
				continue
			}
			if macKey != nil {
				hashes[i].Hash = hmac.New(hashes[i].hash.New, macKey)
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

	done = make(chan error, len(hashes))
	defer close(done)

	if iFlag.value != nil {
		func(file string) {
			var f *os.File = os.Stdin
			var err error
			if file != "" {
				f, err = os.Open(file)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s: %v\n", progname, err)
					os.Exit(1)
				}
				defer f.Close()
			}
			errors = hashFromFile(f)
		}(*iFlag.value)
	} else if flag.NArg() == 0 {
		hashStdin()
		os.Exit(0)
	}

	if *isString {
		for _, s := range flag.Args() {
			hashString(s)
		}
	} else {
		for _, pathname := range flag.Args() {
			errors = hashPathname(pathname)
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
		fmt.Fprintf(os.Stderr, "ERROR: %s: %v\n", progname, err)
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
	tmpl.Execute(os.Stdout, hashes)
}

func hashString(str string) {
	var wg sync.WaitGroup
	wg.Add(len(hashes))
	for h := range hashes {
		go func(h int) {
			defer wg.Done()
			hashes[h].Write([]byte(str))
			hashes[h].File = "" + str + ""
			hashes[h].Digest = hex.EncodeToString(hashes[h].Sum(nil))
			hashes[h].Reset()
		}(h)
	}
	wg.Wait()
	display()
}

func hashFromFile(f *os.File) (errors bool) {
	var terminator string = "\n"
	if *zeroFlag {
		terminator = "\x00"
	}

	inputReader := bufio.NewReader(f)
	for {
		pathname, err := inputReader.ReadString(terminator[0])
		if err == io.EOF {
			return
		}
		pathname = strings.TrimRight(pathname, terminator)
		errors = hashPathname(pathname)
	}
}

func hashPathname(pathname string) (errors bool) {
	info, err := os.Stat(pathname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progname, err)
		errors = true
	} else if info.IsDir() {
		errors = hashDir(pathname)
	} else {
		errors = hashFile(pathname)
	}
	return
}

func hashFile(filename string) (errors bool) {
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
			hashes[h].File = filename
			hashes[h].Digest = hex.EncodeToString(hashes[h].Sum(nil))
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
		hashFile(path)
	}
	return nil
}

func hashDir(dir string) bool {
	err := filepath.Walk(dir, visit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progname, err)
		return false
	}
	return true
}

func hashStdin() (errors bool) {
	for h := range hashes {
		go func(h int) {
			if _, err := io.Copy(hashes[h], os.Stdin); err != nil {
				done <- err
				return
			}
			hashes[h].File = ""
			hashes[h].Digest = hex.EncodeToString(hashes[h].Sum(nil))
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
