// (C) 2016 by Ricardo Branco
//
// MIT License
//
// v0.7
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
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"text/template"
)

const version = "0.7"

const (
	BLAKE2b256 = 100 + iota
	BLAKE2b384
	BLAKE2b512
	BLAKE2s256
)

// Used with -c option
var check_hashes = make(map[crypto.Hash]bool)

var hashes = []*struct {
	check  bool
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

var opts struct {
	all      bool
	cFile    strFlag
	iFile    strFlag
	key      strFlag
	str      bool
	template string
	version  bool
	zero     bool
}

func init() {
	for i := 0; i < len(hashes); i++ {
		if !hashes[i].hash.Available() {
			removeHash(hashes[i].hash)
			i--
		}
	}

	progname = path.Base(os.Args[0])

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] [-s STRING...]|[FILE... DIRECTORY...]\n\n", progname)
		flag.PrintDefaults()
	}

	for h := range hashes {
		name := strings.ToLower(hashes[h].Name)
		flag.BoolVar(&hashes[h].check, name, false, fmt.Sprintf("%s algorithm", name))
	}

	flag.BoolVar(&opts.all, "all", false, "all algorithms")
	flag.BoolVar(&opts.str, "s", false, "treat arguments as strings")
	flag.BoolVar(&opts.version, "version", false, "show version and exit")
	flag.BoolVar(&opts.zero, "0", false, "lines are terminated by a null character")
	flag.StringVar(&opts.template, "format", "{{.Name}}({{.File}})= {{.Digest}}", "output format")
	flag.Var(&opts.cFile, "c", "read checksums from file and check them")
	flag.Var(&opts.iFile, "i", "read pathnames from file (use '-i \"\"' to read from standard input)")
	flag.Var(&opts.key, "key", "key for HMAC (in hexadecimal). If key starts with '/' read key from specified pathname")
}

func main() {
	sizeHashes := map[int]*bool{
		128: nil, 160: nil, 224: nil, 256: nil, 384: nil, 512: nil,
	}
	for size := range sizeHashes {
		sizeStr := strconv.Itoa(size)
		sizeHashes[size] = flag.Bool(sizeStr, false, "all "+sizeStr+" bits algorithms")
	}

	flag.Parse()

	for h := range hashes {
		if !*sizeHashes[hashes[h].size*8] {
			continue
		} else {
			hashes[h].check = true
		}
	}

	if opts.version {
		fmt.Printf("%s v%s %s %s %s\n", progname, version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		fmt.Printf("Supported hashes:")
		for h := range hashes {
			fmt.Printf(" %s", hashes[h].Name)
		}
		fmt.Println()
		fmt.Printf("%s %s\n", C.GoString(C.SSLeay_version(0)), C.GoString(C.SSLeay_version(2)))
		os.Exit(0)
	}

	var macKey []byte
	if opts.key.value != nil {
		var err error
		if strings.HasPrefix(*opts.key.value, "/") {
			macKey, err = ioutil.ReadFile(*opts.key.value)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: %s: %v\n", progname, *opts.key.value)
				os.Exit(1)
			}
		} else {
			macKey, err = hex.DecodeString(*opts.key.value)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: %s: Invalid hexadecimal key: %v\n", progname, *opts.key.value)
				os.Exit(1)
			}
		}
	}

	template := opts.template
	template += "\n"
	if opts.zero {
		template += "\x00"
	}
	template = "{{range .}}{{if .Digest}}" + template + "{{end}}{{end}}"
	var err error
	tmpl, err = tmpl.Parse(template)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s: Invalid template: %v\n", progname, template)
		os.Exit(1)
	}

	if opts.all || choices() == 0 {
		for h := range hashes {
			hashes[h].check = true
		}
	}

	for i := range hashes {
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
			if macKey != nil {
				hashes[i].Hash = hmac.New(hashes[i].hash.New, macKey)
			} else {
				hashes[i].Hash = hashes[i].hash.New()
			}
		}
	}

	var errors bool

	done = make(chan error, choices())
	defer close(done)

	if opts.iFile.value != nil {
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
		}(*opts.iFile.value)
	} else if opts.cFile.value != nil {
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
			errors = checkFromFile(f)
		}(*opts.cFile.value)
	} else if flag.NArg() == 0 {
		hashStdin()
		os.Exit(0)
	}

	if opts.str {
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

// Returns the number of algorithms chosen
func choices() (n int) {
	for h := range hashes {
		if hashes[h].check {
			n++
		}
	}
	return
}

func display() {
	tmpl.Execute(os.Stdout, hashes)
}

func hashString(str string) {
	var wg sync.WaitGroup
	wg.Add(choices())
	for h := range hashes {
		if !hashes[h].check {
			continue
		}
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
	if opts.zero {
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

func checkHash(h int) bool {
	if _, ok := check_hashes[hashes[h].hash]; ok && hashes[h].check {
		return true
	} else {
		return false
	}
}

func hashFile(filename string) (errors bool) {
	for h := range hashes {
		if !checkHash(h) {
			continue
		}
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
	for h := range hashes {
		if !checkHash(h) {
			continue
		}
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
		if !hashes[h].check {
			continue
		}
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
	for h := range hashes {
		if !hashes[h].check {
			continue
		}
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

func checkFromFile(f *os.File) (errors bool) {
	var terminator string = "\n"
	if opts.zero {
		terminator += "\x00"
	}

	// Format used by OpenSSL dgst and *BSD md5, et al
	bsd := regexp.MustCompile("\\) ?= [0-9a-fA-F]{16,}$")
	// Format used by md5sum, et al
	gnu := regexp.MustCompile("^[\\\\]?[0-9a-fA-F]{16,} [ \\*]")

	var hash, file, digest string
	var previous_file string

	inputReader := bufio.NewReader(f)
	for {
		line, err := inputReader.ReadString(terminator[0])
		if err == io.EOF {
			return
		}
		line = strings.TrimRight(line, terminator)
		if bsd.MatchString(line) {
			i := strings.Index(line, "(")
			if i < 0 {
				continue
			}
			hash = line[:i]
			hash = strings.TrimRight(hash, " ")
			j := strings.LastIndex(line[i:], ")")
			if j < 0 {
				continue
			}
			file = line[i+1 : i+j]
			k := strings.Index(line[i+j:], "= ")
			if k < 0 {
				continue
			}
			digest = strings.ToLower(line[i+j+k+2:])
		} else if gnu.MatchString(line) {
			if strings.HasPrefix(line, "\\") {
				line = line[1:]
				line = strings.Replace(line, "\\\\", "\\", -1)
				line = strings.Replace(line, "\\n", "\n", -1)
			}
			i := strings.Index(line, " ")
			if i < 0 {
				continue
			}
			digest = strings.ToLower(line[:i])
			file = line[i+2:]
			switch len(digest) / 2 {
			case 64:
				hash = "SHA512"
			case 48:
				hash = "SHA384"
			case 32:
				hash = "SHA256"
			case 28:
				hash = "SHA224"
			case 20:
				hash = "SHA1"
			case 16:
				hash = "MD5"
			}
		}

		check_hashes[getHashByName(hash)] = true

		if previous_file != file {
			hashFile(file)
			previous_file = file
			check_hashes = make(map[crypto.Hash]bool)
		}
		h := getHashByName(hash)
		if h == 0 {
			// XXX
			continue
		}
	}
}

func getHashByName(name string) crypto.Hash {
	for h := range hashes {
		if hashes[h].Name == name {
			return hashes[h].hash
		}
	}
	return crypto.Hash(0)
}
