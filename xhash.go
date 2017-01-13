// (C) 2016 by Ricardo Branco
//
// MIT License
//
// v0.7.5

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
)

const version = "0.7.5"

const (
	BLAKE2b256 = 100 + iota
	BLAKE2b384
	BLAKE2b512
	BLAKE2s256
)

// Used with -c option
var checkHashes map[int]bool

var hashes = []*struct {
	check   bool
	hash    crypto.Hash
	name    string
	digest  string
	cDigest string
	size    int
	hash.Hash
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

var opts struct {
	all     bool
	bsd     bool
	gnu     bool
	cFile   strFlag
	iFile   strFlag
	key     strFlag
	str     bool
	version bool
	zero    bool
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
		name := strings.ToLower(hashes[h].name)
		flag.BoolVar(&hashes[h].check, name, false, fmt.Sprintf("%s algorithm", name))
	}

	flag.BoolVar(&opts.all, "all", false, "all algorithms")
	flag.BoolVar(&opts.bsd, "bsd", false, "output hashes in the format used by *BSD")
	flag.BoolVar(&opts.gnu, "gnu", false, "output hashes in the format used by *sum")
	flag.BoolVar(&opts.str, "s", false, "treat arguments as strings")
	flag.BoolVar(&opts.version, "version", false, "show version and exit")
	flag.BoolVar(&opts.zero, "0", false, "lines are terminated by a null character")
	flag.Var(&opts.cFile, "c", "read checksums from file (use '-c \"\"' to read from standard input)")
	flag.Var(&opts.iFile, "i", "read pathnames from file (use '-i \"\"' to read from standard input)")
	flag.Var(&opts.key, "key", "key for HMAC (in hexadecimal). If key starts with '/' read key from specified pathname")

	checkHashes = make(map[int]bool, len(hashes))
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
			fmt.Printf(" %s", hashes[h].name)
		}
		fmt.Println()
		fmt.Printf("%s %s\n", C.GoString(C.SSLeay_version(0)), C.GoString(C.SSLeay_version(2)))
		os.Exit(0)
	}

	if opts.all || choices() == 0 {
		if choices() == 0 {
			for h := range hashes {
				hashes[h].check = true
			}
		} else {
			for h := range hashes {
				hashes[h].check = !hashes[h].check
			}
		}
	}

	var macKey []byte
	if opts.key.string != nil {
		var err error
		if strings.HasPrefix(*opts.key.string, "/") {
			if macKey, err = ioutil.ReadFile(*opts.key.string); err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: %s: %v\n", progname, *opts.key.string)
				os.Exit(1)
			}
		} else {
			if macKey, err = hex.DecodeString(*opts.key.string); err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: %s: Invalid hexadecimal key: %v\n", progname, *opts.key.string)
				os.Exit(1)
			}
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

	var errs bool

	done = make(chan error, choices())
	defer close(done)

	if opts.iFile.string != nil {
		func(file string) {
			f := os.Stdin
			var err error
			if file != "" {
				if f, err = os.Open(file); err != nil {
					fmt.Fprintf(os.Stderr, "%s: %v\n", progname, err)
					os.Exit(1)
				}
				defer f.Close()
			}
			errs = hashFromFile(f)
		}(*opts.iFile.string)
	} else if opts.cFile.string != nil {
		func(file string) {
			f := os.Stdin
			var err error
			if file != "" {
				if f, err = os.Open(file); err != nil {
					fmt.Fprintf(os.Stderr, "%s: %v\n", progname, err)
					os.Exit(1)
				}
				defer f.Close()
			}
			errs = checkFromFile(f)
		}(*opts.cFile.string)
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
			errs = hashPathname(pathname)
		}
	}

	if errs {
		os.Exit(1)
	}
}

type strFlag struct {
	*string
}

func (f *strFlag) Set(s string) error {
	f.string = &s
	return nil
}

func (f *strFlag) String() string {
	if f.string != nil {
		return *f.string
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

// Returns an index for the chosen algorithm when choices() == 0
func chosen() int {
	i := -1
	for h := range hashes {
		if hashes[h].check {
			if i != -1 {
				return -1
			}
			i = h
		}
	}
	return i
}

func escapeFilename(filename string) (prefix string, result string) {
	if strings.ContainsAny(filename, "\n\\") {
		prefix = "\\"
		/* NOTE: Only on pathological cases is this code faster
		r := strings.NewReplacer("\\", "\\\\", "\n", "\\n")
		result = r.Replace(filename)
		*/
		result = strings.Replace(filename, "\\", "\\\\", -1)
		result = strings.Replace(result, "\n", "\\n", -1)
		return
	} else {
		return "", filename
	}
}

func unescapeFilename(filename string) (result string) {
	/* NOTE: Only on pathological cases is this code faster
	r := strings.NewReplacer("\\\\", "\\", "\\n", "\n")
	result = r.Replace(filename)
	*/
	result = strings.Replace(filename, "\\\\", "\\", -1)
	result = strings.Replace(result, "\\n", "\n", -1)
	return
}

func display(file string) {
	if opts.cFile.string == nil {
		terminator := "\n"
		if opts.zero {
			terminator += "\x00"
		}
		for h := range hashes {
			if !hashes[h].check {
				continue
			}
			if opts.bsd {
				fmt.Printf("%s (%s) = %s%s", hashes[h].name, file, hashes[h].digest, terminator)
			} else if opts.gnu {
				prefix, filename := escapeFilename(file)
				fmt.Printf("%s%s  %s%s", prefix, hashes[h].digest, filename, terminator)
			} else {
				fmt.Printf("%s(%s)= %s%s", hashes[h].name, file, hashes[h].digest, terminator)
			}
		}
	} else if file != "" {
		var status string
		for h := range hashes {
			if checkHash(h) {
				if hashes[h].digest != hashes[h].cDigest {
					status = "FAILED" // TODO exit 1
				} else {
					status = "OK"
				}
				prefix, filename := escapeFilename(file)
				fmt.Printf("%s%s: %s %s\n", prefix, filename, hashes[h].name, status)
			}
		}
	}
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
			hashes[h].digest = hex.EncodeToString(hashes[h].Sum(nil))
			hashes[h].Reset()
		}(h)
	}
	wg.Wait()
	display("" + str + "")
}

func hashFromFile(f *os.File) (errs bool) {
	terminator := "\n"
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
		errs = hashPathname(pathname)
	}
}

func hashPathname(pathname string) (errs bool) {
	if info, err := os.Stat(pathname); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progname, err)
		errs = true
	} else if info.IsDir() {
		errs = hashDir(pathname)
	} else {
		errs = hashFile(pathname)
	}
	return
}

func checkHash(h int) bool {
	if hashes[h].check {
		if checkHashes[h] || len(checkHashes) == 0 {
			return true
		} else {
			return false
		}
	} else {
		return false
	}
}

func hashFile(filename string) (errs bool) {
	f, err := os.Open(filename)
	defer f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progname, err)
		return true
	}

	if errs = hashF(f, filename); !errs {
		display(filename)
	}
	return
}

func hashStdin() (errs bool) {
	errs = hashF(os.Stdin, "")
	if !errs {
		display("")
	}
	return
}

func hashF(f *os.File, filename string) (errs bool) {
	var Writers []io.Writer
	var pipeWriters []*io.PipeWriter

	for h := range hashes {
		if !checkHash(h) {
			continue
		}
		pr, pw := io.Pipe()
		Writers = append(Writers, pw)
		pipeWriters = append(pipeWriters, pw)
		go func(h int, r io.Reader) {
			if _, err := io.Copy(hashes[h], r); err != nil {
				done <- err
				return
			}
			hashes[h].digest = hex.EncodeToString(hashes[h].Sum(nil))
			hashes[h].Reset()
			done <- nil
		}(h, pr)
	}

	go func() {
		defer func() {
			for _, pw := range pipeWriters {
				pw.Close()
			}
		}()

		// build the multiwriter for all the pipes
		mw := io.MultiWriter(Writers...)

		// copy the data into the multiwriter
		if _, err := io.Copy(mw, f); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %s: %v\n", progname, err)
		}
	}()

	for h := range hashes {
		if !checkHash(h) {
			continue
		}
		if err := <-done; err != nil {
			if !errs {
				fmt.Fprintf(os.Stderr, "%s: %v\n", progname, err)
				errs = true
			}
		}
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
	if err := filepath.Walk(dir, visit); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progname, err)
		return false
	}
	return true
}

func checkFromFile(f *os.File) (errs bool) {
	var hash, current, file, digest string
	var lineno uint64

	// Format used by OpenSSL dgst and *BSD md5, et al
	bsd := regexp.MustCompile("\\) ?= [0-9a-fA-F]{16,}$")
	// Format used by md5sum, et al
	gnu := regexp.MustCompile("^[\\\\]?[0-9a-fA-F]{16,} [ \\*]")

	inputReader := bufio.NewReader(f)
	for {
		lineno++
		line, err := inputReader.ReadString('\n')
		if err != nil && err != io.EOF {
			panic(err) // XXX
		}
		line = strings.TrimLeft(line, "\x00")
		line = strings.TrimRight(line, "\n")
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
				line = unescapeFilename(line[1:])
			}
			i := strings.Index(line, " ")
			if i < 0 {
				continue
			}
			digest = strings.ToLower(line[:i])
			file = line[i+2:]
			if h := chosen(); h != -1 && len(digest)/2 == hashes[h].size {
				hash = hashes[h].name
			} else {
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
		} else if err != io.EOF {
			fmt.Fprintf(os.Stderr, "ERROR: %s: Unrecognized format at line %d\n", progname, lineno)
			os.Exit(1)
		}

		if current == "" {
			current = file
		}

		h := getIndex(hash)
		if h == -1 {
			continue // XXX
		}

		if current != file || err == io.EOF {
			for k := range checkHashes {
				if hashes[k].check && checkHashes[k] {
					hashFile(current)
					break
				}
			}
			current = file
			for k := range checkHashes {
				checkHashes[k] = false
			}
		}

		checkHashes[h] = true
		hashes[h].cDigest = digest

		if err == io.EOF {
			break
		}
	}

	return
}

func getIndex(name string) int {
	for i := range hashes {
		if hashes[i].name == name {
			return i
		}
	}
	return -1
}
