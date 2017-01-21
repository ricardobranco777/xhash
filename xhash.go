// (C) 2016, 2017 by Ricardo Branco
//
// MIT License

package main

/*
#cgo CFLAGS: -I/usr/include
#cgo LDFLAGS: -lcrypto -L/usr/lib
#include <openssl/crypto.h>

#if OPENSSL_VERSION_NUMBER >> 20 & 0xff
// This function was renamed in OpenSSL 1.1.0
#undef SSLeay_version
const char *SSLeay_version(int t) {
	return OpenSSL_version(t);
}
const char *SSLeay_version(int t);
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
	"github.com/ricardobranco777/dgst/whirlpool"
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

const version = "0.8.3"

const (
	BLAKE2b256 = 100 + iota
	BLAKE2b384
	BLAKE2b512
	BLAKE2s256
	WHIRLPOOL
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
	{name: "WHIRLPOOL",
		hash: WHIRLPOOL,
		size: 64},
}

var progname string

var done chan error

var opts struct {
	all     bool
	bsd     bool
	gnu     bool
	quiet   bool
	status  bool
	cFile   strFlag
	iFile   strFlag
	key     strFlag
	str     bool
	version bool
	zero    bool
}

var sizeHashes map[int]*bool

func init() {
	for i := 0; i < len(hashes); i++ {
		if hashes[i].hash > 99 {
			continue
		}
		if !hashes[i].hash.Available() {
			copy(hashes[i:], hashes[i+1:])
			hashes[len(hashes)-1] = nil // item will be garbage-collected
			hashes = hashes[:len(hashes)-1]
			i--
		}
	}

	progname = path.Base(os.Args[0])

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] [-s STRING...]|[FILE... DIRECTORY...]\n\n", progname)
		flag.PrintDefaults()
	}

	for h := range hashes {
		flag.BoolVar(&hashes[h].check, strings.ToLower(hashes[h].name), false, fmt.Sprintf("%s algorithm", hashes[h].name))
	}

	flag.BoolVar(&opts.all, "all", false, "all algorithms")
	flag.BoolVar(&opts.bsd, "bsd", false, "output hashes in the format used by *BSD")
	flag.BoolVar(&opts.gnu, "gnu", false, "output hashes in the format used by *sum")
	flag.BoolVar(&opts.str, "s", false, "treat arguments as strings")
	flag.BoolVar(&opts.quiet, "quiet", false, "don't print OK for each successfully verified file")
	flag.BoolVar(&opts.status, "status", false, "don't output anything, status code shows success")
	flag.BoolVar(&opts.version, "version", false, "show version and exit")
	flag.BoolVar(&opts.zero, "0", false, "lines are terminated by a null character")
	flag.Var(&opts.cFile, "c", "read checksums from file (use '-c \"\"' to read from standard input)")
	flag.Var(&opts.iFile, "i", "read pathnames from file (use '-i \"\"' to read from standard input)")
	flag.Var(&opts.key, "key", "key for HMAC (in hexadecimal). If key starts with '/' read key from specified pathname")

	sizeHashes = map[int]*bool{
		128: nil, 160: nil, 224: nil, 256: nil, 384: nil, 512: nil,
	}
	for size := range sizeHashes {
		sizeStr := strconv.Itoa(size)
		sizeHashes[size] = flag.Bool(sizeStr, false, "all "+sizeStr+" bits algorithms")
	}

	checkHashes = make(map[int]bool, len(hashes))
}

func main() {
	flag.Parse()

	for h := range hashes {
		if *sizeHashes[hashes[h].size*8] {
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

	for h := range hashes {
		switch hashes[h].hash {
		case BLAKE2b256:
			hashes[h].Hash = blake2_(blake2b.New256, macKey)
		case BLAKE2b384:
			hashes[h].Hash = blake2_(blake2b.New384, macKey)
		case BLAKE2b512:
			hashes[h].Hash = blake2_(blake2b.New512, macKey)
		case BLAKE2s256:
			hashes[h].Hash = blake2_(blake2s.New256, macKey)
		case WHIRLPOOL:
			if macKey != nil {
				hashes[h].Hash = hmac.New(whirlpool.New, macKey)
			} else {
				hashes[h].Hash = whirlpool.New()
			}
		default:
			if macKey != nil {
				hashes[h].Hash = hmac.New(hashes[h].hash.New, macKey)
			} else {
				hashes[h].Hash = hashes[h].hash.New()
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
func _choices() func() int {
	n := 0
	return func() int {
		if n > 0 {
			return n
		}
		for h := range hashes {
			if hashes[h].check {
				n++
			}
		}
		return n
	}
}

// We simulate static variables with closures
var choices = _choices()

// Returns an index for the chosen algorithm when choices() == 1, else return -1
func _chosen() func() int {
	i := -1
	return func() int {
		if i == -1 && choices() == 1 {
			for h := range hashes {
				if hashes[h].check {
					i = h
					break
				}
			}
		}
		return i
	}
}

var chosen = _chosen()

func escapeFilename(filename string) (prefix string, result string) {
	if strings.ContainsAny(filename, "\n\\") {
		prefix = "\\"
		result = strings.Replace(filename, "\\", "\\\\", -1)
		result = strings.Replace(result, "\n", "\\n", -1)
		return
	} else {
		return "", filename
	}
}

func unescapeFilename(filename string) (result string) {
	result = strings.Replace(filename, "\\\\", "\\", -1)
	result = strings.Replace(result, "\\n", "\n", -1)
	return
}

func display(file string) (errs int) {
	if opts.cFile.string == nil {
		zero := ""
		if opts.zero {
			zero = "\x00"
		}
		for h := range hashes {
			if !hashes[h].check {
				continue
			}
			if opts.bsd {
				fmt.Printf("%s (%s) = %s%s\n", hashes[h].name, file, hashes[h].digest, zero)
			} else if opts.gnu {
				prefix, file := escapeFilename(file)
				fmt.Printf("%s%s  %s%s\n", prefix, hashes[h].digest, file, zero)
			} else {
				fmt.Printf("%s(%s)= %s%s\n", hashes[h].name, file, hashes[h].digest, zero)
			}
		}
	} else if file != "" {
		for h := range hashes {
			status := ""
			if checkHash(h) {
				if hashes[h].digest != hashes[h].cDigest {
					status = "FAILED"
					errs++
				} else {
					if !opts.quiet {
						status = "OK"
					}
				}
				if !opts.status && status != "" {
					prefix, filename := escapeFilename(file)
					fmt.Printf("%s%s: %s %s\n", prefix, filename, hashes[h].name, status)
				}
			}
		}
	}
	return
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
		if err != nil {
			if err == io.EOF {
				return
			}
			panic(err)
		}
		pathname = strings.TrimSuffix(pathname, terminator)
		if !opts.zero {
			pathname = strings.TrimSuffix(pathname, "\r")
		}
		errs = hashPathname(pathname)
	}
}

func hashPathname(pathname string) (errs bool) {
	if info, err := os.Stat(pathname); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progname, err)
		errs = true // visit() would fail if we return false
	} else if info.IsDir() {
		errs = hashDir(pathname)
	} else {
		errs = hashFile(pathname) != 0
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

func hashFile(filename string) (errs int) {
	f, err := os.Open(filename)
	defer f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progname, err)
		return -1
	}

	if err := hashF(f, filename); !err {
		return display(filename)
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

	var stats struct {
		unmatched  uint64
		unreadable uint64
	}

	// Format used by OpenSSL dgst and *BSD md5, et al
	bsd_begin := regexp.MustCompile(`^[A-Za-z0-9-]+ ?\(`)
	bsd := regexp.MustCompile(`(?ms:^[A-Za-z0-9-]+ ?\(.*?\) ?= [0-9a-fA-F]{16,}$)`)
	// Format used by md5sum, et al
	gnu := regexp.MustCompile(`^[\\]?[0-9a-fA-F]{16,} [ \*]`)

	terminator := "\n"
	if opts.zero {
		terminator = "\x00"
	}

	inputReader := bufio.NewReader(f)
	for {
		var xline string
		lineno++
		line := ""

		var err error

		for {
			xline, err = inputReader.ReadString(terminator[0])
			if err != nil && err != io.EOF {
				panic(err)
			}

			line += xline

			if bsd_begin.MatchString(line) {
				if !bsd.MatchString(line) && err == nil {
					continue
				}
			}
			break
		}

		// Auto detect whether -0 was used
		line = strings.TrimPrefix(line, "\n")
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")
		line = strings.TrimSuffix(line, "\x00")

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
			// b2sum specifies the size in bits & bt2sum in bytes
			if strings.HasPrefix(hash, "BLAKE2") {
				switch hash {
				case "BLAKE2b-64":
					if len(digest)/2 != 64 {
						break
					}
					fallthrough
				case "BLAKE2b":
					hash = "BLAKE2b512"
				case "BLAKE2b-48":
					if len(digest)/2 != 48 {
						break
					}
					fallthrough
				case "BLAKE2b-384":
					hash = "BLAKE2b384"
				case "BLAKE2b-32":
					if len(digest)/2 != 32 {
						break
					}
					fallthrough
				case "BLAKE2b-256":
					hash = "BLAKE2b256"
				case "BLAKE2s-32":
					if len(digest)/2 != 32 {
						break
					}
					fallthrough
				case "BLAKE2s":
					hash = "BLAKE2s256"
				}
			}
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
		} else if err == nil {
			fmt.Fprintf(os.Stderr, "ERROR: %s: Unrecognized format at line %d\n", progname, lineno)
			os.Exit(1)
		}

		if current == "" {
			current = file
		}

		h := getHashIndex(hash, len(digest)/2)
		if h == -1 && err == nil {
			continue
		}

		if current != file || err == io.EOF {
			for k := range checkHashes {
				if hashes[k].check && checkHashes[k] {
					n := hashFile(current)
					if n < 0 {
						stats.unreadable++
					} else if n > 0 {
						stats.unmatched += uint64(n)
					}
					break
				}
			}
			current = file
			for k := range checkHashes {
				checkHashes[k] = false
			}
		}

		if err == io.EOF {
			break
		}

		checkHashes[h] = true
		hashes[h].cDigest = digest
	}

	plural := ""
	if !opts.status && stats.unreadable > 0 {
		errs = true
		if stats.unreadable > 1 {
			plural = "s"
		}
		fmt.Fprintf(os.Stderr, "%s: WARNING: %d listed file%s could not be read\n", progname, stats.unreadable, plural)
	}
	if !opts.status && stats.unmatched > 0 {
		errs = true
		if stats.unmatched > 1 {
			plural = "s"
		}
		fmt.Fprintf(os.Stderr, "%s: WARNING: %d computed checksum%s did NOT match\n", progname, stats.unmatched, plural)
	}
	return
}

func getHashIndex(name string, size int) int {
	for i := range hashes {
		if hashes[i].size == size && hashes[i].name == name {
			return i
		}
	}
	return -1
}
