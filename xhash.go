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
	_ "github.com/ricardobranco777/dgst/sha1"
	_ "github.com/ricardobranco777/dgst/sha256"
	_ "github.com/ricardobranco777/dgst/sha512"
	_ "golang.org/x/crypto/sha3"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

const version = "0.9.4"

const (
	BLAKE2b256 = 100 + iota
	BLAKE2b384
	BLAKE2b512
	BLAKE2s256
)

var (
	algorithms  *Bitset // Algorithms chosen in the command line
	checkHashes *Bitset // Algorithms read with the -c option
	chosen      []int
	debug       bool
	macKey      []byte
	progname    string
)

var hashes = []*struct {
	check   bool
	hash    crypto.Hash
	name    string
	digest  string
	cDigest string
	size    int
	hash.Hash
}{
	{name: "BLAKE2b256", hash: BLAKE2b256, size: 32},
	{name: "BLAKE2b384", hash: BLAKE2b384, size: 48},
	{name: "BLAKE2b512", hash: BLAKE2b512, size: 64},
	{name: "BLAKE2s256", hash: BLAKE2s256, size: 32},
	{name: "MD4", hash: crypto.MD4, size: 16},
	{name: "MD5", hash: crypto.MD5, size: 16},
	{name: "SHA1", hash: crypto.SHA1, size: 20},
	{name: "SHA224", hash: crypto.SHA224, size: 28},
	{name: "SHA256", hash: crypto.SHA256, size: 32},
	{name: "SHA384", hash: crypto.SHA384, size: 48},
	{name: "SHA512", hash: crypto.SHA512, size: 64},
	{name: "SHA3-224", hash: crypto.SHA3_224, size: 28},
	{name: "SHA3-256", hash: crypto.SHA3_256, size: 32},
	{name: "SHA3-384", hash: crypto.SHA3_384, size: 48},
	{name: "SHA3-512", hash: crypto.SHA3_512, size: 64},
}

var opts struct {
	all     bool
	bsd     bool
	gnu     bool
	quiet   bool
	status  bool
	str     bool
	verbose bool
	version bool
	zero    bool
	cFile   strFlag
	iFile   strFlag
	key     strFlag
}

func init() {
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
	flag.BoolVar(&opts.verbose, "v", false, "verbose operation (currently useful with the -c option)")
	flag.BoolVar(&opts.version, "version", false, "show version and exit")
	flag.BoolVar(&opts.zero, "0", false, "lines are terminated by a null character")
	flag.Var(&opts.cFile, "c", "read checksums from file (use '-c \"\"' to read from standard input)")
	flag.Var(&opts.iFile, "i", "read pathnames from file (use '-i \"\"' to read from standard input)")
	flag.Var(&opts.key, "key", "key for HMAC (in hexadecimal). If key starts with '/' read key from specified pathname")

	algorithms = NewBitset(len(hashes) - 1)
	checkHashes = NewBitset(len(hashes) - 1)

	debug = os.Getenv("DEBUG") != ""
}

func main() {
	flag.Parse()

	if opts.version {
		fmt.Printf("%s v%s %s %s %s\n", progname, version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		fmt.Printf("Supported hashes:")
		for h := range hashes {
			fmt.Printf(" %s", hashes[h].name)
		}
		fmt.Println()
		fmt.Printf("%s\n", C.GoString(C.SSLeay_version(0)))
		os.Exit(0)
	}

	for h := range hashes {
		if hashes[h].check {
			algorithms.Add(h)
		}
	}

	if opts.all || algorithms.GetCount() == 0 {
		if algorithms.GetCount() == 0 {
			algorithms.SetAll()
		} else {
			for h := range hashes {
				if algorithms.Test(h) {
					algorithms.Del(h)
				} else {
					algorithms.Add(h)
				}
			}
		}
	}
	chosen = algorithms.GetAll()

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
		if opts.cFile.string == nil && !algorithms.Test(h) {
			continue
		}
		initHash(h)
	}

	var errs bool

	if opts.cFile.string != nil {
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
	} else if opts.iFile.string != nil {
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

// Wrapper for the Blake2 New() methods that needs an optional for MAC
func blake2_(f func([]byte) (hash.Hash, error), key []byte) hash.Hash {
	h, err := f(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s: %v\n", progname, err)
		os.Exit(1)
	}
	return h
}

func initHash(h int) {
	if hashes[h].Hash != nil {
		return
	}

	switch hashes[h].hash {
	case BLAKE2b256:
		hashes[h].Hash = blake2_(blake2b.New256, macKey)
	case BLAKE2b384:
		hashes[h].Hash = blake2_(blake2b.New384, macKey)
	case BLAKE2b512:
		hashes[h].Hash = blake2_(blake2b.New512, macKey)
	case BLAKE2s256:
		hashes[h].Hash = blake2_(blake2s.New256, macKey)
	default:
		if macKey != nil {
			hashes[h].Hash = hmac.New(hashes[h].hash.New, macKey)
		} else {
			hashes[h].Hash = hashes[h].hash.New()
		}
	}
}

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
	var prefix string
	if opts.cFile.string == nil {
		zero := ""
		if opts.zero {
			zero = "\x00"
		}
		if opts.gnu {
			prefix, file = escapeFilename(file)
		}
		for _, h := range chosen {
			if opts.bsd {
				fmt.Printf("%s (%s) = %s%s\n", hashes[h].name, file, hashes[h].digest, zero)
			} else if opts.gnu {
				fmt.Printf("%s%s  %s%s\n", prefix, hashes[h].digest, file, zero)
			} else {
				fmt.Printf("%s(%s)= %s%s\n", hashes[h].name, file, hashes[h].digest, zero)
			}
		}
	} else if file != "" {
		prefix, file := escapeFilename(file)
		for _, h := range chosen {
			status := ""
			if checkHashes.Test(h) || checkHashes.GetCount() == 0 {
				if hashes[h].digest != hashes[h].cDigest {
					status = "FAILED"
					if opts.verbose {
						status += " with " + hashes[h].digest
					}
					errs++
				} else {
					if !opts.quiet {
						status = "OK"
					}
				}
				if !opts.status && status != "" {
					fmt.Printf("%s%s: %s %s\n", prefix, file, hashes[h].name, status)
				}
			}
		}
	}
	return
}

func hashString(str string) {
	var wg sync.WaitGroup
	wg.Add(len(chosen))
	for _, h := range chosen {
		go func(h int) {
			defer wg.Done()
			hashes[h].Write([]byte(str))
			hashes[h].digest = hex.EncodeToString(hashes[h].Sum(nil))
			hashes[h].Reset()
		}(h)
	}
	wg.Wait()
	display(`"` + str + `"`)
}

func hashF(f *os.File, filename string) (errs bool) {
	var wg sync.WaitGroup
	var writers []io.Writer
	var pipeWriters []*io.PipeWriter

	for _, h := range chosen {
		if opts.cFile.string != nil && !checkHashes.Test(h) {
			continue
		}
		wg.Add(1)
		pr, pw := io.Pipe()
		writers = append(writers, pw)
		pipeWriters = append(pipeWriters, pw)
		go func(h int, r io.Reader) {
			defer wg.Done()
			if debug {
				defer timeTrack(time.Now(), hashes[h].name)
			}
			if _, err := io.Copy(hashes[h], r); err != nil {
				errs = true
				return
			}
			hashes[h].digest = hex.EncodeToString(hashes[h].Sum(nil))
			hashes[h].Reset()
		}(h, pr)
	}

	go func() {
		wg.Add(1)
		defer wg.Done()
		defer func() {
			for _, pw := range pipeWriters {
				pw.Close()
			}
		}()

		// build the multiwriter for all the pipes
		mw := io.MultiWriter(writers...)

		// copy the data into the multiwriter
		if _, err := io.Copy(mw, f); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %s: %v\n", progname, err)
			errs = true
		}
	}()

	wg.Wait()
	return
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

func hashFile(filename string) (errs int) {
	f, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", progname, err)
		return -1
	}
	defer f.Close()

	if err := hashF(f, filename); !err {
		return display(filename)
	} else {
		errs++
	}
	return
}

func hashStdin() (errs bool) {
	if errs = hashF(os.Stdin, ""); !errs {
		display("")
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

func checkFromFile(f *os.File) (errs bool) {
	var hash, current, file, digest string
	var lineno uint64

	var stats struct {
		unmatched  uint64
		unreadable uint64
	}

	bsdFormat, gnuFormat := opts.bsd, opts.gnu

	// Format used by OpenSSL dgst and *BSD md5, et al
	bsd_begin := regexp.MustCompile(`^[A-Z]+[a-z0-9-]* ?\(`)
	bsd := regexp.MustCompile(`(?ms:^([A-Z]+[a-z0-9-]*) ?\((.*?)\) ?= ([0-9a-f]{16,})$)`)
	// Format used by md5sum, et al
	gnu := regexp.MustCompile(`^[\\]?([0-9a-f]{16,}) [ \*](.*)$`)

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

			if (bsdFormat || !gnuFormat) && bsd_begin.MatchString(line) {
				bsdFormat = true
				if !bsd.MatchString(line) && err == nil {
					continue
				}
			} else {
				gnuFormat = true
			}
			break
		}

		// Auto detect whether -0 was used
		line = strings.TrimPrefix(line, "\n")
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")
		line = strings.TrimSuffix(line, "\x00")

		if bsdFormat && err == nil {
			res := bsd.FindStringSubmatch(line)
			if res == nil {
				badFormat(lineno)
			}
			hash, file, digest = res[1], res[2], strings.ToLower(res[3])
			if strings.HasPrefix(hash, "BLAKE2") {
				switch hash {
				case "BLAKE2b":
					hash = "BLAKE2b512"
				case "BLAKE2b-384":
					hash = "BLAKE2b384"
				case "BLAKE2b-256":
					hash = "BLAKE2b256"
				case "BLAKE2s":
					hash = "BLAKE2s256"
				}
			}
		} else if gnuFormat && err == nil {
			res := gnu.FindStringSubmatch(line)
			if res == nil {
				badFormat(lineno)
			}
			digest, file = strings.ToLower(res[1]), res[2]
			if strings.HasPrefix(line, "\\") {
				file = unescapeFilename(file)
			}
			if len(chosen) == 1 && len(digest)/2 == hashes[chosen[0]].size {
				hash = hashes[chosen[0]].name
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
			badFormat(lineno)
		}

		if current == "" {
			current = file
		}

		h := getHashIndex(hash, len(digest)/2)
		if h == -1 && err == nil {
			continue
		}

		if current != file || err == io.EOF {
			for _, k := range checkHashes.GetAll() {
				if algorithms.Test(k) {
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
			checkHashes.ClearAll()
		}

		if err == io.EOF {
			break
		}

		initHash(h)
		checkHashes.Add(h)
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

func badFormat(lineno uint64) {
	fmt.Fprintf(os.Stderr, "ERROR: %s: Unrecognized format at line %d\n", progname, lineno)
	os.Exit(1)
}

func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("%s took %s", name, elapsed)
}
