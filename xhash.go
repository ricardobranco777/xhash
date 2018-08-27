// (C) 2016, 2017, 2018 by Ricardo Branco
//
// MIT License

package main

/*
#cgo pkg-config: libcrypto
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
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/subtle"
	"encoding/hex"
	"flag"
	"fmt"
	_ "github.com/ricardobranco777/dgst/md5"
	_ "github.com/ricardobranco777/dgst/sha1"
	_ "github.com/ricardobranco777/dgst/sha256"
	_ "github.com/ricardobranco777/dgst/sha512"
	"golang.org/x/crypto/blake2b"
	_ "golang.org/x/crypto/sha3"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

const version = "1.0"

const (
	BLAKE2b256 = 100 + iota
	BLAKE2b384
	BLAKE2b512
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
	digest  []byte
	cDigest []byte
	size    int
	hash.Hash
}{
	{name: "BLAKE2b256", hash: BLAKE2b256, size: 32},
	{name: "BLAKE2b384", hash: BLAKE2b384, size: 48},
	{name: "BLAKE2b512", hash: BLAKE2b512, size: 64},
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
	recurse bool
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
	progname = filepath.Base(os.Args[0])

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] [-s STRING...]|[FILE... DIRECTORY...]\n\n", progname)
		flag.PrintDefaults()
	}

	for h := range hashes {
		flag.BoolVar(&hashes[h].check, strings.ToLower(hashes[h].name), false, hashes[h].name+" algorithm")
	}

	flag.BoolVar(&opts.all, "all", false, "all algorithms (except others specified, if any)")
	flag.BoolVar(&opts.bsd, "bsd", false, "output hashes in the format used by *BSD")
	flag.BoolVar(&opts.gnu, "gnu", false, "output hashes in the format used by *sum")
	flag.BoolVar(&opts.recurse, "r", false, "recurse into directories")
	flag.BoolVar(&opts.str, "s", false, "treat arguments as strings")
	flag.BoolVar(&opts.quiet, "quiet", false, "don't print OK for each successfully verified file")
	flag.BoolVar(&opts.status, "status", false, "don't output anything, status code shows success")
	flag.BoolVar(&opts.verbose, "v", false, "verbose operation (currently useful with the -c option)")
	flag.BoolVar(&opts.version, "version", false, "show version and exit")
	flag.BoolVar(&opts.zero, "0", false, "lines are terminated by a null character (with the -i option)")
	flag.Var(&opts.cFile, "c", "read checksums from file (use '-c \"\"' to read from standard input)")
	flag.Var(&opts.iFile, "i", "read pathnames from file (use '-i \"\"' to read from standard input)")
	flag.Var(&opts.key, "key", "key for HMAC (in hexadecimal). If key starts with '"+string(os.PathSeparator)+"' read key from specified pathname")

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

	if opts.key.isSet() {
		var err error
		key := opts.key.String()
		if strings.HasPrefix(key, string(os.PathSeparator)) {
			if macKey, err = ioutil.ReadFile(key); err != nil {
				perror("%v", err)
				os.Exit(1)
			}
		} else {
			if macKey, err = hex.DecodeString(key); err != nil {
				perror("%v", err)
				os.Exit(1)
			}
		}
	}

	for h := range hashes {
		if !opts.cFile.isSet() && !algorithms.Test(h) {
			continue
		}
		initHash(h)
	}

	var errs bool

	if opts.cFile.isSet() {
		errs = checkFromFile(opts.cFile.String()) != 0
	} else if opts.iFile.isSet() {
		errs = hashFromFile(opts.cFile.String()) != 0
	} else if flag.NArg() == 0 {
		errs = hashStdin()
	}

	if opts.str {
		for _, s := range flag.Args() {
			hashString(s)
		}
	} else {
		for _, pathname := range flag.Args() {
			errs = hashPathname(pathname) != 0
		}
	}

	if errs {
		os.Exit(1)
	}
}

func perror(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "%s: ", progname)
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// Wrapper for the Blake2 New() methods that need an optional key for MAC
func blake2_(f func([]byte) (hash.Hash, error), key []byte) hash.Hash {
	h, err := f(key)
	if err != nil {
		perror("%v", err)
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

func equalDigests(h int) bool {
	if macKey != nil {
		return subtle.ConstantTimeCompare(hashes[h].digest, hashes[h].cDigest) == 1
	} else {
		return bytes.Equal(hashes[h].digest, hashes[h].cDigest)
	}
}

func display(file string) (errs int) {
	var prefix string
	if !opts.cFile.isSet() {
		if opts.gnu {
			prefix, file = escapeFilename(file)
		}
		for _, h := range chosen {
			digest := hex.EncodeToString(hashes[h].digest)
			if opts.bsd {
				fmt.Printf("%s (%s) = %s\n", hashes[h].name, file, digest)
			} else if opts.gnu {
				fmt.Printf("%s%s  %s\n", prefix, digest, file)
			} else {
				fmt.Printf("%s(%s)= %s\n", hashes[h].name, file, digest)
			}
		}
	} else if file != "" {
		prefix, file := escapeFilename(file)
		for _, h := range chosen {
			status := ""
			if checkHashes.Test(h) || checkHashes.GetCount() == 0 {
				if equalDigests(h) {
					if !opts.quiet {
						status = "OK"
					}
				} else {
					status = "FAILED"
					if opts.verbose {
						status += " with " + hex.EncodeToString(hashes[h].digest)
					}
					errs++
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
			hashes[h].digest = hashes[h].Sum(nil)
			hashes[h].Reset()
		}(h)
	}
	wg.Wait()
	display(`"` + str + `"`)
}

func hashSmallF(f *os.File) (errs bool) {
	var wg sync.WaitGroup

	data, err := ioutil.ReadAll(f)
	if err != nil {
		perror("%v", err)
		return true
	}

	for _, h := range chosen {
		if opts.cFile.isSet() && !checkHashes.Test(h) {
			continue
		}
		wg.Add(1)
		go func(h int) {
			defer wg.Done()
			if debug {
				defer timeTrack(time.Now(), hashes[h].name)
			}
			hashes[h].Write(data)
			hashes[h].digest = hashes[h].Sum(nil)
			hashes[h].Reset()
		}(h)
	}

	wg.Wait()
	return
}

func hashF(f *os.File) bool {
	var wg sync.WaitGroup
	var writers []io.Writer
	var pipeWriters []*io.PipeWriter

	for _, h := range chosen {
		if opts.cFile.isSet() && !checkHashes.Test(h) {
			continue
		}
		pr, pw := io.Pipe()
		writers = append(writers, pw)
		pipeWriters = append(pipeWriters, pw)
		wg.Add(1)
		go func(h int) {
			defer wg.Done()
			if debug {
				defer timeTrack(time.Now(), hashes[h].name)
			}
			if _, err := io.Copy(hashes[h], pr); err != nil {
				panic(err)
			}
			hashes[h].digest = hashes[h].Sum(nil)
			hashes[h].Reset()
		}(h)
	}

	wg.Add(1)
	go func() {
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
			panic(err)
		}
	}()

	wg.Wait()
	return false
}

func hashPathname(pathname string) (errs int) {
	f, err := os.Open(pathname)
	if err != nil {
		perror("%v", err)
		return -1
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		perror("%v", err)
		return -1
	}

	if fi.IsDir() {
		if opts.recurse {
			pathSeparator := string(os.PathSeparator)
			if !strings.HasSuffix(pathname, pathSeparator) {
				pathname += pathSeparator
			}
			return hashDir(pathname)
		}
		perror("%s is a directory and the -r option was not specified", pathname)
		return -1
	}

	if fi.Size() < 1e6 {
		if hashSmallF(f) {
			errs++
		}
	} else {
		if hashF(f) {
			errs++
		}
	}
	if errs == 0 {
		return display(pathname)
	} else {
		return -1
	}
}

func hashStdin() (errs bool) {
	if errs = hashF(os.Stdin); !errs {
		display("")
	}
	return
}

func hashDir(dir string) int {
	err := filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			perror("%v", err)
			if !os.IsPermission(err) {
				return err
			}
		} else {
			if fi.Mode().IsRegular() {
				hashPathname(path)
			}
		}
		return nil
	})
	if err != nil {
		perror("%v", err)
		return -1
	}
	return 0
}

func hashFromFile(filename string) (errs int) {
	terminator := "\n"
	if opts.zero {
		terminator = "\x00"
	}

	f := os.Stdin
	var err error
	if filename != "" {
		if f, err = os.Open(filename); err != nil {
			perror("%v", err)
			os.Exit(1)
		}
		defer f.Close()
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
		if hashPathname(pathname) != 0 {
			errs++
		}
	}
}

func checkFromFile(filename string) int {
	var hash, current, file, digest string
	var lineno uint64

	var stats struct {
		unmatched  uint64
		unreadable uint64
	}

	bsdFormat, gnuFormat := opts.bsd, opts.gnu

	defaultHashes := map[int]string{
		64: "SHA512", 48: "SHA384", 32: "SHA256", 28: "SHA224", 20: "SHA1", 16: "MD5",
	}

	// Format used by OpenSSL dgst and *BSD md5, et al
	bsd_begin := regexp.MustCompile(`^[A-Z]+[a-z0-9-]* ?\(`)
	bsd := regexp.MustCompile(`(?ms:^([A-Z]+[a-z0-9-]*) ?\((.*?)\) ?= ([0-9a-f]{16,})$)`)
	// Format used by md5sum, et al
	gnu := regexp.MustCompile(`^[\\]?([0-9a-f]{16,}) [ \*](.*)$`)
	// Get hint from filename for the algorithm to use
	re := regexp.MustCompile(`(?i:(md5|sha1|sha224|sha256|sha384|sha512))`)
	hint := strings.ToUpper(re.FindString(filepath.Base(filename)))

	f := os.Stdin
	var err error
	if filename != "" {
		if f, err = os.Open(filename); err != nil {
			perror("%v", err)
			os.Exit(1)
		}
		defer f.Close()
	}

	inputReader := bufio.NewReader(f)
	for {
		var xline string
		lineno++
		line := ""

		for {
			xline, err = inputReader.ReadString('\n')
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

		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")

		if bsdFormat && err == nil {
			res := bsd.FindStringSubmatch(line)
			if res == nil {
				badFormat(lineno)
			}
			hash, file, digest = res[1], res[2], strings.ToLower(res[3])
			hash = strings.Replace(hash, "BLAKE2b-", "BLAKE2b", 1)
			if hash == "BLAKE2b" {
				hash = "BLAKE2b512"
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
			} else if hint != "" {
				hash = hint
			} else {
				hash = defaultHashes[len(digest)/2]
			}
		} else if err == nil {
			badFormat(lineno)
		}

		if current == "" {
			current = file
		}

		h := getHashIndex(hash, len(digest)/2)
		if h == -1 && err == nil {
			if opts.verbose {
				perror("Skipping unsupported algorithm %s for file %s (line %d)", hash, file, lineno)
			}
			continue
		}

		if current != file || err == io.EOF {
			for _, k := range checkHashes.GetAll() {
				if algorithms.Test(k) {
					n := hashPathname(current)
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

		if hashes[h].cDigest, err = hex.DecodeString(digest); err != nil {
			badFormat(lineno)
		}

		initHash(h)
		checkHashes.Add(h)
	}

	plural := ""
	if !opts.status && stats.unreadable > 0 {
		if stats.unreadable > 1 {
			plural = "s"
		}
		perror("WARNING: %d listed file%s could not be read", stats.unreadable, plural)
	}
	if !opts.status && stats.unmatched > 0 {
		if stats.unmatched > 1 {
			plural = "s"
		}
		perror("WARNING: %d computed checksum%s did NOT match", stats.unmatched, plural)
	}
	if stats.unreadable > 0 || stats.unmatched > 0 {
		return -1
	}
	return 0
}

var hashIndex = make(map[string]int)

func getHashIndex(name string, size int) int {
	if h, ok := hashIndex[name]; !ok {
		for i := range hashes {
			if hashes[i].size == size && hashes[i].name == name {
				hashIndex[name] = i
				return hashIndex[name]
			}
		}
	} else {
		return h
	}
	return -1
}

func badFormat(lineno uint64) {
	perror("Unrecognized format at line %d", lineno)
	os.Exit(1)
}

func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("%s took %s", name, elapsed)
}
