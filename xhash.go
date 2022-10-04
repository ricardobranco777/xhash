package main

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"fmt"
	_ "golang.org/x/crypto/sha3"
	"hash"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

import flag "github.com/spf13/pflag"

const version string = "v2.0"

type Checksum struct {
	hash crypto.Hash
	hash.Hash
	sum []byte
}

type Info struct {
	check bool
	name  string
}

type Input struct {
	file string
	// Used only by the -c option
	sum  []byte
	hash crypto.Hash
}

type Results struct {
	file      string
	checksums []*Checksum
	// Used only by the -c option
	check []byte
}

var (
	algorithms map[crypto.Hash]*Info
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
	verbose   bool // Used by the -c option
	version   bool
	warn      bool // Used by the -c option
}

var stats struct {
	unmatched  uint64
	unreadable uint64
}

func display(results *Results) {
	file := results.file
	if opts.check != "\x00" {
		var ok bool
		if macKey != nil {
			ok = hmac.Equal(results.checksums[0].sum, results.check)
		} else {
			ok = bytes.Equal(results.checksums[0].sum, results.check)
		}
		if ok {
			if !opts.quiet && !opts.status {
				if opts.verbose {
					fmt.Printf("%s: %s OK\n", file, algorithms[results.checksums[0].hash].name)
				} else {
					fmt.Printf("%s: OK\n", file)
				}
			}
		} else {
			stats.unmatched++
			if !opts.status {
				if opts.verbose {
					fmt.Printf("%s: %s FAILED with %s\n", file, algorithms[results.checksums[0].hash].name, hex.EncodeToString(results.checksums[0].sum))
				} else {
					fmt.Printf("%s: FAILED\n", file)
				}
			}
		}
	} else {
		var prefix string
		if opts.gnu {
			prefix, file = escapeFilename(results.file)
		}
		for _, h := range results.checksums {
			if opts.bsd {
				fmt.Printf("%s (%s) = %x\n", algorithms[h.hash].name, file, h.sum)
			} else if opts.gnu {
				fmt.Printf("%s%x  %s\n", prefix, h.sum, file)
			} else {
				fmt.Printf("%s(%s)= %x\n", algorithms[h.hash].name, file, h.sum)
			}
		}
	}
}

func init() {
	logger = log.New(os.Stderr, "ERROR: ", 0)

	progname := filepath.Base(os.Args[0])

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] [-s STRING...]|[-c FILE]|[-i FILE]|[FILE...]|[-r FILE... DIRECTORY...]\n\n", progname)
		flag.PrintDefaults()
	}

	flag.BoolVarP(&opts.all, "all", "a", false, "all algorithms (except others specified, if any)")
	flag.BoolVarP(&opts.bsd, "bsd", "", false, "output hashes in the format used by *BSD")
	flag.BoolVarP(&opts.gnu, "gnu", "", false, "output hashes in the format used by *sum")
	flag.BoolVarP(&opts.ignore, "ignore-missing", "", false, "don't fail or report status for missing files")
	flag.BoolVarP(&opts.quiet, "quiet", "q", false, "don't print OK for each successfully verified file")
	flag.BoolVarP(&opts.recursive, "recursive", "r", false, "recurse into directories")
	flag.BoolVarP(&opts.status, "status", "S", false, "don't output anything, status code shows success")
	flag.BoolVarP(&opts.strict, "strict", "", false, "exit non-zero for improperly formatted checksum lines")
	flag.BoolVarP(&opts.str, "string", "s", false, "treat arguments as strings")
	flag.BoolVarP(&opts.verbose, "verbose", "v", false, "verbose operation")
	flag.BoolVarP(&opts.version, "version", "V", false, "show version and exit")
	flag.BoolVarP(&opts.warn, "warn", "w", false, "warn about improperly formatted checksum lines")
	flag.StringVarP(&opts.check, "check", "c", "\x00", "read checksums from file (use \"\" for stdin)")
	flag.StringVarP(&opts.input, "input", "i", "\x00", "read pathnames from file (use \"\" for stdin)")
	flag.StringVarP(&opts.key, "hmac", "H", "\x00", "key for HMAC (in hexadecimal) or read from specified pathname")

	hashes := []crypto.Hash{
		crypto.BLAKE2b_256,
		//crypto.BLAKE2b_384,
		crypto.BLAKE2b_512,
		//crypto.MD4,
		crypto.MD5,
		crypto.SHA1,
		//crypto.SHA224,
		crypto.SHA256,
		//crypto.SHA384,
		crypto.SHA512,
		//crypto.SHA512_224,
		crypto.SHA512_256,
		//crypto.SHA3_224,
		crypto.SHA3_256,
		//crypto.SHA3_384,
		crypto.SHA3_512,
	}
	max := 0
	for _, h := range hashes {
		if int(h) > max {
			max = int(h)
		}
	}

	algorithms = make(map[crypto.Hash]*Info)
	for _, h := range hashes {
		if h.Available() {
			algorithms[h] = &Info{
				name: strings.ReplaceAll(strings.ReplaceAll(h.String(), "SHA-", "SHA"), "/", "-"),
			}
			flag.BoolVar(
				&algorithms[h].check,
				strings.ToLower(algorithms[h].name),
				false,
				h.String()+" algorithm")
		}
	}
	flag.Parse()

	if opts.bsd && opts.gnu {
		logger.Fatal("The --bsd & --gnu options are mutually exclusive")
	}
	if opts.input != "\x00" && opts.check != "\x00" {
		logger.Fatal("The --input & --check options are mutually exclusive")
	}

	if opts.version {
		fmt.Printf("%s\t%v %s/%s\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		fmt.Printf("Supported hashes:")
		for _, h := range hashes {
			fmt.Printf(" %s", algorithms[h].name)
		}
		fmt.Println()
		os.Exit(0)
	}

	if opts.all {
		// Ignore algorithm if -all was specified
		for h := range algorithms {
			algorithms[h].check = !algorithms[h].check
		}
	}

	// Initialize algorithms
	for _, h := range hashes {
		if h.Available() && algorithms[h].check {
			chosen = append(chosen, &Checksum{hash: h})
		}
	}

	if opts.check != "\x00" {
		// Populate name2Hash
		name2Hash = make(map[string]crypto.Hash)
		for _, h := range hashes {
			name2Hash[algorithms[h].name] = h
		}
	} else if len(chosen) == 0 {
		// SHA-512 is default
		chosen = append(chosen, &Checksum{hash: crypto.SHA512})
	}

	if opts.key != "\x00" {
		var err error
		if opts.key == "" {
			if macKey, err = io.ReadAll(os.Stdin); err != nil {
				logger.Fatal(err)
			}
		} else if macKey, err = hex.DecodeString(opts.key); err != nil {
			if macKey, err = os.ReadFile(opts.key); err != nil {
				logger.Fatal(err)
			}
		}
	}
}

func main() {
	inputFrom := inputFromArgs
	if opts.check != "\x00" {
		inputFrom = inputFromCheck
	} else if opts.input != "\x00" {
		inputFrom = inputFromFile
	} else if flag.NArg() == 0 {
		display(hashStdin())
		os.Exit(0)
	} else if opts.recursive {
		inputFrom = inputFromDir
	} else if opts.str {
		for _, s := range flag.Args() {
			display(hashString(s))
		}
		os.Exit(0)
	}

	var wg sync.WaitGroup
	channel := make(chan *Results)

	go func() {
		for input := range inputFrom() {
			wg.Add(1)
			go func(input *Input) {
				defer wg.Done()
				channel <- hashFile(input)
			}(input)

		}
		wg.Wait()
		close(channel)
	}()

	for checksum := range channel {
		if checksum == nil {
			continue
		}
		display(checksum)
	}

	if opts.check != "\x00" || opts.input != "\x00" {
		plural := ""
		if !opts.status && stats.unreadable > 0 {
			if stats.unreadable > 1 {
				plural = "s"
			}
			fmt.Fprintf(os.Stderr, "WARNING: %d listed file%s could not be read\n", stats.unreadable, plural)
		}
		if !opts.status && stats.unmatched > 0 {
			if stats.unmatched > 1 {
				plural = "s"
			}
			fmt.Fprintf(os.Stderr, "WARNING: %d computed checksum%s did NOT match\n", stats.unmatched, plural)
		}
	}
	if stats.unreadable > 0 || stats.unmatched > 0 {
		os.Exit(1)
	}
}
