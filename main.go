package main

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	_ "golang.org/x/crypto/sha3"
	"golang.org/x/sync/errgroup"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
)

import flag "github.com/spf13/pflag"

const version string = "3.5.2"

func getOutput(results *Checksums, noEscape bool, opts Options) []*Output {
	var backslash string
	outputs := make([]*Output, 0, len(results.checksums)+1)
	file := results.file
	if !noEscape {
		if !opts.zero {
			file = escapeFilename(file)
		}
		if opts.gnu && len(file) != len(results.file) {
			backslash = "\\"
		}
	}
	if opts.size {
		outputs = append(outputs, &Output{
			File: file,
			Name: "SIZE",
			Sum:  strconv.FormatInt(results.size, 10),
		})
	}
	for i := range results.checksums {
		var sum string
		if opts.base64 {
			sum = base64.StdEncoding.EncodeToString(results.checksums[i].sum)
		} else {
			sum = hex.EncodeToString(results.checksums[i].sum)
		}
		outputs = append(outputs, &Output{
			File: file,
			Name: algorithms[results.checksums[i].hash].name,
			Sum:  backslash + sum,
		})
	}
	return outputs
}

func printChecksums(results *Checksums, noEscape bool, opts Options) {
	if err := format.Execute(os.Stdout, getOutput(results, noEscape, opts)); err != nil {
		panic(err)
	}
}

func printCheckResults(results *Checksums) (unmatched int) {
	file := escapeFilename(results.file)
	for i := range results.checksums {
		var ok bool
		if macKey != nil {
			ok = hmac.Equal(results.checksums[i].sum, results.checksums[i].csum)
		} else {
			ok = bytes.Equal(results.checksums[i].sum, results.checksums[i].csum)
		}
		if ok {
			if !opts.quiet && !opts.status {
				if opts.verbose {
					fmt.Printf("%s: %s OK\n", file, algorithms[results.checksums[i].hash].name)
				} else {
					fmt.Printf("%s: OK\n", file)
				}
			}
		} else {
			unmatched++
			if !opts.status {
				if opts.verbose {
					fmt.Printf("%s: %s FAILED with %s\n", file, algorithms[results.checksums[i].hash].name, hex.EncodeToString(results.checksums[i].sum))
				} else {
					fmt.Printf("%s: FAILED\n", file)
				}
			}
		}
	}
	return unmatched
}

func init() {
	log.SetPrefix("ERROR: ")
	log.SetFlags(0)

	progname := filepath.Base(os.Args[0])

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] [-s STRING...]|[-c FILE]|[-i FILE]|[FILE...]|[-r FILE... DIRECTORY...]\n", progname)
		flag.PrintDefaults()
	}

	if strings.HasPrefix(progname, "xhash") {
		flag.BoolVarP(&opts.all, "all", "a", false, "all algorithms (except others specified, if any)")
	}
	if strings.Contains(progname, "sum") {
		flag.BoolVarP(&opts.base64, "base64", "", false, "output hash in Base64 encoding format")
		flag.BoolVarP(&opts.dummy, "binary", "b", false, "read in binary mode")
		flag.BoolVarP(&opts.dummy, "text", "t", false, "read in text mode (default)")
		flag.BoolVarP(&opts.tag, "tag", "", false, "create a BSD-style checksum")
	} else {
		flag.BoolVarP(&opts.base64, "base64", "b", false, "output hash in Base64 encoding format")
		flag.BoolVarP(&opts.gnu, "gnu", "", false, "output hashes in the format used by md5sum")
	}
	flag.BoolVarP(&opts.ignore, "ignore-missing", "", false, "don't fail or report status for missing files")
	flag.BoolVarP(&opts.quiet, "quiet", "q", false, "don't print OK for each successfully verified file")
	flag.BoolVarP(&opts.recursive, "recursive", "r", false, "recurse into directories")
	flag.BoolVarP(&opts.size, "size", "", false, "output size")
	flag.BoolVarP(&opts.status, "status", "S", false, "don't output anything, status code shows success")
	flag.BoolVarP(&opts.strict, "strict", "", false, "exit non-zero for improperly formatted checksum lines")
	flag.BoolVarP(&opts.str, "string", "s", false, "treat arguments as strings")
	flag.BoolVarP(&opts.followSymlinks, "symlinks", "L", false, "follow symbolic links while recursing directories")
	flag.BoolVarP(&opts.verbose, "verbose", "v", false, "verbose operation")
	flag.BoolVarP(&opts.version, "version", "", false, "show version and exit")
	flag.BoolVarP(&opts.warn, "warn", "w", false, "warn about improperly formatted checksum lines")
	flag.BoolVarP(&opts.zero, "zero", "z", false, "end each output line with NUL, not newline, and disable file name escaping")
	flag.StringVarP(&opts.check, "check", "c", "\x00", "read checksums from file (use \"\" for stdin)")
	flag.StringVarP(&opts.input, "input", "i", "\x00", "read pathnames from file (use \"\" for stdin)")
	flag.StringVarP(&opts.key, "hmac", "H", "\x00", "key for HMAC (in hexadecimal) or read from specified pathname")
	if strings.Contains(progname, "sum") {
		flag.StringVarP(&opts.format, "format", "f", gnuFormat, "output format")
	} else {
		flag.StringVarP(&opts.format, "format", "f", bsdFormat, "output format")
	}

	// Allow xhash to be hard-linked to "md5sum" or "md5", etc and only use that algorithm
	if !strings.HasPrefix(progname, "xhash") {
		cmd := strings.TrimSuffix(strings.TrimSuffix(progname, ".exe"), "sum")
		var defaults = map[string]crypto.Hash{
			"b2":     crypto.BLAKE2b_512,
			"b3":     BLAKE3,
			"md5":    crypto.MD5,
			"sha1":   crypto.SHA1,
			"sha256": crypto.SHA256,
			"sha512": crypto.SHA512,
		}
		if h, ok := defaults[cmd]; ok {
			hashes = []crypto.Hash{h}
		}
	}

	algorithms = make(map[crypto.Hash]*Algorithm)
	for _, h := range hashes {
		if h == BLAKE3 {
			algorithms[h] = &Algorithm{name: "BLAKE3"}
		} else if h.Available() {
			algorithms[h] = &Algorithm{
				name: strings.ReplaceAll(strings.ReplaceAll(h.String(), "SHA-", "SHA"), "/", "-"),
			}
		}
		if _, ok := algorithms[h]; ok {
			if strings.HasPrefix(progname, "xhash") {
				flag.BoolVar(
					&algorithms[h].check,
					strings.ToLower(algorithms[h].name),
					false,
					algorithms[h].name+" algorithm")
			}
		}
	}
	flag.Parse()

	if opts.input != "\x00" && opts.check != "\x00" {
		log.Fatal("The --input & --check options are mutually exclusive")
	}

	if opts.version {
		fmt.Printf("v%s %v %s/%s\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		fmt.Printf("Supported hashes:")
		for _, h := range hashes {
			fmt.Printf(" %s", algorithms[h].name)
		}
		fmt.Println()
		os.Exit(0)
	}

	if strings.HasPrefix(progname, "xhash") {
		if opts.all {
			// Ignore algorithm if --all was specified
			for h := range algorithms {
				algorithms[h].check = !algorithms[h].check
			}
		}

		// Initialize chosen and populate name2Hash
		for _, h := range hashes {
			available := h == BLAKE3 || h.Available()
			if available && algorithms[h].check {
				chosen = append(chosen, h)
			}
			name2Hash[algorithms[h].name] = h
		}

		if opts.check == "\x00" && len(chosen) == 0 {
			// SHA-256 is default
			chosen = append(chosen, crypto.SHA256)
		}
	} else {
		chosen = []crypto.Hash{hashes[0]}
		name2Hash[algorithms[hashes[0]].name] = hashes[0]
	}

	if opts.key != "\x00" {
		var err error
		if opts.key == "" {
			if macKey, err = io.ReadAll(os.Stdin); err != nil {
				log.Fatal(err)
			}
		} else if macKey, err = hex.DecodeString(opts.key); err != nil {
			if macKey, err = os.ReadFile(opts.key); err != nil {
				log.Fatal(err)
			}
		}
	}

	if opts.gnu {
		opts.format = gnuFormat
	} else if opts.tag {
		opts.format = bsdFormat
	}
	opts.format = unescape(opts.format)
	if opts.zero && !strings.Contains(opts.format, "\x00") {
		opts.format = strings.ReplaceAll(opts.format, "\n", "\x00")
	}
	var err error
	format, err = format.Parse(opts.format)
	if err != nil {
		log.Fatal(err)
	}

	if strings.Contains(progname, "sum") {
		opts.gnu = true
	}
}

func openFileOrStdin(filename string) io.ReadCloser {
	var err error
	f := os.Stdin
	if filename != "" {
		if f, err = os.Open(filename); err != nil {
			log.Fatal(err)
		}
	}
	return f
}

func main() {
	var lines <-chan *Checksums
	if opts.check != "\x00" {
		onError := ErrorIgnore
		if opts.warn {
			onError = ErrorWarn
		} else if opts.strict {
			onError = ErrorExit
		}
		f := openFileOrStdin(opts.check)
		defer f.Close()
		lines = inputFromCheck(f, opts.zero, onError)
	} else if opts.input != "\x00" {
		f := openFileOrStdin(opts.input)
		defer f.Close()
		lines = inputFromFile(f, opts.zero)
	} else if flag.NArg() == 0 {
		printChecksums(hashStdin(), true, opts)
		os.Exit(0)
	} else if opts.recursive {
		lines = inputFromDir(flag.Args(), opts.followSymlinks)
	} else if opts.str {
		for _, s := range flag.Args() {
			printChecksums(hashString(s), true, opts)
		}
		os.Exit(0)
	} else {
		lines = inputFromArgs(flag.Args())
	}

	var unreadable atomic.Uint64
	g := new(errgroup.Group)
	g.SetLimit(runtime.NumCPU())

	checksums := make(chan *Checksums)
	go func() {
		defer close(checksums)
		for line := range lines {
			g.Go(func() error {
				if checksum, err := hashFile(line.file, line.checksums); err != nil {
					unreadable.Add(1)
					if !opts.ignore {
						log.Print(err)
					}
				} else {
					checksums <- checksum
				}
				return nil
			})
		}
		if err := g.Wait(); err != nil {
			log.Fatal(err)
		}
	}()

	if opts.check == "\x00" {
		for checksum := range checksums {
			printChecksums(checksum, false, opts)
		}
		os.Exit(0)
	}

	// Handle -c option

	unmatched := 0
	for checksum := range checksums {
		unmatched += printCheckResults(checksum)
	}

	unreadableFiles := unreadable.Load()
	if opts.check != "\x00" || opts.input != "\x00" {
		plural := ""
		if !opts.status && unreadableFiles > 0 {
			if unreadableFiles > 1 {
				plural = "s"
			}
			fmt.Fprintf(os.Stderr, "WARNING: %d listed file%s could not be read\n", unreadableFiles, plural)
		}
		if !opts.status && unmatched > 0 {
			if unmatched > 1 {
				plural = "s"
			}
			fmt.Fprintf(os.Stderr, "WARNING: %d computed checksum%s did NOT match\n", unmatched, plural)
		}
	}
	if unreadableFiles > 0 || unmatched > 0 {
		os.Exit(1)
	}
}
