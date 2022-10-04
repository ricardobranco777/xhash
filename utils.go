package main

import (
	"bufio"
	"crypto"
	"crypto/hmac"
	"golang.org/x/crypto/blake2b"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

import flag "github.com/spf13/pflag"

// Wrapper for the Blake2 New() methods that need an optional key for MAC
func blake2_(f func([]byte) (hash.Hash, error), key []byte) hash.Hash {
	h, err := f(key)
	if err != nil {
		logger.Fatal(err)
	}
	return h
}

func initHash(h *Checksum) {
	switch h.hash {
	case crypto.BLAKE2b_256:
		h.Hash = blake2_(blake2b.New256, macKey)
	case crypto.BLAKE2b_384:
		h.Hash = blake2_(blake2b.New384, macKey)
	case crypto.BLAKE2b_512:
		h.Hash = blake2_(blake2b.New512, macKey)
	default:
		if macKey != nil {
			h.Hash = hmac.New(h.hash.New, macKey)
		} else {
			h.Hash = h.hash.New()
		}
	}
}

func getChosen() []*Checksum {
	checksums := make([]*Checksum, len(chosen))
	for i := range chosen {
		checksums[i] = &Checksum{hash: chosen[i].hash}
		initHash(checksums[i])
	}
	return checksums
}

func hashF(f *os.File) (checksums []*Checksum) {
	var wg sync.WaitGroup
	var writers []io.Writer
	var pipeWriters []*io.PipeWriter

	checksums = getChosen()

	wg.Add(len(checksums))
	for _, h := range checksums {
		pr, pw := io.Pipe()
		writers = append(writers, pw)
		pipeWriters = append(pipeWriters, pw)
		go func(h *Checksum) {
			defer wg.Done()
			if _, err := io.Copy(h, pr); err != nil {
				logger.Print(err)
			}
			h.sum = h.Sum(nil)
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
			logger.Print(err)
		}
	}()
	wg.Wait()

	return
}

func hashFile(input *Input) *Results {
	file := input.file
	f, err := os.Open(file)
	if err != nil {
		stats.unreadable++
		if !opts.ignore {
			logger.Print(err)
		}
		return nil
	}
	defer f.Close()
	if !opts.recursive {
		info, err := f.Stat()
		if err != nil {
			logger.Print(err)
			return nil
		}
		if info.IsDir() {
			logger.Printf("%s is a directory and the -r option was not specified", file)
			return nil
		}
	}
	if opts.check != "\x00" {
		checksum := &Checksum{hash: input.hash}
		initHash(checksum)
		if _, err := io.Copy(checksum, f); err != nil {
			logger.Print(err)
			return nil
		}
		checksum.sum = checksum.Sum(nil)
		return &Results{
			file:      file,
			checksums: []*Checksum{checksum},
			check:     input.sum,
		}
	}
	return &Results{
		file:      file,
		checksums: hashF(f),
	}
}

func hashStdin() *Results {
	return &Results{
		file:      "",
		checksums: hashF(os.Stdin),
	}
}

func hashString(str string) *Results {
	checksums := getChosen()
	for _, h := range checksums {
		h.Write([]byte(str))
		h.sum = h.Sum(nil)
	}
	return &Results{
		file:      `"` + str + `"`,
		checksums: checksums,
	}
}

// *sum escapes filenames with backslash & newline
func escapeFilename(filename string) (prefix string, result string) {
	if strings.ContainsAny(filename, "\n\\") {
		return "\\", strings.Replace(strings.Replace(filename, "\\", "\\\\", -1), "\n", "\\n", -1)
	} else {
		return "", filename
	}
}

// *sum escapes filenames with backslash & newline
func unescapeFilename(filename string) string {
	return strings.Replace(strings.Replace(filename, "\\\\", "\\", -1), "\\n", "\n", -1)
}

func inputFromArgs() <-chan *Input {
	files := make(chan *Input)
	go func() {
		for _, arg := range flag.Args() {
			files <- &Input{file: arg}
		}
		close(files)
	}()
	return files
}

// Used by the -r option
func inputFromDir() <-chan *Input {
	files := make(chan *Input)
	go func() {
		for _, arg := range flag.Args() {
			filepath.WalkDir(arg, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					logger.Print(err)
					if !os.IsPermission(err) {
						return err
					}
				} else if d.Type().IsRegular() {
					files <- &Input{file: path}
				}
				return nil
			})
		}
		close(files)
	}()
	return files
}

// Used by the -i option
func inputFromFile() <-chan *Input {
	var err error

	f := os.Stdin
	if opts.input != "" {
		if f, err = os.Open(opts.input); err != nil {
			logger.Fatal(err)
		}
	}

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	files := make(chan *Input)
	go func() {
		for scanner.Scan() {
			if err := scanner.Err(); err != nil {
				logger.Fatal(err)
			}
			files <- &Input{file: scanner.Text()}
		}
		close(files)
		f.Close()
	}()
	return files
}
