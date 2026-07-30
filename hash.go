package main

import (
	"bytes"
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"github.com/pkg/xattr"
	"golang.org/x/sync/errgroup"
	"io"
	"log"
	"os"
	"strings"
)

// xattrName returns the extended attribute name used to cache a checksum,
// e.g. "user.checksum.sha256".
func xattrName(c *Checksum) string {
	return "user.checksum." + strings.ToLower(algorithms[c.hash].name)
}

// setCachedSum stores c's digest in file's extended attributes.
func setCachedSum(file string, c *Checksum) {
	if err := xattr.Set(file, xattrName(c), []byte(hex.EncodeToString(c.sum))); err != nil {
		log.Print(err)
	}
}

// getCachedSum returns the digest for c stored in file's extended
// attributes, or nil if there's none.
func getCachedSum(file string, c *Checksum) []byte {
	data, err := xattr.Get(file, xattrName(c))
	if err != nil {
		return nil
	}
	sum, err := hex.DecodeString(string(data))
	if err != nil {
		return nil
	}
	return sum
}

// xattrChecksums builds the expected checksums for file from its cached
// extended attributes, one per chosen algorithm. A nil csum means there's
// no cached value yet, so the caller has nothing to compare against.
func xattrChecksums(file string) []*Checksum {
	checksums := make([]*Checksum, len(chosen))
	for i, h := range chosen {
		checksums[i] = &Checksum{hash: h}
		checksums[i].csum = getCachedSum(file, checksums[i])
	}
	return checksums
}

// checksumsMatch reports whether sum matches the expected csum, using a
// constant-time comparison when an HMAC key is in use.
func checksumsMatch(sum, csum []byte) bool {
	if macKey != nil {
		return hmac.Equal(sum, csum)
	}
	return bytes.Equal(sum, csum)
}

func hashF(f io.ReadCloser, checksums []*Checksum) ([]*Checksum, Size) {
	if checksums == nil {
		checksums = make([]*Checksum, len(chosen))
		for i, h := range chosen {
			checksums[i] = &Checksum{hash: h}
		}
	}

	if len(checksums) == 1 {
		h := checksums[0]
		initHash(h)
		n, err := io.Copy(h, f)
		if err != nil {
			log.Print(err)
			return nil, 0
		}
		h.sum = h.Sum(nil)
		return checksums, Size(n)
	}

	writers := make([]io.Writer, len(checksums))
	pipeWriters := make([]*io.PipeWriter, len(checksums))

	g := new(errgroup.Group)
	for i, h := range checksums {
		initHash(h)
		pr, pw := io.Pipe()
		writers[i] = pw
		pipeWriters[i] = pw
		g.Go(func() error {
			defer pr.Close()
			if _, err := io.Copy(h, pr); err != nil {
				return err
			}
			h.sum = h.Sum(nil)
			return nil
		})
	}

	var size Size
	g.Go(func() error {
		defer func() {
			for _, pw := range pipeWriters {
				pw.Close()
			}
		}()
		// build the multiwriter for all the pipes
		mw := io.MultiWriter(writers...)
		// copy the data into the multiwriter
		n, err := io.Copy(mw, f)
		size = Size(n)
		return err
	})
	if err := g.Wait(); err != nil {
		log.Print(err)
		return nil, 0
	}

	return checksums, size
}

func hashFile(file string, checksums []*Checksum) (*Checksums, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", file)
	}

	checksums, size := hashF(f, checksums)

	switch opts.xattr {
	case xattrStore:
		// Unconditional write: always accept the freshly computed digest
		// as the baseline, regardless of whatever might already be cached.
		for _, c := range checksums {
			setCachedSum(file, c)
		}
	case xattrForce:
		// Verify, but accept a mismatch (including nothing cached) as the
		// new baseline instead of just reporting it.
		for _, c := range checksums {
			if !checksumsMatch(c.sum, c.csum) {
				setCachedSum(file, c)
			}
		}
	}

	return &Checksums{
		file:      file,
		size:      size,
		checksums: checksums,
	}, nil
}

func hashStdin() *Checksums {
	checksums, size := hashF(os.Stdin, nil)
	return &Checksums{
		file:      "",
		size:      size,
		checksums: checksums,
	}
}

func hashString(str string) *Checksums {
	checksums := make([]*Checksum, len(chosen))
	for i, h := range chosen {
		checksums[i] = &Checksum{hash: h}
		initHash(checksums[i])
		checksums[i].Write([]byte(str))
		checksums[i].sum = checksums[i].Sum(nil)
	}
	return &Checksums{
		file:      `"` + str + `"`,
		size:      Size(len(str)),
		checksums: checksums,
	}
}
