package main

import (
	"fmt"
	"golang.org/x/sync/errgroup"
	"io"
	"log"
	"os"
)

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
