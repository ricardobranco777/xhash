package main

import (
	"fmt"
	"golang.org/x/sync/errgroup"
	"io"
	"log"
	"os"
)

func hashF(f io.ReadCloser, checksums []*Checksum) []*Checksum {
	if checksums == nil {
		checksums = make([]*Checksum, len(chosen))
		for i := range chosen {
			checksums[i] = &Checksum{hash: chosen[i].hash}
		}
	}

	if len(checksums) == 1 {
		h := checksums[0]
		initHash(h)
		n, err := io.Copy(h, f)
		if err != nil {
			log.Print(err)
			return nil
		}
		h.written = n
		h.sum = h.Sum(nil)
		return checksums
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
			n, err := io.Copy(h, pr)
			if err != nil {
				return err
			}
			h.written = n
			h.sum = h.Sum(nil)
			return nil
		})
	}

	g.Go(func() error {
		defer func() {
			for _, pw := range pipeWriters {
				pw.Close()
			}
		}()
		// build the multiwriter for all the pipes
		mw := io.MultiWriter(writers...)
		// copy the data into the multiwriter
		_, err := io.Copy(mw, f)
		return err
	})
	if err := g.Wait(); err != nil {
		log.Print(err)
		return nil
	}

	return checksums
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

	return &Checksums{
		file:      file,
		checksums: hashF(f, checksums),
	}, nil
}

func hashStdin() *Checksums {
	return &Checksums{
		file:      "",
		checksums: hashF(os.Stdin, nil),
	}
}

func hashString(str string) *Checksums {
	checksums := make([]*Checksum, len(chosen))
	for i, h := range chosen {
		checksums[i] = &Checksum{hash: h.hash}
		initHash(checksums[i])
		checksums[i].Write([]byte(str))
		checksums[i].sum = checksums[i].Sum(nil)
	}
	return &Checksums{
		file:      `"` + str + `"`,
		checksums: checksums,
	}
}
