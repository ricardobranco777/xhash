package main

import (
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

	var writers []io.Writer
	var pipeWriters []*io.PipeWriter

	g := new(errgroup.Group)
	for _, h := range checksums {
		initHash(h)
		pr, pw := io.Pipe()
		writers = append(writers, pw)
		pipeWriters = append(pipeWriters, pw)
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
		if _, err := io.Copy(mw, f); err != nil {
			return err
		}
		return nil
	})
	if err := g.Wait(); err != nil {
		log.Print(err)
		return nil
	}

	return checksums
}

func hashFile(file string, checksums []*Checksum) *Checksums {
	f, err := os.Open(file)
	if err != nil {
		stats.unreadable++
		if !opts.ignore {
			log.Print(err)
		}
		return nil
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		log.Print(err)
		return nil
	}
	if info.IsDir() {
		log.Printf("%s is a directory", file)
		return nil
	}

	return &Checksums{
		file:      file,
		checksums: hashF(f, checksums),
	}
}

func hashStdin(f io.ReadCloser) *Checksums {
	if f == nil {
		f = os.Stdin
	}
	return &Checksums{
		file:      "",
		checksums: hashF(f, nil),
	}
}

func hashString(str string) *Checksums {
	checksums := make([]*Checksum, len(chosen))
	for i := range chosen {
		checksums[i] = &Checksum{hash: chosen[i].hash}
	}
	for _, h := range checksums {
		initHash(h)
		h.Write([]byte(str))
		h.sum = h.Sum(nil)
	}
	return &Checksums{
		file:      `"` + str + `"`,
		checksums: checksums,
	}
}
