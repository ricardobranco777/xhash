package main

import (
	"context"
	"golang.org/x/sync/errgroup"
	"io"
	"log"
	"os"
	"sync"
)

// Hash file with just one algorithm
func hashSmallF1(f io.ReadCloser, checksums []*Checksum) []*Checksum {
	if checksums == nil {
		checksums = getChosen()
	}
	initHashes(checksums)

	data, err := io.ReadAll(f)
	if err != nil {
		log.Print(err)
		return nil
	}
	h := checksums[0]
	if n, err := h.Write(data); err != nil {
		log.Print(err)
		return nil
	} else {
		h.written = int64(n)
		h.sum = h.Sum(nil)
	}

	return checksums
}

// Hash small file with goroutines
func hashSmallF(g *errgroup.Group, ctx context.Context, f io.ReadCloser, checksums []*Checksum) []*Checksum {
	if checksums == nil {
		checksums = getChosen()
	}
	if len(checksums) == 1 {
		return hashSmallF1(f, checksums)
	}
	initHashes(checksums)

	data, err := io.ReadAll(f)
	if err != nil {
		log.Print(err)
		return nil
	}

	var wg sync.WaitGroup
	for _, h := range checksums {
		wg.Add(1)
		g.Go(func() error {
			defer wg.Done()
			if n, err := h.Write(data); err != nil {
				log.Print(err)
				return err
			} else {
				h.written = int64(n)
				h.sum = h.Sum(nil)
			}
			return nil
		})
	}
	wg.Wait()

	return checksums
}

// Hash file with just one algorithm
func hashF1(f io.ReadCloser, checksums []*Checksum) []*Checksum {
	if checksums == nil {
		checksums = getChosen()
	}
	initHashes(checksums)

	if n, err := io.Copy(checksums[0], f); err != nil {
		log.Print(err)
		return nil
	} else {
		checksums[0].written = n
		checksums[0].sum = checksums[0].Sum(nil)
	}

	return checksums
}

// Hash file with goroutines
func hashF(g *errgroup.Group, ctx context.Context, f io.ReadCloser, checksums []*Checksum) []*Checksum {
	if checksums == nil {
		checksums = getChosen()
	}
	if len(checksums) == 1 {
		return hashF1(f, checksums)
	}
	initHashes(checksums)

	var wg sync.WaitGroup
	var writers []io.Writer
	var pipeWriters []*io.PipeWriter

	for _, h := range checksums {
		pr, pw := io.Pipe()
		writers = append(writers, pw)
		pipeWriters = append(pipeWriters, pw)
		wg.Add(1)
		g.Go(func() error {
			defer wg.Done()
			if n, err := io.Copy(h, pr); err != nil {
				log.Print(err)
				return err
			} else {
				h.written = n
				h.sum = h.Sum(nil)
			}
			return nil
		})
	}

	wg.Add(1)
	g.Go(func() error {
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
			log.Print(err)
			return err
		}
		return nil
	})
	wg.Wait()

	return checksums
}

func hashFile(g *errgroup.Group, ctx context.Context, input *Checksums) *Checksums {
	file := input.file
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

	var checksums []*Checksum
	if info.Size() < 1e6 {
		checksums = hashSmallF(g, ctx, f, input.checksums)
	} else {
		checksums = hashF(g, ctx, f, input.checksums)
	}

	return &Checksums{
		file:      file,
		checksums: checksums,
	}
}

func hashStdin(g *errgroup.Group, ctx context.Context, f io.ReadCloser) *Checksums {
	if f == nil {
		f = os.Stdin
	}
	return &Checksums{
		file:      "",
		checksums: hashF(g, ctx, f, nil),
	}
}

func hashString(str string) *Checksums {
	checksums := getChosen()
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
