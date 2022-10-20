package main

import (
	"io"
	"os"
	"sync"
)

// Hash bytes
func hashBytes(data []byte, checksums []*Checksum) []*Checksum {
	if checksums == nil {
		checksums = getChosen()
	}
	initHashes(checksums)
	// Do not use goroutines if only one algorith or no data
	if len(checksums) == 1 || len(data) == 0 {
		for i := range checksums {
			if n, err := checksums[i].Write(data); err != nil {
				logger.Print(err)
				return nil
			} else {
				checksums[i].written = int64(n)
				checksums[i].sum = checksums[i].Sum(nil)
			}
		}
		return checksums
	}

	// Use goroutines if more than one algorithm
	var wg sync.WaitGroup

	wg.Add(len(checksums))
	for _, h := range checksums {
		go func(h *Checksum) {
			defer wg.Done()
			if n, err := h.Write(data); err != nil {
				logger.Print(err)
			} else {
				h.written = int64(n)
				h.sum = h.Sum(nil)
			}
		}(h)
	}
	wg.Wait()
	return checksums
}

// Hash file
func hashF(f io.ReadCloser, checksums []*Checksum) []*Checksum {
	if checksums == nil {
		checksums = getChosen()
	}
	initHashes(checksums)
	if len(checksums) == 1 {
		if n, err := io.Copy(checksums[0], f); err != nil {
			logger.Print(err)
			return nil
		} else {
			checksums[0].written = n
			checksums[0].sum = checksums[0].Sum(nil)
		}
		return checksums
	}

	// Use goroutines if more than one algorithm

	var wg sync.WaitGroup
	var writers []io.Writer
	var pipeWriters []*io.PipeWriter

	wg.Add(len(checksums))
	for _, h := range checksums {
		pr, pw := io.Pipe()
		writers = append(writers, pw)
		pipeWriters = append(pipeWriters, pw)
		go func(h *Checksum) {
			defer wg.Done()
			if n, err := io.Copy(h, pr); err != nil {
				logger.Print(err)
			} else {
				h.written = n
				h.sum = h.Sum(nil)
			}
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
	return checksums
}

func hashFile(input *Checksums) *Checksums {
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

	info, err := f.Stat()
	if err != nil {
		logger.Print(err)
		return nil
	}
	if info.IsDir() {
		logger.Printf("%s is a directory", file)
		return nil
	}

	var checksums []*Checksum

	if info.Size() < 1<<28 {
		data, err := io.ReadAll(f)
		if err != nil {
			logger.Print(err)
		} else {
			checksums = hashBytes(data, input.checksums)
		}
	}
	if checksums == nil { // io.ReadAll() failed or file is bigger
		checksums = hashF(f, input.checksums)
	}

	if info.Size() > 0 && checksums[0].written != info.Size() {
		logger.Printf("%s: written %d, expected: %d", file, checksums[0].written, info.Size())
		return nil
	} else {
		return &Checksums{
			file:      file,
			checksums: checksums,
		}
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
