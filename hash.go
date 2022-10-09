package main

import (
	"io"
	"os"
	"sync"
)

// Hash small file with just one algorithm
func hashSmallF1(f io.ReadCloser, checksums []*Checksum) []*Checksum {
	if checksums == nil {
		checksums = getChosen()
	}
	initHash(checksums[0])
	data, err := io.ReadAll(f)
	if err != nil {
		logger.Print(err)
		return nil
	}
	checksums[0].Write(data)
	checksums[0].sum = checksums[0].Sum(nil)
	return checksums
}

// Hash small file with goroutines
func hashSmallF(f io.ReadCloser, checksums []*Checksum) []*Checksum {
	if checksums == nil {
		checksums = getChosen()
	} else if len(checksums) == 1 {
		return hashSmallF1(f, checksums)
	}
	for i, _ := range checksums {
		initHash(checksums[i])
	}

	data, err := io.ReadAll(f)
	if err != nil {
		logger.Print(err)
		return nil
	}

	var wg sync.WaitGroup

	wg.Add(len(checksums))
	for _, h := range checksums {
		go func(h *Checksum) {
			defer wg.Done()
			h.Write(data)
			h.sum = h.Sum(nil)
		}(h)
	}
	wg.Wait()
	return checksums
}

// Hash file with just one algorithm
func hashF1(f io.ReadCloser, checksums []*Checksum) []*Checksum {
	if checksums == nil {
		checksums = getChosen()
	}
	initHash(checksums[0])
	if _, err := io.Copy(checksums[0], f); err != nil {
		logger.Print(err)
		return nil
	}
	checksums[0].sum = checksums[0].Sum(nil)
	return checksums
}

// Hash file with goroutines
func hashF(f io.ReadCloser, checksums []*Checksum) []*Checksum {
	if checksums == nil {
		checksums = getChosen()
	} else if len(checksums) == 1 {
		return hashF1(f, checksums)
	}
	for i, _ := range checksums {
		initHash(checksums[i])
	}

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
	return checksums
}

func hashFile(input *Info) *Info {
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
	if opts.recursive && info.IsDir() {
		logger.Printf("%s is a directory and the -r option was not specified", file)
		return nil
	}

	var hashIt func(f io.ReadCloser, checksums []*Checksum) []*Checksum
	if info.Size() < 1e4 {
		hashIt = hashSmallF
	} else {
		hashIt = hashF
	}

	return &Info{
		file:      file,
		checksums: hashIt(f, input.checksums),
	}
}

func hashStdin(f io.ReadCloser) *Info {
	if f == nil {
		f = os.Stdin
	}
	return &Info{
		file:      "",
		checksums: hashF(f, nil),
	}
}

func hashString(str string) *Info {
	checksums := getChosen()
	for i, h := range checksums {
		initHash(checksums[i])
		h.Write([]byte(str))
		h.sum = h.Sum(nil)
	}
	return &Info{
		file:      `"` + str + `"`,
		checksums: checksums,
	}
}
