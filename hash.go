package main

import (
	"io"
	"os"
	"sync"
)

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
	wg.Add(len(checksums))

	dataChans := make([]chan []byte, len(checksums))

	for i, h := range checksums {
		dataChans[i] = make(chan []byte)
		go func(h *Checksum, dataChan <-chan []byte) {
			defer wg.Done()
			for data := range dataChan {
				n, err := h.Write(data)
				if err != nil {
					logger.Print(err)
				}
				h.written += int64(n)
			}
			h.sum = h.Sum(nil)
		}(h, dataChans[i])
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		b := make([]byte, 65536) // TODO: Check best buffer size
		for {
			n, err := f.Read(b)
			if err != nil {
				if err != io.EOF {
					logger.Print(err)
				}
				break
			}
			for i := range dataChans {
				dataChans[i] <- b[:n]
			}
		}
		for i := range dataChans {
			close(dataChans[i])
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

	checksums := hashF(f, input.checksums)
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
