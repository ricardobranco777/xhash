package main

import (
	"io"
	"log"
	"os"
	"sync"
)

func hashF(f io.ReadCloser, checksums []*Checksum) []*Checksum {
	if checksums == nil {
		checksums = getChosen()
	}
	initHashes(checksums)
	if len(checksums) == 1 {
		n, err := io.Copy(checksums[0], f)
		if err != nil {
			log.Print(err)
			return nil
		}
		checksums[0].written = n
		checksums[0].sum = checksums[0].Sum(nil)
		return checksums
	}

	// Use goroutines if more than one algorithm

	var wg sync.WaitGroup
	wg.Add(len(checksums))
	channels := make([]chan []byte, len(checksums))

	for i, h := range checksums {
		channels[i] = make(chan []byte)
		go func(h *Checksum, channel <-chan []byte) {
			defer wg.Done()
			for data := range channel {
				n, err := h.Write(data)
				if err != nil {
					log.Print(err)
					return
				}
				h.written += int64(n)
			}
			h.sum = h.Sum(nil)
		}(h, channels[i])
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		b := make([]byte, 64*KB) // TODO: Check best buffer size
		for {
			n, err := f.Read(b)
			if err != nil {
				if err != io.EOF {
					log.Print(err)
				}
				break
			}
			bCopy := make([]byte, n)
			copy(bCopy, b[:n])
			for i := range channels {
				channels[i] <- bCopy
			}
		}
		for i := range channels {
			close(channels[i])
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

	checksums := hashF(f, input.checksums)

	return &Checksums{
		file:      file,
		checksums: checksums,
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
