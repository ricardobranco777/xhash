package main

import (
	"io"
	"log"
	"os"
	"sync"

	"github.com/edsrzf/mmap-go"
)

// Hash bytes
func hashBytes(data []byte, checksums []*Checksum) []*Checksum {
	if checksums == nil {
		checksums = getChosen()
	}
	for h := range checksums {
		initHash(checksums[h])
	}
	if len(checksums) == 1 || len(data) == 0 { // TODO: Check best len(data)
		for i := range checksums {
			n, err := checksums[i].Write(data)
			if err != nil {
				log.Print(err)
				return nil
			}
			checksums[i].written = int64(n)
			checksums[i].sum = checksums[i].Sum(nil)
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
				log.Print(err)
			} else {
				h.written = int64(n)
				h.sum = h.Sum(nil)
			}
		}(h)
	}
	wg.Wait()
	return checksums
}

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
			for i := range channels {
				channels[i] <- b[:n]
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

	var checksums []*Checksum

	if opts.mmap && info.Size() > 0 { // TODO: Check best size
		m, err := mmap.Map(f, mmap.RDONLY, 0)
		if err != nil {
			log.Printf("%s: mmap: %v", file, err)
		} else {
			defer func() { m.Unmap() }()
			checksums = hashBytes(m, input.checksums)
		}
	}
	if checksums == nil { // !opts.map or mmap failed
		checksums = hashF(f, input.checksums)
	}

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
