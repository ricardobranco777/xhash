package main

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log"
	"os"
	"slices"
	"strings"
)

// Choose the algorithm with the longest digest size
func bestHash(checksums []*Checksum, ignore crypto.Hash) *Checksum {
	minIndex := 777

	var best *Checksum
	for _, checksum := range checksums {
		index := slices.Index(better, checksum.hash)
		if ignore != checksum.hash && index < minIndex {
			minIndex = index
			best = checksum
		}
	}
	return best
}

// Choose the best algorithm, or 2 if one of them is insecure
func bestHashes(checksums []*Checksum) (best []*Checksum) {
	best1 := bestHash(checksums, 0)
	if best1 == nil {
		return nil
	}
	best = append(best, best1)
	// Return 2 algorithms if the "best" of them is insecure
	if slices.Contains(insecure, best1.hash) {
		best2 := bestHash(checksums, best1.hash)
		if best2 != nil {
			best = append(best, best2)
		}
	}
	return best
}

func isChosen(h crypto.Hash) bool {
	for i := range chosen {
		if chosen[i].hash == h {
			return true
		}
	}
	return false
}

func parseLine(line string, lineno uint64) *Checksums {
	var algorithm, file, digest string
	var hash crypto.Hash
	var match []string
	var sum []byte
	var err error
	var ok bool

	if !opts.gnu {
		match = regex.bsd.FindStringSubmatch(line)
		if match != nil {
			algorithm, file, digest = match[1], match[2], match[3]
		}
	}
	if match == nil {
		match = regex.gnu.FindStringSubmatch(line)
		if match != nil {
			digest, file = match[1], match[2]
		}
	}
	if !opts.zero {
		file = unescapeFilename(file)
	}
	/* All hashes except 384-bits have Base64 padding */
	if opts.base64 || strings.HasSuffix(digest, "=") || regex.base64.MatchString(digest) {
		sum, err = base64.StdEncoding.DecodeString(digest)
	} else {
		sum, err = hex.DecodeString(digest)
	}
	/* Guess algorithm if not specified */
	if algorithm == "" {
		if len(chosen) == 1 {
			algorithm = algorithms[chosen[0].hash].name
		} else {
			algorithm = size2hash[len(sum)]
		}
	}
	if hash, ok = name2Hash[algorithm]; !ok || err != nil || len(chosen) > 0 && !isChosen(hash) {
		stats.invalid++
		if opts.warn {
			log.Printf("Invalid digest at line %d\n", lineno)
		} else if opts.strict {
			log.Fatalf("Invalid digest at line %d\n", lineno)
		}
		return nil
	}
	return &Checksums{
		file: file,
		checksums: []*Checksum{
			{
				hash: hash,
				csum: sum,
			},
		},
	}
}

func inputFromCheck(f io.ReadCloser) <-chan *Checksums {
	var current string
	var lineno uint64
	var input *Checksums
	var err error

	if f == nil {
		f = os.Stdin
		if opts.check != "" {
			if f, err = os.Open(opts.check); err != nil {
				log.Fatal(err)
			}
		}
	}

	checksums := []*Checksum{}
	scanner := getScanner(f)

	files := make(chan *Checksums, 1024)

	go func() {
		defer close(files)
		defer f.Close()
		for {
			lineno++
			eof := !scanner.Scan()
			if !eof {
				if input = parseLine(scanner.Text(), lineno); input != nil && current == "" {
					current = input.file
				}
			}
			if input != nil && current != input.file || eof {
				if current != "" {
					if best := bestHashes(checksums); best != nil {
						files <- &Checksums{file: current, checksums: best}
					}
				}
				if eof {
					if err := scanner.Err(); err != nil {
						log.Fatal(err)
					}
					break
				}
				current = input.file
				checksums = []*Checksum{}
			}
			if input != nil {
				checksums = append(checksums, input.checksums[0])
			}
		}
	}()

	return files
}
