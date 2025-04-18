package main

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"slices"
	"strings"
)

// Choose the algorithm with the longest digest size
func bestHash(checksums []*Checksum, ignore crypto.Hash) *Checksum {
	minIndex := int(^uint(0) >> 1) // math.MaxInt32

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

func parseLine(line string, zeroTerminated bool) (*Checksums, error) {
	var algorithm, file, digest string
	if match := regex.bsd.FindStringSubmatch(line); match != nil {
		algorithm, file, digest = match[1], match[2], match[3]
	} else if match = regex.gnu.FindStringSubmatch(line); match != nil {
		digest, file = match[1], match[2]
	}

	if !zeroTerminated {
		file = unescapeFilename(file)
	}

	var sum []byte
	var err error
	/* All hashes except those with 384-bits have Base64 padding */
	if strings.HasSuffix(digest, "=") {
		sum, err = base64.StdEncoding.DecodeString(digest)
	} else {
		sum, err = hex.DecodeString(digest)
	}

	/* Guess algorithm if not specified */
	if algorithm == "" {
		if len(chosen) == 1 {
			algorithm = algorithms[chosen[0]].name
		} else {
			algorithm = size2hash[len(sum)]
		}
	}
	if hash, ok := name2Hash[algorithm]; !ok || err != nil || len(chosen) > 0 && !slices.Contains(chosen, hash) {
		return nil, fmt.Errorf("invalid digest")
	} else {
		return &Checksums{
			file: file,
			checksums: []*Checksum{
				{
					hash: hash,
					csum: sum,
				},
			},
		}, nil
	}
}

func inputFromCheck(f io.ReadCloser, zeroTerminated bool, onError ErrorAction) <-chan *Checksums {
	files := make(chan *Checksums, 1024)

	go func() {
		defer close(files)
		defer f.Close()

		var checksums []*Checksum
		var input *Checksums
		var current string
		var lineno uint64

		scanner, err := getScanner(f, zeroTerminated)
		if err != nil {
			log.Fatal(err)
		}

		for {
			lineno++
			eof := !scanner.Scan()
			if !eof {
				input, err = parseLine(scanner.Text(), zeroTerminated)
				if err != nil {
					if onError == ErrorWarn {
						log.Printf("%v at line %d", err, lineno)
					} else if onError == ErrorExit {
						log.Fatalf("%v at line %d", err, lineno)
					}
					continue
				} else if current == "" {
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
			checksums = append(checksums, input.checksums[0])
		}
	}()

	return files
}
