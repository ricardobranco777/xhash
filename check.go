package main

import (
	"bufio"
	"crypto"
	"encoding/hex"
	"os"
	"regexp"
	"strings"
)

var regex = struct {
	bsd, gnu *regexp.Regexp
}{
	regexp.MustCompile(`^([A-Z]+[a-z0-9-]*) ?\((.*?)\) ?= ([0-9a-f]{16,})$`), // Format used by OpenSSL dgst and *BSD md5, et al
	regexp.MustCompile(`^[\\]?([0-9a-f]{16,}) [ \*](.*)$`),                   // Format used by md5sum, et al
}

var size2hash = map[int]string{128: "SHA512", 96: "SHA384", 64: "SHA256", 56: "SHA224", 40: "SHA1", 32: "MD5"}

func bestHash(inputs []*Info) (best *Info) {
	max := 0
	// For now, choose the algorithm with the longest digest size
	for _, input := range inputs {
		if input.checksums[0].hash.Size() > max {
			max = input.checksums[0].hash.Size()
			best = input
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

func parseLine(line string, lineno uint64) *Info {
	var algorithm, file, digest string
	var hash crypto.Hash
	var match []string
	var sum []byte
	var err error
	var ok bool

	if !opts.bsd {
		match = regex.gnu.FindStringSubmatch(line)
		if match != nil {
			digest, file = strings.ToLower(match[1]), unescapeFilename(match[2])
			if len(chosen) == 1 {
				algorithm = algorithms[chosen[0].hash].name
			} else {
				algorithm = size2hash[len(digest)]
			}
		}
	}
	if !opts.gnu {
		match = regex.bsd.FindStringSubmatch(line)
		if match != nil {
			algorithm, file, digest = match[1], match[2], strings.ToLower(match[3])
		}
	}
	sum, err = hex.DecodeString(digest)
	if hash, ok = name2Hash[algorithm]; !ok || err != nil || len(chosen) > 0 && !isChosen(hash) {
		stats.invalid++
		if opts.warn {
			logger.Printf("Invalid digest at line %d\n", lineno)
		} else if opts.strict {
			logger.Fatalf("Invalid digest at line %d\n", lineno)
		}
		return nil
	}
	return &Info{
		file: file,
		checksums: []*Checksum{
			&Checksum{
				hash: hash,
				csum: sum,
			},
		},
	}
}

func inputFromCheck() <-chan *Info {
	var current string
	var lineno uint64
	var input *Info
	var err error

	f := os.Stdin
	if opts.input != "" {
		if f, err = os.Open(opts.check); err != nil {
			logger.Fatal(err)
		}
	}

	inputs := []*Info{}
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	files := make(chan *Info)
	go func() {
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
					if info := bestHash(inputs); info != nil {
						files <- info
					}
				}
				if eof {
					if err := scanner.Err(); err != nil {
						logger.Fatal(err)
					}
					break
				}
				current = input.file
				inputs = []*Info{}
			}
			if input != nil {
				inputs = append(inputs, input)
			}
		}
		close(files)
		f.Close()
	}()
	return files
}
