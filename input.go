package main

import (
	"io"
	"io/fs"
	"log"
	"path/filepath"
)

const chanSize = 1024

func inputFromArgs(args []string) <-chan *Checksums {
	files := make(chan *Checksums, min(len(args), chanSize))

	go func() {
		defer close(files)
		for _, arg := range args {
			files <- &Checksums{file: arg}
		}
	}()

	return files
}

// Used by the -r option
func inputFromDir(args []string, followSymlinks bool) <-chan *Checksums {
	isSymlink := func(d fs.DirEntry) bool { return d.Type()&fs.ModeType == fs.ModeSymlink }

	walkDir := filepath.WalkDir
	if fsys != nil {
		walkDir = func(root string, fn fs.WalkDirFunc) error { return fs.WalkDir(fsys, root, fn) }
	}

	files := make(chan *Checksums, chanSize)

	go func() {
		defer close(files)
		for _, arg := range args {
			walkDir(arg, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					log.Print(err)
				} else if followSymlinks && isSymlink(d) || !d.IsDir() && !isSymlink(d) {
					files <- &Checksums{file: path}
				}
				return nil
			})
		}
	}()

	return files
}

// Used by the -i option
func inputFromFile(f io.ReadCloser, zeroTerminated bool) <-chan *Checksums {
	files := make(chan *Checksums, chanSize)

	go func() {
		defer close(files)
		defer f.Close()

		scanner, err := getScanner(f, zeroTerminated)
		if err != nil {
			log.Fatal(err)
		}
		for scanner.Scan() {
			if err := scanner.Err(); err != nil {
				log.Fatal(err)
			}
			file := scanner.Text()
			if file != "" {
				files <- &Checksums{file: scanner.Text()}
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	}()

	return files
}
