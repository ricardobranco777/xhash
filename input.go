package main

import (
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
)

import flag "github.com/spf13/pflag"

func inputFromArgs(f io.ReadCloser) <-chan *Checksums {
	files := make(chan *Checksums, 1024)

	go func() {
		defer close(files)
		for _, arg := range flag.Args() {
			files <- &Checksums{file: arg}
		}
	}()

	return files
}

// Used by the -r option
func inputFromDir(f io.ReadCloser) <-chan *Checksums {
	isSymlink := func(d fs.DirEntry) bool { return d.Type()&fs.ModeType == fs.ModeSymlink }

	walkDir := filepath.WalkDir
	if fsys != nil {
		walkDir = func(root string, fn fs.WalkDirFunc) error { return fs.WalkDir(fsys, root, fn) }
	}

	files := make(chan *Checksums, 1024)

	go func() {
		defer close(files)
		for _, arg := range flag.Args() {
			walkDir(arg, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					log.Print(err)
				} else if opts.symlinks && isSymlink(d) || !d.IsDir() && !isSymlink(d) {
					files <- &Checksums{file: path}
				}
				return nil
			})
		}
	}()

	return files
}

// Used by the -i option
func inputFromFile(f io.ReadCloser) <-chan *Checksums {
	var err error

	if f == nil {
		f = os.Stdin
		if opts.input != "" {
			if f, err = os.Open(opts.input); err != nil {
				log.Fatal(err)
			}
		}
	}

	files := make(chan *Checksums, 1024)

	go func() {
		defer close(files)
		defer f.Close()
		scanner := getScanner(f)
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
