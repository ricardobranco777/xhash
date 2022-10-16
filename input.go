package main

import (
	"bufio"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

import flag "github.com/spf13/pflag"

func inputFromArgs(f io.ReadCloser) <-chan *Checksums {
	files := make(chan *Checksums)
	go func() {
		for _, arg := range flag.Args() {
			files <- &Checksums{file: arg}
		}
		close(files)
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

	files := make(chan *Checksums)
	go func() {
		for _, arg := range flag.Args() {
			walkDir(arg, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					logger.Print(err)
				} else if opts.symlinks && isSymlink(d) || !d.IsDir() && !isSymlink(d) {
					files <- &Checksums{file: path}
				}
				return nil
			})
		}
		close(files)
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
				logger.Fatal(err)
			}
		}
	}

	scanner := bufio.NewScanner(f)
	if opts.zero {
		scanner.Split(scanLinesZ)
	} else {
		scanner.Split(bufio.ScanLines)
	}

	files := make(chan *Checksums)
	go func() {
		for scanner.Scan() {
			if err := scanner.Err(); err != nil {
				logger.Fatal(err)
			}
			file := scanner.Text()
			if file != "" {
				files <- &Checksums{file: scanner.Text()}
			}
		}
		close(files)
		f.Close()
	}()
	return files
}
