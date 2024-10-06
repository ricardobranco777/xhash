package main

import (
	"context"
	"golang.org/x/sync/errgroup"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
)

import flag "github.com/spf13/pflag"

func inputFromArgs(g *errgroup.Group, ctx context.Context, f io.ReadCloser) <-chan *Checksums {
	files := make(chan *Checksums, 1024)

	g.Go(func() error {
		defer close(files)
		for _, arg := range flag.Args() {
			select {
			case files <- &Checksums{file: arg}:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})

	return files
}

// Used by the -r option
func inputFromDir(g *errgroup.Group, ctx context.Context, f io.ReadCloser) <-chan *Checksums {
	isSymlink := func(d fs.DirEntry) bool { return d.Type()&fs.ModeType == fs.ModeSymlink }

	walkDir := filepath.WalkDir
	if fsys != nil {
		walkDir = func(root string, fn fs.WalkDirFunc) error { return fs.WalkDir(fsys, root, fn) }
	}

	files := make(chan *Checksums, 1024)

	g.Go(func() error {
		defer close(files)
		for _, arg := range flag.Args() {
			if err := walkDir(arg, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					log.Print(err)
				} else if opts.symlinks && isSymlink(d) || !d.IsDir() && !isSymlink(d) {
					select {
					case files <- &Checksums{file: path}:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	})

	return files
}

// Used by the -i option
func inputFromFile(g *errgroup.Group, ctx context.Context, f io.ReadCloser) <-chan *Checksums {
	var err error

	if f == nil {
		f = os.Stdin
		if opts.input != "" {
			if f, err = os.Open(opts.input); err != nil {
				log.Fatal(err)
			}
		}
	}

	scanner := getScanner(f)
	files := make(chan *Checksums, 1024)

	g.Go(func() error {
		defer close(files)
		defer f.Close()
		for scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return err
			}
			file := scanner.Text()
			if file != "" {
				select {
				case files <- &Checksums{file: scanner.Text()}:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
		if err := scanner.Err(); err != nil {
			return err
		}
		return nil
	})

	return files
}
