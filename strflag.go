// (C) 2016, 2017 by Ricardo Branco
//
// MIT License

package main

/*
 * The Set() and String() methods satisfy the Value interface of the flag package.
 * We use it to determine whether a string option was specified.
 */

type strFlag struct {
	*string
}

func (f *strFlag) Set(s string) error {
	f.string = &s
	return nil
}

func (f *strFlag) String() string {
	if f.string != nil {
		return *f.string
	}
	return ""
}
