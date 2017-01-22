// (C) 2016, 2017 by Ricardo Branco
//
// MIT License

package main

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
