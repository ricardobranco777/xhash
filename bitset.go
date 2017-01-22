// (C) 2017 by Ricardo Branco
//
// MIT License

package main

type word uint64

const (
	bitsPerWord = 64
)

type Bitset struct {
	words []word
	count int // Number of elements inserted
	max   int // Keep track of the maximum number ever inserted
}

// Returns a new Bitset. Set argument to the expected maximum number or -1.
func NewBitset(max int) *Bitset {
	words := 1
	if max >= 0 {
		words = max / bitsPerWord
		if max%bitsPerWord != 0 {
			words++
		}
	}
	bs := new(Bitset)
	bs.words = make([]word, words)
	bs.max = max
	return bs
}

func (bs *Bitset) Add(i int) {
	if i >= len(bs.words)*bitsPerWord {
		var newSet = make([]word, len(bs.words)+i/bitsPerWord+1)
		copy(newSet, bs.words)
		bs.words = newSet
	}
	bs.words[i/bitsPerWord] |= 1 << uint(i%bitsPerWord)
	bs.count++
	if i > bs.max {
		bs.max = i
	}
}

func (bs *Bitset) Del(i int) {
	bs.words[i/bitsPerWord] &= ^(1 << uint(i%bitsPerWord))
	bs.count--
}

func (bs *Bitset) Test(i int) bool {
	return (bs.words[i/bitsPerWord] & (1 << uint(i%bitsPerWord))) != 0
}

func (bs *Bitset) SetAll() {
	for i := range bs.words {
		bs.words[i] = ^word(0)
	}
	bs.count = len(bs.words) * bitsPerWord
	if bs.max >= 0 {
		bs.count = bs.max + 1
	}
}

func (bs *Bitset) ClearAll() {
	for i := range bs.words {
		bs.words[i] = 0
	}
	bs.count = 0
}

func (bs *Bitset) GetCount() int {
	return bs.count
}

// Returns a slice of all numbers in the set
func (bs *Bitset) GetAll() (s []int) {
	if bs.count == 0 {
		return
	}
	s = make([]int, 0, bs.count)
	for i, w := range bs.words {
		if w == 0 {
			continue
		}
		for bit := 0; bit < bitsPerWord; bit++ {
			if w&(1<<uint(bit)) != 0 {
				num := i*bitsPerWord + bit
				if num > bs.max {
					return
				}
				s = append(s, num)
			}
		}
	}
	return
}
