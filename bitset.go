// (C) 2017 by Ricardo Branco
//
// MIT License

package main

type word uint64

const (
	bitsPerWord = 64
)

type Bitset struct {
	word
	count int // Number of elements inserted
	max   int // Keep track of the maximum number ever inserted
}

// Returns a new Bitset. Set argument to the expected maximum number or -1.
func NewBitset(max int) *Bitset {
	bs := new(Bitset)
	bs.max = max
	return bs
}

func (bs *Bitset) Add(i int) {
	bs.word |= 1 << uint(i%bitsPerWord)
	bs.count++
	if i > bs.max {
		bs.max = i
	}
}

func (bs *Bitset) Del(i int) {
	bs.word &= ^(1 << uint(i%bitsPerWord))
	bs.count--
}

func (bs *Bitset) Test(i int) bool {
	return (bs.word & (1 << uint(i%bitsPerWord))) != 0
}

func (bs *Bitset) SetAll() {
	bs.word = ^word(0)
	if bs.max >= 0 {
		bs.count = bs.max + 1
	} else {
		bs.count = bitsPerWord
	}
}

func (bs *Bitset) ClearAll() {
	bs.word = 0
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
	w := bs.word
	for {
		if w == 0 {
			break
		}
		bit := ffs(w)
		num := int(bit)
		if num > bs.max {
			return
		}
		s = append(s, num)
		w &= ^(1 << bit)
	}
	return
}

func ffs(w word) (bit uint) {
	if w&0xffffffff == 0 {
		bit += 32
		w >>= 32
	}
	if w&0xffff == 0 {
		bit += 16
		w >>= 16
	}
	if w&0xff == 0 {
		bit += 8
		w >>= 8
	}
	if w&0xf == 0 {
		bit += 4
		w >>= 4
	}
	if w&0x3 == 0 {
		bit += 2
		w >>= 2
	}
	if w&0x1 == 0 {
		bit++
	}
	return
}
