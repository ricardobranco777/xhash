package bitset

type word uint64

const (
	bitsPerWord = 64
)

type Bitset struct {
	set   []word
	count int
}

func New() Bitset {
	bs := new(Bitset)
	bs.set = make([]word, 1)
	return *bs
}

func (bs *Bitset) Add(i int) {
	setlen := len(bs.set)
	if i >= setlen*bitsPerWord {
		var newSet = make([]word, setlen+i/bitsPerWord+1)
		copy(newSet, bs.set)
		bs.set = newSet
	}
	bs.set[i/bitsPerWord] |= 1 << uint(i%bitsPerWord)
	bs.count++
}

func (bs *Bitset) Del(i int) {
	bs.set[i/bitsPerWord] &= ^(1 << uint(i%bitsPerWord))
	bs.count--
}

func (bs *Bitset) Test(i int) bool {
	return (bs.set[i/bitsPerWord] & (1 << uint(i%bitsPerWord))) != 0
}

func (bs *Bitset) SetAll() {
	for i := range bs.set {
		bs.set[i] = ^word(0)
	}
	bs.count = len(bs.set) * bitsPerWord
}

func (bs *Bitset) ClearAll() {
	for i := range bs.set {
		bs.set[i] = 0
	}
	bs.count = 0
}

func (bs *Bitset) GetCount() int {
	return bs.count
}

func (bs *Bitset) GetAll(s []int) {
	for i, set := range bs.set {
		if set == 0 {
			continue
		}
		for bit := 0; bit < bitsPerWord; bit++ {
			if set&(1<<uint(bit)) != 0 {
				s = append(s, i*bitsPerWord+bit)
			}
		}
	}
	return
}
