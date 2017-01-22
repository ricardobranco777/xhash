package bitset

type word uint64

const (
	bitsPerWord = 64
)

type Bitset struct {
	word  []word
	count int
}

func New() Bitset {
	bs := new(Bitset)
	bs.word = make([]word, 1)
	return *bs
}

func (bs *Bitset) Add(i int) {
	if i >= len(bs.word)*bitsPerWord {
		var newSet = make([]word, len(bs.word)+i/bitsPerWord+1)
		copy(newSet, bs.word)
		bs.word = newSet
	}
	bs.word[i/bitsPerWord] |= 1 << uint(i%bitsPerWord)
	bs.count++
}

func (bs *Bitset) Del(i int) {
	bs.word[i/bitsPerWord] &= ^(1 << uint(i%bitsPerWord))
	bs.count--
}

func (bs *Bitset) Test(i int) bool {
	return (bs.word[i/bitsPerWord] & (1 << uint(i%bitsPerWord))) != 0
}

func (bs *Bitset) SetAll() {
	for i := range bs.word {
		bs.word[i] = ^word(0)
	}
	bs.count = len(bs.word) * bitsPerWord
}

func (bs *Bitset) ClearAll() {
	for i := range bs.word {
		bs.word[i] = 0
	}
	bs.count = 0
}

func (bs *Bitset) GetCount() int {
	return bs.count
}

func (bs *Bitset) GetAll(s []int) {
	for i, w := range bs.word {
		if w == 0 {
			continue
		}
		for bit := 0; bit < bitsPerWord; bit++ {
			if w&(1<<uint(bit)) != 0 {
				s = append(s, i*bitsPerWord+bit)
			}
		}
	}
	return
}
