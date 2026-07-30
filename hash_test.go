package main

import (
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"github.com/pkg/xattr"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var xchecksum = map[string][]*Checksum{
	"": {
		{
			hash: crypto.MD5,
			csum: []byte{0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e},
		},
		{
			hash: crypto.SHA256,
			csum: []byte{0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55},
		},
	},
}

var hmacKey = []byte{0xab, 0xcd}
var xhmac = map[string][]*Checksum{
	"": {
		{
			hash: crypto.MD5,
			csum: []byte{0xe2, 0x60, 0xf5, 0x76, 0xe1, 0xa6, 0xd2, 0x8b, 0x65, 0x9f, 0xba, 0x8f, 0xa8, 0xc7, 0x09, 0x4e},
		},
		{
			hash: crypto.SHA256,
			csum: []byte{0x6a, 0xcf, 0xf2, 0x42, 0x29, 0xa6, 0xef, 0x2c, 0x5f, 0x26, 0xc0, 0xca, 0xf7, 0xdf, 0xb6, 0x0c, 0x85, 0xd9, 0xc5, 0xbe, 0x9f, 0xe1, 0x94, 0x26, 0xaa, 0x97, 0xb0, 0xac, 0xe1, 0x82, 0x94, 0x76},
		},
	},
}

func testIt(t *testing.T, funcname string, f func(io.ReadCloser, []*Checksum) ([]*Checksum, Size)) {
	// SHA256("The quick brown fox jumps over the lazy dog")
	foxString := "The quick brown fox jumps over the lazy dog"
	foxSha256 := []byte{0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92}

	for checksum := range xchecksum {
		reader := io.NopCloser(strings.NewReader(checksum))
		got, _ := f(reader, xchecksum[checksum][:1])
		if !reflect.DeepEqual(got, xchecksum[checksum][:1]) {
			t.Errorf("%s(%q) got %v, want %v", funcname, checksum, got, xchecksum[checksum][:1])
		}
	}

	// Test with nil (should default to SHA-256)
	reader := io.NopCloser(strings.NewReader(foxString))
	got, _ := f(reader, nil)
	if got[0].hash != crypto.SHA256 || !bytes.Equal(got[0].sum, foxSha256) {
		t.Errorf("%s(%q) got %v, want %v", funcname, foxString, got[0].sum, foxSha256)
	}

	// Test HMAC
	oldKey := macKey
	macKey = hmacKey
	defer func() { macKey = oldKey }()

	for checksum := range xhmac {
		reader := io.NopCloser(strings.NewReader(checksum))
		want := xhmac[checksum][:1]
		got, _ := f(reader, want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s(%q) got %v, want %v", funcname, checksum, got, want)
		}
	}
}

func testIt2(t *testing.T, funcname string, f func(io.ReadCloser, []*Checksum) ([]*Checksum, Size)) {
	for checksum, want := range xchecksum {
		reader := io.NopCloser(strings.NewReader(checksum))
		got, _ := f(reader, want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s(%q) got %v, want %v", funcname, checksum, got, want)
		}
	}

	// Test HMAC
	oldKey := macKey
	macKey = hmacKey
	defer func() { macKey = oldKey }()

	for checksum, want := range xhmac {
		reader := io.NopCloser(strings.NewReader(checksum))
		got, _ := f(reader, want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s(%q) got %v, want %v", funcname, checksum, got, want)
		}
	}
}

func Test_hashF(t *testing.T) {
	testIt(t, "hashF", hashF)
	testIt2(t, "hashF", hashF)
}

// xattrTestFile creates a temp file and skips the test if the underlying
// filesystem doesn't support extended attributes (e.g. some CI sandboxes).
func xattrTestFile(t *testing.T, data string) string {
	t.Helper()
	if !xattr.XATTR_SUPPORTED {
		t.Skip("xattr not supported on this platform")
	}
	file := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(file, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := xattr.Set(file, "user.test", []byte("x")); err != nil {
		t.Skipf("filesystem does not support extended attributes: %v", err)
	}
	return file
}

func Test_xattrName(t *testing.T) {
	c := &Checksum{hash: crypto.SHA256}
	want := "user.checksum.sha256"
	if got := xattrName(c); got != want {
		t.Errorf("xattrName() = %q, want %q", got, want)
	}
}

func Test_setCachedSum(t *testing.T) {
	file := xattrTestFile(t, "hello")

	c := &Checksum{hash: crypto.SHA256}
	sum := sha256.Sum256([]byte("hello"))
	c.sum = sum[:]

	setCachedSum(file, c)

	got, err := xattr.Get(file, "user.checksum.sha256")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != hex.EncodeToString(c.sum) {
		t.Fatalf("stored attribute = %q, want %q", got, hex.EncodeToString(c.sum))
	}
}

func Test_getCachedSum(t *testing.T) {
	file := xattrTestFile(t, "hello")

	c := &Checksum{hash: crypto.SHA256}
	if got := getCachedSum(file, c); got != nil {
		t.Fatalf("getCachedSum() before Set = %x, want nil", got)
	}

	sum := sha256.Sum256([]byte("hello"))
	c.sum = sum[:]
	setCachedSum(file, c)

	if got := getCachedSum(file, c); !bytes.Equal(got, sum[:]) {
		t.Fatalf("getCachedSum() = %x, want %x", got, sum)
	}

	// A garbage attribute value must not be returned as a digest.
	if err := xattr.Set(file, xattrName(c), []byte("not hex")); err != nil {
		t.Fatal(err)
	}
	if got := getCachedSum(file, c); got != nil {
		t.Fatalf("getCachedSum() with garbage value = %x, want nil", got)
	}
}

func Test_xattrChecksums(t *testing.T) {
	file := xattrTestFile(t, "hello")

	oldChosen := chosen
	chosen = []crypto.Hash{crypto.SHA256, crypto.MD5}
	defer func() { chosen = oldChosen }()

	// Nothing cached yet: every csum comes back nil.
	got := xattrChecksums(file)
	for _, c := range got {
		if c.csum != nil {
			t.Errorf("xattrChecksums() csum for %v = %x, want nil", c.hash, c.csum)
		}
	}

	sha := sha256.Sum256([]byte("hello"))
	setCachedSum(file, &Checksum{hash: crypto.SHA256, sum: sha[:]})
	md := md5.Sum([]byte("hello"))
	setCachedSum(file, &Checksum{hash: crypto.MD5, sum: md[:]})

	got = xattrChecksums(file)
	for _, c := range got {
		switch c.hash {
		case crypto.SHA256:
			if !bytes.Equal(c.csum, sha[:]) {
				t.Errorf("xattrChecksums() sha256 csum = %x, want %x", c.csum, sha)
			}
		case crypto.MD5:
			if !bytes.Equal(c.csum, md[:]) {
				t.Errorf("xattrChecksums() md5 csum = %x, want %x", c.csum, md)
			}
		}
	}
}

// setXattrMode sets opts.xattr for the duration of the test and restores it
// (along with chosen) on cleanup.
func setXattrMode(t *testing.T, mode string) {
	t.Helper()
	oldXattr, oldChosen := opts.xattr, chosen
	opts.xattr = mode
	chosen = []crypto.Hash{crypto.SHA256}
	t.Cleanup(func() {
		opts.xattr = oldXattr
		chosen = oldChosen
	})
}

func Test_hashFile_xattrStore(t *testing.T) {
	file := xattrTestFile(t, "hello")
	setXattrMode(t, xattrStore)

	// store always overwrites, regardless of whatever might already be
	// cached: there's no comparison, no staleness tracking.
	if err := xattr.Set(file, "user.checksum.sha256", []byte(hex.EncodeToString(bytes.Repeat([]byte{0xAB}, sha256.Size)))); err != nil {
		t.Fatal(err)
	}

	want := sha256.Sum256([]byte("hello"))
	got, err := hashFile(file, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.checksums[0].sum, want[:]) {
		t.Fatalf("hashFile() sum = %x, want %x", got.checksums[0].sum, want)
	}

	cached, err := xattr.Get(file, "user.checksum.sha256")
	if err != nil {
		t.Fatal(err)
	}
	if string(cached) != hex.EncodeToString(want[:]) {
		t.Fatalf("cached digest = %q, want %q", cached, hex.EncodeToString(want[:]))
	}
}

func Test_hashFile_xattrVerify(t *testing.T) {
	file := xattrTestFile(t, "hello")
	setXattrMode(t, xattrVerify)

	// Nothing cached yet: csum comes back nil, sum is freshly computed, and
	// verify never writes -- the cache stays empty.
	want := sha256.Sum256([]byte("hello"))
	got, err := hashFile(file, xattrChecksums(file))
	if err != nil {
		t.Fatal(err)
	}
	if got.checksums[0].csum != nil {
		t.Fatalf("csum = %x, want nil (nothing cached yet)", got.checksums[0].csum)
	}
	if !bytes.Equal(got.checksums[0].sum, want[:]) {
		t.Fatalf("sum = %x, want %x", got.checksums[0].sum, want)
	}
	if _, err := xattr.Get(file, "user.checksum.sha256"); err == nil {
		t.Fatal("verify must not write a cached value")
	}

	// Populate a baseline directly, then verify it matches.
	setCachedSum(file, &Checksum{hash: crypto.SHA256, sum: want[:]})
	got, err = hashFile(file, xattrChecksums(file))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.checksums[0].csum, want[:]) || !bytes.Equal(got.checksums[0].sum, want[:]) {
		t.Fatalf("sum = %x, csum = %x, want both %x", got.checksums[0].sum, got.checksums[0].csum, want)
	}

	// Tamper with the file: verify reports the mismatch but leaves the
	// cached (pre-tamper) value untouched -- it's the evidence of what
	// changed.
	if err := os.WriteFile(file, []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = hashFile(file, xattrChecksums(file))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got.checksums[0].sum, got.checksums[0].csum) {
		t.Fatalf("sum and csum unexpectedly match after tampering: %x", got.checksums[0].sum)
	}
	cached, err := xattr.Get(file, "user.checksum.sha256")
	if err != nil {
		t.Fatal(err)
	}
	if string(cached) != hex.EncodeToString(want[:]) {
		t.Fatalf("verify overwrote the cached value: got %q, want pre-tamper %q", cached, hex.EncodeToString(want[:]))
	}
}

func Test_hashFile_xattrForce(t *testing.T) {
	file := xattrTestFile(t, "hello")
	setXattrMode(t, xattrForce)

	// Nothing cached yet: treated as a mismatch, and force writes the new
	// baseline.
	want := sha256.Sum256([]byte("hello"))
	got, err := hashFile(file, xattrChecksums(file))
	if err != nil {
		t.Fatal(err)
	}
	if got.checksums[0].csum != nil {
		t.Fatalf("csum = %x, want nil (nothing cached yet)", got.checksums[0].csum)
	}
	cached, err := xattr.Get(file, "user.checksum.sha256")
	if err != nil {
		t.Fatal(err)
	}
	if string(cached) != hex.EncodeToString(want[:]) {
		t.Fatalf("force did not store the initial baseline: got %q, want %q", cached, hex.EncodeToString(want[:]))
	}

	// Tamper with the file: force accepts the new digest as the baseline.
	wantTampered := sha256.Sum256([]byte("hello world"))
	if err := os.WriteFile(file, []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := hashFile(file, xattrChecksums(file)); err != nil {
		t.Fatal(err)
	}
	cached, err = xattr.Get(file, "user.checksum.sha256")
	if err != nil {
		t.Fatal(err)
	}
	if string(cached) != hex.EncodeToString(wantTampered[:]) {
		t.Fatalf("cache was not refreshed with force: got %q, want %q", cached, hex.EncodeToString(wantTampered[:]))
	}
}

func BenchmarkHashes(b *testing.B) {
	buf := make([]byte, 16384)

	for _, h := range hashes {
		checksum := &Checksum{hash: h}
		name := h.String()
		if h == BLAKE3 {
			name = "BLAKE3"
		}
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				initHash(checksum)
				if _, err := checksum.Write(buf); err != nil {
					panic(err)
				}
				checksum.sum = checksum.Sum(nil)
			}
		})
	}
}
