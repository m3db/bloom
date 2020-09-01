package bloom

import (
	"crypto/rand"
	"io"
	"testing"
	"unsafe"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/m3db/bloom/testdata"
	stackmurmur3 "github.com/m3db/stackmurmur3"
	"github.com/stretchr/testify/assert"
	twmbmurmur3 "github.com/twmb/murmur3"
)

const _benchStr = `"The quick brown fox jumps over the lazy dog" is an English-language pangram`

var _entropy = []byte{1}

func TestMurmurTwmbVsStackSum128(t *testing.T) {
	properties := gopter.NewProperties(newGopterTestParameters())
	properties.Property("twmb digest matches spaolacci", prop.ForAll(
		func(v []byte) bool {
			twmbH1, twmbH2 := twmbmurmur3.Sum128(v)
			var hash stackmurmur3.Digest128
			hash = hash.Write(v)
			spH1, spH2 := hash.Sum128()
			return spH1 == twmbH1 && spH2 == twmbH2
		},
		newByteGen(),
	))

	properties.TestingRun(t)
}

func TestBloomFilterHashesReferenceVsNew(t *testing.T) {
	properties := gopter.NewProperties(newGopterTestParameters())
	properties.Property("sum128WithEntropy matches reference stackmurmur3-based implementation",
		prop.ForAll(
			func(v []byte) bool {
				var twmbH, spH [4]uint64
				twmbH = sum128WithEntropy(v)
				spH = concurrentBloomFilterHashesReference(v)
				return assert.EqualValues(t, spH, twmbH)
			},
			newByteGen(),
		),
	)

	properties.TestingRun(t)
}

func TestBloomFilterHashesTwmbVsNew(t *testing.T) {
	properties := gopter.NewProperties(newGopterTestParameters())
	properties.Property("sum128WithEntropy matches reference stackmurmur3-based implementation",
		prop.ForAll(
			func(v []byte) bool {
				var twmbH, spH [4]uint64
				twmbH = sum128WithEntropy(v)
				spH = concurrentBloomFilterHashesTwmb(v)
				return assert.EqualValues(t, spH, twmbH)
			},
			newByteGen(),
		),
	)

	properties.TestingRun(t)
}
func TestBloomFilterHashesTwmbTestSuite(t *testing.T) {
	for _, test := range []struct {
		h64_1 uint64
		h64_2 uint64
		s     string
	}{
		// test suite from "github.com/twmb/murmur3"
		{0x0000000000000000, 0x0000000000000000, ""},
		{0xcbd8a7b341bd9b02, 0x5b1e906a48ae1d19, "hello"},
		{0x342fac623a5ebc8e, 0x4cdcbc079642414d, "hello, world"},
		{0xb89e5988b737affc, 0x664fc2950231b2cb, "19 Jan 2038 at 3:14:07 AM"},
		{0xcd99481f9ee902c9, 0x695da1a38987b6e7, "The quick brown fox jumps over the lazy dog."},
	} {
		refh1, refh2 := twmbmurmur3.StringSum128(test.s)
		hash := sum128WithEntropy([]byte(test.s))
		assert.EqualValues(t, refh1, hash[0])
		assert.EqualValues(t, refh2, hash[1])
	}
}

// Test suite function from github.com/twmb/murmur3
// go1.14 showed that doing *(*uint32)(unsafe.Pointer(&data[i*4])) was unsafe
// due to alignment issues; this test ensures that we will always catch that.
func TestUnaligned(t *testing.T) {
	in1 := []byte("abcdefghijklmnopqrstuvwxyz")
	in2 := []byte("_abcdefghijklmnopqrstuvwxyz")
	{
		hash1 := sum128WithEntropy(in1)
		hash2 := sum128WithEntropy(in2[1:])
		sum1l, sum1r := hash1[0], hash1[1]
		sum2l, sum2r := hash2[0], hash2[1]

		if sum1l != sum2l {
			t.Errorf("%s: got sum1l %v sum2l %v unexpectedly not equal", "Sum128 left", sum1l, sum2l)
		}
		if sum1r != sum2r {
			t.Errorf("%s: got sum1r %v sum2r %v unexpectedly not equal", "Sum128 right", sum1r, sum2r)
		}
	}
}

// Test suite function from github.com/twmb/murmur3
// TestBoundaries forces every block/tail path to be exercised for Sum32 and Sum128.
func TestBoundaries(t *testing.T) {
	const maxCheck = 17
	var (
		isLittleEndian = func() bool {
			i := uint16(1)
			return (*(*[2]byte)(unsafe.Pointer(&i)))[0] == 1
		}()
		data [maxCheck]byte
	)
	for i := 0; !t.Failed() && i < 20; i++ {
		// Check all zeros the first iteration.
		for size := 0; size <= maxCheck; size++ {
			test := data[:size]
			hash := sum128WithEntropy(test)
			g128h1, g128h2 := hash[0], hash[1]
			c128h1, c128h2 := g128h1, g128h2
			if isLittleEndian {
				c128h1, c128h2 = testdata.SeedSum128(0, test)
			}
			if g128h1 != c128h1 {
				t.Errorf("size #%d: in: %x, g128h1 (%d) != c128h1 (%d); attempt #%d", size, test, g128h1, c128h1, i)
			}
			if g128h2 != c128h2 {
				t.Errorf("size #%d: in: %x, g128h2 (%d) != c128h2 (%d); attempt #%d", size, test, g128h2, c128h2, i)
			}
		}
		// Randomize the data for all subsequent tests.
		io.ReadFull(rand.Reader, data[:])
	}
}

func BenchmarkBloomFilterHash(b *testing.B) {
	buf := []byte(_benchStr)
	for i := 0; i < b.N; i++ {
		_ = sum128WithEntropy(buf)
	}
}

func BenchmarkBloomFilterHash15(b *testing.B) {
	//  payload is not a multiple of 16 bytes, tail is 15 bytes
	buf := []byte(_benchStr + _benchStr)[:127]
	for i := 0; i < b.N; i++ {
		_ = sum128WithEntropy(buf)
	}
}

func BenchmarkBloomFilterHash16(b *testing.B) {
	// payload is a multiple of 16 bytes
	buf := []byte(_benchStr + _benchStr)[:128]
	for i := 0; i < b.N; i++ {
		_ = sum128WithEntropy(buf)
	}
}

func BenchmarkBloomFilterHashReference(b *testing.B) {
	buf := []byte(_benchStr)
	for i := 0; i < b.N; i++ {
		_ = concurrentBloomFilterHashesReference(buf)
	}
}

func BenchmarkBloomFilterHashReference15(b *testing.B) {
	//  payload is not a multiple of 16 bytes, tail is 15 bytes
	buf := []byte(_benchStr + _benchStr)[:127]
	for i := 0; i < b.N; i++ {
		_ = concurrentBloomFilterHashesReference(buf)
	}
}

func BenchmarkBloomFilterHashReference16(b *testing.B) {
	// payload is a multiple of 16 bytes
	buf := []byte(_benchStr + _benchStr)[:128]
	for i := 0; i < b.N; i++ {
		_ = concurrentBloomFilterHashesReference(buf)
	}
}

// reference implementation using a fork of github.com/spaolacci/murmur3
func concurrentBloomFilterHashesReference(data []byte) [4]uint64 {
	var hash stackmurmur3.Digest128
	hash = hash.Write(data)
	h1, h2 := hash.Sum128()
	hash = hash.Write(_entropy) // Add entropy
	h3, h4 := hash.Sum128()
	return [4]uint64{h1, h2, h3, h4}
}

// reference implementation using a fork of github.com/twmb/murmur3
func concurrentBloomFilterHashesTwmb(data []byte) [4]uint64 {
	var hash = twmbmurmur3.New128()
	hash.Write(data)
	h1, h2 := hash.Sum128()
	hash.Write(_entropy) // Add entropy
	h3, h4 := hash.Sum128()
	return [4]uint64{h1, h2, h3, h4}
}

func newGopterTestParameters() *gopter.TestParameters {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100000

	return params
}

// newByteGen returns a gopter generator for an []byte. All bytes (not just valid UTF-8) are generated.
func newByteGen() gopter.Gen {
	// uint8 == byte; therefore, derive []byte generator from []uint8 generator.
	return gopter.DeriveGen(func(v []uint8) []byte {
		out := make([]byte, len(v))
		for i, val := range v {
			out[i] = val
		}
		return out
	}, func(v []byte) []uint8 {
		out := make([]byte, len(v))
		for i, val := range v {
			out[i] = val
		}
		return out
	}, gen.SliceOf(gen.UInt8()))
}
