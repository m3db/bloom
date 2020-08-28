package bloom

import (
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	stackmurmur3 "github.com/m3db/stackmurmur3"
	"github.com/stretchr/testify/assert"
	twmbmurmur3 "github.com/twmb/murmur3"
)

// previous implementation using a fork of github.com/spaolacci/murmur3
func stackConcurrentBloomFilterHashes(data []byte) [4]uint64 {
	var hash stackmurmur3.Digest128
	hash = hash.Write(data)
	h1, h2 := hash.Sum128()
	hash = hash.Write([]byte{1}) // Add entropy
	h3, h4 := hash.Sum128()
	return [4]uint64{h1, h2, h3, h4}
}

func TestMurmurSum128(t *testing.T) {
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

func TestBloomFilterHashes(t *testing.T) {
	properties := gopter.NewProperties(newGopterTestParameters())
	properties.Property("sum128WithEntropy matches stackmurmur3", prop.ForAll(
		func(v []byte) bool {
			var twmbH, spH [4]uint64
			twmbH = sum128WithEntropy(v)
			spH = stackConcurrentBloomFilterHashes(v)
			return assert.EqualValues(t, spH, twmbH)
		},
		newByteGen(),
	))

	properties.TestingRun(t)
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
