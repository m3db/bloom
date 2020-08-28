package bloom

import "math/bits"

const (
	c1_128         = 0x87c37b91114253d5
	c2_128         = 0x4cf5ad432745937f
	entropy uint64 = 1
)

// murmur3 hash variant from https://github.com/twmb/murmur3
// used in M3DB bloom filter, code equivalent to:
//
// 	var hash stackmurmur3.Digest128
// 	hash = hash.Write(data)
// 	h1, h2 := hash.Sum128()
// 	hash = hash.Write(entropy) // Add entropy
// 	h3, h4 := hash.Sum128()
// 	return [4]uint64{h1, h2, h3, h4}
//
// M3DB should really just use two different hashes
func sum128WithEntropy(data []byte) [4]uint64 {
	var (
		h1, h2 uint64
		res    [4]uint64
	)
	clen := len(data)
	for len(data) >= 16 {
		// yes, this is faster than using binary.LittleEndian.Uint64
		k1 := uint64(data[0]) | uint64(data[1])<<8 | uint64(data[2])<<16 | uint64(data[3])<<24 | uint64(data[4])<<32 | uint64(data[5])<<40 | uint64(data[6])<<48 | uint64(data[7])<<56
		k2 := uint64(data[8]) | uint64(data[9])<<8 | uint64(data[10])<<16 | uint64(data[11])<<24 | uint64(data[12])<<32 | uint64(data[13])<<40 | uint64(data[14])<<48 | uint64(data[15])<<56

		data = data[16:]

		k1 *= c1_128
		k1 = bits.RotateLeft64(k1, 31)
		k1 *= c2_128
		h1 ^= k1

		h1 = bits.RotateLeft64(h1, 27)
		h1 += h2
		h1 = h1*5 + 0x52dce729

		k2 *= c2_128
		k2 = bits.RotateLeft64(k2, 33)
		k2 *= c1_128
		h2 ^= k2

		h2 = bits.RotateLeft64(h2, 31)
		h2 += h1
		h2 = h2*5 + 0x38495ab5
	}

	var _h1, _h2 = h1, h2 // save state after mixing, before final processing
	var k1, k2 uint64
	switch len(data) {
	case 15:
		k2 ^= uint64(data[14]) << 48
		fallthrough
	case 14:
		k2 ^= uint64(data[13]) << 40
		fallthrough
	case 13:
		k2 ^= uint64(data[12]) << 32
		fallthrough
	case 12:
		k2 ^= uint64(data[11]) << 24
		fallthrough
	case 11:
		k2 ^= uint64(data[10]) << 16
		fallthrough
	case 10:
		k2 ^= uint64(data[9]) << 8
		fallthrough
	case 9:
		k2 ^= uint64(data[8]) << 0

		k2 *= c2_128
		k2 = bits.RotateLeft64(k2, 33)
		k2 *= c1_128
		h2 ^= k2

		fallthrough

	case 8:
		k1 ^= uint64(data[7]) << 56
		fallthrough
	case 7:
		k1 ^= uint64(data[6]) << 48
		fallthrough
	case 6:
		k1 ^= uint64(data[5]) << 40
		fallthrough
	case 5:
		k1 ^= uint64(data[4]) << 32
		fallthrough
	case 4:
		k1 ^= uint64(data[3]) << 24
		fallthrough
	case 3:
		k1 ^= uint64(data[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint64(data[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint64(data[0]) << 0
		k1 *= c1_128
		k1 = bits.RotateLeft64(k1, 31)
		k1 *= c2_128
		h1 ^= k1
	}

	h1 ^= uint64(clen)
	h2 ^= uint64(clen)

	h1 += h2
	h2 += h1

	h1 = fmix64(h1)
	h2 = fmix64(h2)

	h1 += h2
	h2 += h1

	res[0], res[1] = h1, h2 // done with 1st hash
	// the last 128 bytes is hash for the same data with 0x01 appended for entropy
	// h3, h4 = hash.Write(data).Write([]byte{1}).Sum128()
	k1, k2 = 0, 0
	h1, h2 = _h1, _h2      // restore state
	clen++                 // add entropy byte to total hash data length
	switch len(data) + 1 { // process entropy byte *only*, no fallthrough - unless it's now a full block
	case 16: // == entire block
		k1 = uint64(data[0]) | uint64(data[1])<<8 | uint64(data[2])<<16 | uint64(data[3])<<24 | uint64(data[4])<<32 | uint64(data[5])<<40 | uint64(data[6])<<48 | uint64(data[7])<<56
		k2 = uint64(data[8]) | uint64(data[9])<<8 | uint64(data[10])<<16 | uint64(data[11])<<24 | uint64(data[12])<<32 | uint64(data[13])<<40 | uint64(data[14])<<48 | entropy<<56

		k1 *= c1_128
		k1 = bits.RotateLeft64(k1, 31)
		k1 *= c2_128
		h1 ^= k1

		h1 = bits.RotateLeft64(h1, 27)
		h1 += h2
		h1 = h1*5 + 0x52dce729

		k2 *= c2_128
		k2 = bits.RotateLeft64(k2, 33)
		k2 *= c1_128
		h2 ^= k2

		h2 = bits.RotateLeft64(h2, 31)
		h2 += h1
		h2 = h2*5 + 0x38495ab5
	case 15:
		k2 ^= entropy << 48
	case 14:
		k2 ^= entropy << 40
	case 13:
		k2 ^= entropy << 32
	case 12:
		k2 ^= entropy << 24
	case 11:
		k2 ^= entropy << 16
	case 10:
		k2 ^= entropy << 8
	case 9:
		k2 ^= entropy << 0
		k2 *= c2_128
		k2 = bits.RotateLeft64(k2, 33)
		k2 *= c1_128
		h2 ^= k2
	case 8:
		k1 ^= entropy << 56
	case 7:
		k1 ^= entropy << 48
	case 6:
		k1 ^= entropy << 40
	case 5:
		k1 ^= entropy << 32
	case 4:
		k1 ^= entropy << 24
	case 3:
		k1 ^= entropy << 16
	case 2:
		k1 ^= entropy << 8
	case 1:
		k1 ^= entropy << 0
		k1 *= c1_128
		k1 = bits.RotateLeft64(k1, 31)
		k1 *= c2_128
		h1 ^= k1
	}

	switch len(data) {
	case 15: // nothing, entire block processed
	case 14:
		k2 ^= uint64(data[13]) << 40
		fallthrough
	case 13:
		k2 ^= uint64(data[12]) << 32
		fallthrough
	case 12:
		k2 ^= uint64(data[11]) << 24
		fallthrough
	case 11:
		k2 ^= uint64(data[10]) << 16
		fallthrough
	case 10:
		k2 ^= uint64(data[9]) << 8
		fallthrough
	case 9:
		k2 ^= uint64(data[8]) << 0

		k2 *= c2_128
		k2 = bits.RotateLeft64(k2, 33)
		k2 *= c1_128
		h2 ^= k2

		fallthrough

	case 8:
		k1 ^= uint64(data[7]) << 56
		fallthrough
	case 7:
		k1 ^= uint64(data[6]) << 48
		fallthrough
	case 6:
		k1 ^= uint64(data[5]) << 40
		fallthrough
	case 5:
		k1 ^= uint64(data[4]) << 32
		fallthrough
	case 4:
		k1 ^= uint64(data[3]) << 24
		fallthrough
	case 3:
		k1 ^= uint64(data[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint64(data[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint64(data[0]) << 0
		k1 *= c1_128
		k1 = bits.RotateLeft64(k1, 31)
		k1 *= c2_128
		h1 ^= k1
	}

	h1 ^= uint64(clen)
	h2 ^= uint64(clen)

	h1 += h2
	h2 += h1

	h1 = fmix64(h1)
	h2 = fmix64(h2)

	h1 += h2
	h2 += h1
	res[2], res[3] = h1, h2
	return res
}

func fmix64(k uint64) uint64 {
	k ^= k >> 33
	k *= 0xff51afd7ed558ccd
	k ^= k >> 33
	k *= 0xc4ceb9fe1a85ec53
	k ^= k >> 33
	return k
}
