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
	// Calculate 1st set of hashes - twmb/murmur3 Sum128() of payload
	clen := len(data)
	for len(data) >= 16 { // bmix() step
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

	// The following line diverges from twmb/murmur3.Sum128() in a cruicial way:
	// - for the 2nd hash set for Bloom filter, we need to save seed state to recalculate the hash
	//   as if the *data* was exactly the same, just with the last *byte* being equal to `entropy`
	var _h1, _h2 = h1, h2
	// end of change from twmb/murmur3
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
	// End of original twmb/murmur3.Sum128
	// Save this hash, as it's equivalent of h1, h2 = hash.Write(data).Sum128()
	res[0], res[1] = h1, h2

	// Now, reset state back to before the tail calculation.
	// The state is such that all but final 15 bytes have been processed, as murmur3 works
	// on 128 bit / 16 byte chunks for all but the final mixing.
	// last byte of the array, and apply the Sum128() logic accordingly.
	k1, k2 = 0, 0
	h1, h2 = _h1, _h2 // restore state to before final mixing
	clen++            // total hash data length now includes entropy

	rlen := len(data) // remainder length

	// If we are really lucky and remainder was 15 bytes, with entropy byte it is now a full 16 byte block.
	// In that case, just apply bmix() again, with the modified payload and directly go to hash finalization.
	if rlen == 15 {
		k1 = uint64(data[0]) | uint64(data[1])<<8 | uint64(data[2])<<16 | uint64(data[3])<<24 | uint64(data[4])<<32 | uint64(data[5])<<40 | uint64(data[6])<<48 | uint64(data[7])<<56
		// Note: this is different from original bmix() - we don't mutate `data`,
		// so we reuse the entire 15 byte slice of the original remainder and treat the last byte as equal to `entropy`
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
		// No further processing needed, skip the next state
		goto Finalize
	}

	// Process entropy byte - note, **no fallthrough**, because how we process it depends on how long the payload is
	switch rlen + 1 {
	case 15: // the entropy byte index is 15
		k2 ^= entropy << 48
		goto l14 // jump into processing rest of the array, at position 14
	case 14: // entropy byte index is 14 ...
		k2 ^= entropy << 40
		goto l13
	case 13:
		k2 ^= entropy << 32
		goto l12
	case 12:
		k2 ^= entropy << 24
		goto l11
	case 11:
		k2 ^= entropy << 16
		goto l10
	case 10:
		k2 ^= entropy << 8
		goto l9
	case 9:
		k2 ^= entropy << 0
		k2 *= c2_128
		k2 = bits.RotateLeft64(k2, 33)
		k2 *= c1_128
		h2 ^= k2
		goto l8
	case 8:
		k1 ^= entropy << 56
		goto l7
	case 7:
		k1 ^= entropy << 48
		goto l6
	case 6:
		k1 ^= entropy << 40
		goto l5
	case 5:
		k1 ^= entropy << 32
		goto l4
	case 4:
		k1 ^= entropy << 24
		goto l3
	case 3:
		k1 ^= entropy << 16
		goto l2
	case 2:
		k1 ^= entropy << 8
		goto l1
	case 1:
		// Case where entropy byte is the actual tail (payload length is a multiple of 16 bytes)
		k1 ^= entropy << 0
		k1 *= c1_128
		k1 = bits.RotateLeft64(k1, 31)
		k1 *= c2_128
		h1 ^= k1
		goto Finalize // Nothing else to do but finalize the hash
	}

	// Process the payload that is before entropy byte.
	// Entropy was handled in the switch above: it will directly jump into the code below,
	// depending on remaining payload length.
l14:
	k2 ^= uint64(data[13]) << 40
l13:
	k2 ^= uint64(data[12]) << 32
l12:
	k2 ^= uint64(data[11]) << 24
l11:
	k2 ^= uint64(data[10]) << 16
l10:
	k2 ^= uint64(data[9]) << 8
l9:
	k2 ^= uint64(data[8]) << 0
	k2 *= c2_128
	k2 = bits.RotateLeft64(k2, 33)
	k2 *= c1_128
	h2 ^= k2
l8:
	k1 ^= uint64(data[7]) << 56
l7:
	k1 ^= uint64(data[6]) << 48
l6:
	k1 ^= uint64(data[5]) << 40
l5:
	k1 ^= uint64(data[4]) << 32
l4:
	k1 ^= uint64(data[3]) << 24
l3:
	k1 ^= uint64(data[2]) << 16
l2:
	k1 ^= uint64(data[1]) << 8
l1:
	k1 ^= uint64(data[0]) << 0
	k1 *= c1_128
	k1 = bits.RotateLeft64(k1, 31)
	k1 *= c2_128
	h1 ^= k1

Finalize:
	h1 ^= uint64(clen)
	h2 ^= uint64(clen)

	h1 += h2
	h2 += h1

	h1 = fmix64(h1)
	h2 = fmix64(h2)

	h1 += h2
	h2 += h1

	// That's it, save 2nd hash, equivalent of twmb/murmur3.Sum128(data + '\0x01') (byte of entropy)
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
