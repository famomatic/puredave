package dave

// ULEB128 helpers, following the WebRTC implementation used by libdave.

const leb128MaxSize = 10

func leb128Size(v uint64) int {
	n := 1
	for v >= 0x80 {
		n++
		v >>= 7
	}
	return n
}

// readLeb128 decodes a ULEB128 value from b, returning the value and the
// number of bytes consumed, or ok=false if b holds no complete value.
func readLeb128(b []byte) (value uint64, n int, ok bool) {
	fill := 0
	for n < len(b) && fill < 64-7 {
		c := b[n]
		value |= uint64(c&0x7f) << fill
		n++
		fill += 7
		if c&0x80 == 0 {
			return value, n, true
		}
	}
	// Nine bytes without a terminator: the tenth may carry a single bit.
	if n < len(b) && b[n] <= 1 {
		value |= uint64(b[n]) << fill
		return value, n + 1, true
	}
	return 0, 0, false
}

// appendLeb128 appends the ULEB128 encoding of v.
func appendLeb128(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, 0x80|byte(v&0x7f))
		v >>= 7
	}
	return append(dst, byte(v))
}
