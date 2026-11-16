// Package scrypt implements the scrypt key derivation function (RFC 7914)
// on top of the standard library.
package scrypt

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"
)

// Key derives a key of length keyLen from password and salt.
// N must be a power of two greater than 1.
func Key(password, salt []byte, N, r, p, keyLen int) ([]byte, error) {
	if N <= 1 || N&(N-1) != 0 {
		return nil, errors.New("scrypt: N must be > 1 and a power of 2")
	}
	if r <= 0 || p <= 0 || uint64(r)*uint64(p) >= 1<<30 || r > (1<<31-1)/128/p || r > (1<<31-1)/256 || N > (1<<31-1)/128/r {
		return nil, errors.New("scrypt: parameters are too large")
	}
	b, err := pbkdf2.Key(sha256.New, string(password), salt, 1, p*128*r)
	if err != nil {
		return nil, err
	}
	xy := make([]uint32, 64*r)
	v := make([]uint32, 32*N*r)
	for i := 0; i < p; i++ {
		smix(b[i*128*r:], r, N, v, xy)
	}
	return pbkdf2.Key(sha256.New, string(password), b, 1, keyLen)
}

func smix(b []byte, r, N int, v, xy []uint32) {
	var tmp [16]uint32
	R := 32 * r
	x := xy
	y := xy[R:]
	j := 0
	for i := 0; i < R; i++ {
		x[i] = binary.LittleEndian.Uint32(b[j:])
		j += 4
	}
	for i := 0; i < N; i += 2 {
		copy(v[i*R:], x)
		blockMix(&tmp, x, y, r)
		copy(v[(i+1)*R:], y)
		blockMix(&tmp, y, x, r)
	}
	for i := 0; i < N; i += 2 {
		k := int(integer(x, r) & uint64(N-1))
		blockXOR(x, v[k*R:], R)
		blockMix(&tmp, x, y, r)
		k = int(integer(y, r) & uint64(N-1))
		blockXOR(y, v[k*R:], R)
		blockMix(&tmp, y, x, r)
	}
	j = 0
	for _, w := range x[:R] {
		binary.LittleEndian.PutUint32(b[j:], w)
		j += 4
	}
}

func blockXOR(dst, src []uint32, n int) {
	for i, w := range src[:n] {
		dst[i] ^= w
	}
}

func integer(b []uint32, r int) uint64 {
	j := (2*r - 1) * 16
	return uint64(b[j]) | uint64(b[j+1])<<32
}

func blockMix(tmp *[16]uint32, in, out []uint32, r int) {
	copy(tmp[:], in[(2*r-1)*16:])
	for i := 0; i < 2*r; i += 2 {
		salsaXOR(tmp, in[i*16:], out[i*8:])
		salsaXOR(tmp, in[i*16+16:], out[i*8+r*16:])
	}
}

// salsaXOR applies Salsa20/8 to tmp XOR in, storing the result in both
// tmp and out.
func salsaXOR(tmp *[16]uint32, in, out []uint32) {
	var x [16]uint32
	for i := range x {
		tmp[i] ^= in[i]
		x[i] = tmp[i]
	}
	for i := 0; i < 8; i += 2 {
		x[4] ^= bits.RotateLeft32(x[0]+x[12], 7)
		x[8] ^= bits.RotateLeft32(x[4]+x[0], 9)
		x[12] ^= bits.RotateLeft32(x[8]+x[4], 13)
		x[0] ^= bits.RotateLeft32(x[12]+x[8], 18)
		x[9] ^= bits.RotateLeft32(x[5]+x[1], 7)
		x[13] ^= bits.RotateLeft32(x[9]+x[5], 9)
		x[1] ^= bits.RotateLeft32(x[13]+x[9], 13)
		x[5] ^= bits.RotateLeft32(x[1]+x[13], 18)
		x[14] ^= bits.RotateLeft32(x[10]+x[6], 7)
		x[2] ^= bits.RotateLeft32(x[14]+x[10], 9)
		x[6] ^= bits.RotateLeft32(x[2]+x[14], 13)
		x[10] ^= bits.RotateLeft32(x[6]+x[2], 18)
		x[3] ^= bits.RotateLeft32(x[15]+x[11], 7)
		x[7] ^= bits.RotateLeft32(x[3]+x[15], 9)
		x[11] ^= bits.RotateLeft32(x[7]+x[3], 13)
		x[15] ^= bits.RotateLeft32(x[11]+x[7], 18)
		x[1] ^= bits.RotateLeft32(x[0]+x[3], 7)
		x[2] ^= bits.RotateLeft32(x[1]+x[0], 9)
		x[3] ^= bits.RotateLeft32(x[2]+x[1], 13)
		x[0] ^= bits.RotateLeft32(x[3]+x[2], 18)
		x[6] ^= bits.RotateLeft32(x[5]+x[4], 7)
		x[7] ^= bits.RotateLeft32(x[6]+x[5], 9)
		x[4] ^= bits.RotateLeft32(x[7]+x[6], 13)
		x[5] ^= bits.RotateLeft32(x[4]+x[7], 18)
		x[11] ^= bits.RotateLeft32(x[10]+x[9], 7)
		x[8] ^= bits.RotateLeft32(x[11]+x[10], 9)
		x[9] ^= bits.RotateLeft32(x[8]+x[11], 13)
		x[10] ^= bits.RotateLeft32(x[9]+x[8], 18)
		x[12] ^= bits.RotateLeft32(x[15]+x[14], 7)
		x[13] ^= bits.RotateLeft32(x[12]+x[15], 9)
		x[14] ^= bits.RotateLeft32(x[13]+x[12], 13)
		x[15] ^= bits.RotateLeft32(x[14]+x[13], 18)
	}
	for i := range x {
		tmp[i] += x[i]
		out[i] = tmp[i]
	}
}
