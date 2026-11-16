// Package tls implements the TLS presentation language encoding used by MLS
// (RFC 8446 Section 3 with the RFC 9420 Section 2.1.2 variable-size vector
// length headers).
package tls

import (
	"errors"
	"fmt"
)

// ErrShortBuffer is returned when a value runs past the end of its input.
var ErrShortBuffer = errors.New("tls: unexpected end of input")

// ErrNonMinimalVarint is returned for a vector length header that is not
// encoded in the minimum number of bytes.
var ErrNonMinimalVarint = errors.New("tls: non-minimal varint length")

// ErrInvalidVarint is returned for a vector length header with the reserved
// 0b11 prefix.
var ErrInvalidVarint = errors.New("tls: invalid varint prefix")

// ErrTrailingData is returned by Unmarshal-style helpers when input remains.
var ErrTrailingData = errors.New("tls: trailing data")

// MaxVarint is the largest value a variable-size length header can carry.
const MaxVarint = 1<<30 - 1

// Writer accumulates a TLS-encoded byte string.
type Writer struct {
	buf []byte
	err error
}

// NewWriter returns an empty Writer.
func NewWriter() *Writer { return &Writer{} }

// Bytes returns the encoded bytes.
func (w *Writer) Bytes() []byte { return w.buf }

// Err returns the first encoding error, if any.
func (w *Writer) Err() error { return w.err }

// Finish returns the encoded bytes or the first encoding error.
func (w *Writer) Finish() ([]byte, error) {
	if w.err != nil {
		return nil, w.err
	}
	return w.buf, nil
}

// SetErr records an encoding error.
func (w *Writer) SetErr(err error) {
	if w.err == nil {
		w.err = err
	}
}

// U8 writes a uint8.
func (w *Writer) U8(v uint8) { w.buf = append(w.buf, v) }

// Bool writes a uint8-encoded boolean.
func (w *Writer) Bool(v bool) {
	if v {
		w.U8(1)
	} else {
		w.U8(0)
	}
}

// U16 writes a big-endian uint16.
func (w *Writer) U16(v uint16) { w.buf = append(w.buf, byte(v>>8), byte(v)) }

// U32 writes a big-endian uint32.
func (w *Writer) U32(v uint32) {
	w.buf = append(w.buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// U64 writes a big-endian uint64.
func (w *Writer) U64(v uint64) {
	w.buf = append(w.buf,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// Raw appends bytes without a length header.
func (w *Writer) Raw(b []byte) { w.buf = append(w.buf, b...) }

// Varint writes an MLS variable-size length header.
func (w *Writer) Varint(n int) {
	switch {
	case n < 0 || n > MaxVarint:
		w.SetErr(fmt.Errorf("tls: length %d does not fit a varint", n))
	case n < 1<<6:
		w.U8(uint8(n))
	case n < 1<<14:
		w.U16(uint16(n) | 0x4000)
	default:
		w.U32(uint32(n) | 0x80000000)
	}
}

// Opaque writes a variable-length opaque vector (opaque data<V>).
func (w *Writer) Opaque(b []byte) {
	w.Varint(len(b))
	w.Raw(b)
}

// Vector writes a variable-length vector whose body is produced by fn.
func (w *Writer) Vector(fn func(w *Writer)) {
	inner := &Writer{}
	fn(inner)
	if inner.err != nil {
		w.SetErr(inner.err)
		return
	}
	w.Opaque(inner.buf)
}

// Optional writes an MLS optional<T> presence octet followed by fn's output
// when present is true.
func (w *Writer) Optional(present bool, fn func(w *Writer)) {
	w.Bool(present)
	if present {
		fn(w)
	}
}

// Reader decodes a TLS-encoded byte string.
type Reader struct {
	buf []byte
	err error
}

// NewReader returns a Reader over b.
func NewReader(b []byte) *Reader { return &Reader{buf: b} }

// Err returns the first decoding error, if any.
func (r *Reader) Err() error { return r.err }

// Len returns the number of unread bytes.
func (r *Reader) Len() int { return len(r.buf) }

// Empty reports whether all input has been consumed.
func (r *Reader) Empty() bool { return len(r.buf) == 0 }

// Rest returns the unread bytes without consuming them.
func (r *Reader) Rest() []byte { return r.buf }

// SetErr records a decoding error.
func (r *Reader) SetErr(err error) {
	if r.err == nil {
		r.err = err
	}
	r.buf = nil
}

// Done returns an error if decoding failed or input remains.
func (r *Reader) Done() error {
	if r.err != nil {
		return r.err
	}
	if len(r.buf) != 0 {
		return ErrTrailingData
	}
	return nil
}

func (r *Reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.buf) {
		r.SetErr(ErrShortBuffer)
		return nil
	}
	out := r.buf[:n:n]
	r.buf = r.buf[n:]
	return out
}

// U8 reads a uint8.
func (r *Reader) U8() uint8 {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}

// Bool reads a uint8-encoded boolean; values other than 0 and 1 are errors.
func (r *Reader) Bool() bool {
	v := r.U8()
	switch v {
	case 0:
		return false
	case 1:
		return true
	default:
		r.SetErr(fmt.Errorf("tls: invalid boolean %d", v))
		return false
	}
}

// U16 reads a big-endian uint16.
func (r *Reader) U16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return uint16(b[0])<<8 | uint16(b[1])
}

// U32 reads a big-endian uint32.
func (r *Reader) U32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// U64 reads a big-endian uint64.
func (r *Reader) U64() uint64 {
	b := r.take(8)
	if b == nil {
		return 0
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

// Raw reads n bytes. The returned slice aliases the input.
func (r *Reader) Raw(n int) []byte { return r.take(n) }

// Varint reads an MLS variable-size length header.
func (r *Reader) Varint() int {
	if r.err != nil {
		return 0
	}
	if len(r.buf) == 0 {
		r.SetErr(ErrShortBuffer)
		return 0
	}
	prefix := r.buf[0] >> 6
	switch prefix {
	case 0:
		return int(r.U8() & 0x3f)
	case 1:
		v := int(r.U16() & 0x3fff)
		if r.err == nil && v < 1<<6 {
			r.SetErr(ErrNonMinimalVarint)
		}
		return v
	case 2:
		v := int(r.U32() & 0x3fffffff)
		if r.err == nil && v < 1<<14 {
			r.SetErr(ErrNonMinimalVarint)
		}
		return v
	default:
		r.SetErr(ErrInvalidVarint)
		return 0
	}
}

// Opaque reads a variable-length opaque vector. The result is a copy.
func (r *Reader) Opaque() []byte {
	n := r.Varint()
	b := r.take(n)
	if b == nil {
		return nil
	}
	return append([]byte{}, b...)
}

// Vector reads a variable-length vector and calls fn with a Reader over its
// body. fn must consume the whole body.
func (r *Reader) Vector(fn func(r *Reader)) {
	n := r.Varint()
	b := r.take(n)
	if r.err != nil {
		return
	}
	inner := &Reader{buf: b}
	fn(inner)
	if err := inner.Done(); err != nil {
		r.SetErr(err)
	}
}

// VectorEach reads a variable-length vector and calls fn until the body is
// exhausted.
func (r *Reader) VectorEach(fn func(r *Reader)) {
	r.Vector(func(inner *Reader) {
		for inner.err == nil && len(inner.buf) > 0 {
			fn(inner)
		}
	})
}

// Optional reads an MLS optional<T> presence octet and calls fn if present.
func (r *Reader) Optional(fn func(r *Reader)) bool {
	present := r.Bool()
	if present && r.err == nil {
		fn(r)
	}
	return present && r.err == nil
}
