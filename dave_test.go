package dave

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"
)

// staticKeyRatchet mirrors libdave's test StaticKeyRatchet: the key is the
// little-endian user ID repeated twice.
type staticKeyRatchet struct{ id uint64 }

func (r staticKeyRatchet) GetKey(KeyGeneration) []byte {
	k := make([]byte, 16)
	binary.LittleEndian.PutUint64(k, r.id)
	binary.LittleEndian.PutUint64(k[8:], r.id)
	return k
}
func (r staticKeyRatchet) DeleteKey(KeyGeneration) {}
func (r staticKeyRatchet) DomainIdentity() []byte {
	return binary.LittleEndian.AppendUint64(nil, r.id)
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func encryptFrame(t *testing.T, e *Encryptor, mt MediaType, frame []byte) []byte {
	t.Helper()
	out := make([]byte, e.MaxCiphertextByteSize(mt, len(frame)))
	n, r := e.Encrypt(mt, 1, frame, out)
	if r != EncryptSuccess {
		t.Fatalf("encrypt: %v", r)
	}
	return out[:n]
}

func TestLeb128(t *testing.T) {
	for _, v := range []uint64{0, 1, 127, 128, 300, 1 << 32, ^uint64(0)} {
		b := appendLeb128(nil, v)
		if len(b) != leb128Size(v) {
			t.Fatalf("size(%d) = %d, encoded %d", v, leb128Size(v), len(b))
		}
		got, n, ok := readLeb128(b)
		if !ok || n != len(b) || got != v {
			t.Fatalf("round trip %d = %d (%d, %v)", v, got, n, ok)
		}
	}
	if _, _, ok := readLeb128([]byte{0x80, 0x80}); ok {
		t.Fatal("unterminated value accepted")
	}
}

func TestCryptorTruncatedTag(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	c, err := newCryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := expandTruncatedNonce(42)
	pt := []byte("hello opus frame")
	aad := []byte{1, 2, 3}
	ct := make([]byte, len(pt))
	tag := make([]byte, 8)
	if !c.encrypt(ct, pt, nonce[:], aad, tag) {
		t.Fatal("encrypt failed")
	}
	out := make([]byte, len(ct))
	if !c.decrypt(out, ct, tag, nonce[:], aad) || !bytes.Equal(out, pt) {
		t.Fatal("decrypt failed")
	}
	tag[0] ^= 1
	if c.decrypt(out, ct, tag, nonce[:], aad) {
		t.Fatal("tampered tag accepted")
	}
	tag[0] ^= 1
	if c.decrypt(out, ct, tag, nonce[:], []byte{9}) {
		t.Fatal("wrong additional data accepted")
	}
}

func TestEncryptDecryptAllCodecs(t *testing.T) {
	frames := map[Codec][]byte{
		CodecOpus: bytes.Repeat([]byte{0xab}, 90),
		CodecVP8:  append([]byte{0x10, 1, 2, 3, 4, 5, 6, 7, 8, 9}, bytes.Repeat([]byte{7}, 50)...),
		CodecVP9:  bytes.Repeat([]byte{3}, 64),
		CodecH264: {0, 0, 0, 1, 0x67, 1, 2, 3, 0, 0, 1, 0x65, 0x88, 0x84, 0x21, 0xa0, 5, 6, 7, 8},
		CodecH265: {0, 0, 0, 1, 0x40, 0x01, 9, 9, 0, 0, 1, 0x26, 0x01, 0xaf, 1, 2, 3},
		CodecAV1:  {0x12, 0x00, 0x0a, 0x02, 0xaa, 0xbb, 0x32, 0x03, 1, 2, 3},
	}
	for codec, frame := range frames {
		mt := MediaTypeVideo
		if codec == CodecOpus {
			mt = MediaTypeAudio
		}
		e := NewEncryptor()
		e.AssignSsrcToCodec(1, codec)
		e.SetKeyRatchet(staticKeyRatchet{7})
		d := NewDecryptor()
		d.TransitionToKeyRatchet(staticKeyRatchet{7}, DefaultTransitionDuration)
		for i := 0; i < 5; i++ {
			ct := encryptFrame(t, e, mt, frame)
			if codec != CodecAV1 && bytes.Equal(ct[:len(frame)], frame) && codec != CodecVP8 {
				t.Fatalf("%v: frame left unencrypted", codec)
			}
			out := make([]byte, len(ct))
			n, r := d.Decrypt(mt, ct, out)
			if r != DecryptSuccess {
				t.Fatalf("%v: decrypt: %v", codec, r)
			}
			want := frame
			if codec == CodecH264 || codec == CodecH265 {
				// three byte start codes become four byte start codes
				want = bytes.ReplaceAll(frame, []byte{0, 0, 1}, []byte{0, 0, 0, 1})
				want = bytes.ReplaceAll(want, []byte{0, 0, 0, 0, 1}, []byte{0, 0, 0, 1})
			}
			if codec == CodecAV1 {
				// temporal delimiter dropped, last OBU size removed
				want = []byte{0x0a, 0x02, 0xaa, 0xbb, 0x30, 1, 2, 3}
			}
			if !bytes.Equal(out[:n], want) {
				t.Fatalf("%v: got %x want %x", codec, out[:n], want)
			}
		}
	}
}

func TestDecryptorRejectsReplay(t *testing.T) {
	e := NewEncryptor()
	e.AssignSsrcToCodec(1, CodecOpus)
	e.SetKeyRatchet(staticKeyRatchet{1})
	d := NewDecryptor()
	d.TransitionToKeyRatchet(staticKeyRatchet{1}, DefaultTransitionDuration)
	ct := encryptFrame(t, e, MediaTypeAudio, []byte("frame one"))
	out := make([]byte, len(ct))
	if _, r := d.Decrypt(MediaTypeAudio, ct, out); r != DecryptSuccess {
		t.Fatal(r)
	}
	if _, r := d.Decrypt(MediaTypeAudio, ct, out); r != DecryptInvalidNonce {
		t.Fatalf("replay: %v", r)
	}
	// Out-of-order frames within the missing nonce window are accepted once.
	ct2 := encryptFrame(t, e, MediaTypeAudio, []byte("frame two"))
	ct3 := encryptFrame(t, e, MediaTypeAudio, []byte("frame three"))
	if _, r := d.Decrypt(MediaTypeAudio, ct3, out); r != DecryptSuccess {
		t.Fatal(r)
	}
	if _, r := d.Decrypt(MediaTypeAudio, ct2, out); r != DecryptSuccess {
		t.Fatal(r)
	}
	if _, r := d.Decrypt(MediaTypeAudio, ct2, out); r != DecryptInvalidNonce {
		t.Fatalf("late replay: %v", r)
	}
}

func TestPassthroughAndSilence(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	d := NewDecryptorWithClock(clock)
	out := make([]byte, 16)
	frame := []byte{1, 2, 3, 4}
	if _, r := d.Decrypt(MediaTypeAudio, frame, out); r != DecryptFailure {
		t.Fatalf("unencrypted frame without passthrough: %v", r)
	}
	if n, r := d.Decrypt(MediaTypeAudio, OpusSilencePacket, out); r != DecryptSuccess || !bytes.Equal(out[:n], OpusSilencePacket) {
		t.Fatal("silence packet not passed through")
	}
	d.TransitionToPassthroughMode(true, DefaultTransitionDuration)
	if n, r := d.Decrypt(MediaTypeAudio, frame, out); r != DecryptSuccess || !bytes.Equal(out[:n], frame) {
		t.Fatal("passthrough failed")
	}
	d.TransitionToPassthroughMode(false, DefaultTransitionDuration)
	clock.advance(5 * time.Second)
	if _, r := d.Decrypt(MediaTypeAudio, frame, out); r != DecryptSuccess {
		t.Fatal("passthrough should last for the transition period")
	}
	clock.advance(6 * time.Second)
	if _, r := d.Decrypt(MediaTypeAudio, frame, out); r != DecryptFailure {
		t.Fatal("passthrough should expire")
	}

	e := NewEncryptor()
	e.SetPassthroughMode(true)
	if e.ProtocolVersion() != DisabledVersion {
		t.Fatal("passthrough encryptor should report version 0")
	}
	if n, r := e.Encrypt(MediaTypeAudio, 1, frame, out); r != EncryptSuccess || !bytes.Equal(out[:n], frame) {
		t.Fatal("encryptor passthrough failed")
	}
	e.SetPassthroughMode(false)
	if _, r := e.Encrypt(MediaTypeAudio, 1, frame, out); r != EncryptMissingKeyRatchet {
		t.Fatalf("missing ratchet: %v", r)
	}
}

func TestDecryptorKeepsPreviousRatchetDuringTransition(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	d := NewDecryptorWithClock(clock)
	d.TransitionToKeyRatchet(staticKeyRatchet{1}, DefaultTransitionDuration)
	old := NewEncryptor()
	old.AssignSsrcToCodec(1, CodecOpus)
	old.SetKeyRatchet(staticKeyRatchet{1})
	d.TransitionToKeyRatchet(staticKeyRatchet{2}, DefaultTransitionDuration)
	out := make([]byte, 64)
	if _, r := d.Decrypt(MediaTypeAudio, encryptFrame(t, old, MediaTypeAudio, []byte("in flight")), out); r != DecryptSuccess {
		t.Fatalf("old epoch frame during transition: %v", r)
	}
	clock.advance(11 * time.Second)
	if _, r := d.Decrypt(MediaTypeAudio, encryptFrame(t, old, MediaTypeAudio, []byte("late")), out); r == DecryptSuccess {
		t.Fatal("old epoch frame accepted after transition expiry")
	}
}

func TestEncryptorNonceSequence(t *testing.T) {
	e := NewEncryptor()
	e.AssignSsrcToCodec(1, CodecOpus)
	e.SetKeyRatchet(staticKeyRatchet{1})
	p := &inboundFrameProcessor{}
	for i := uint32(1); i <= 3; i++ {
		p.parseFrame(encryptFrame(t, e, MediaTypeAudio, []byte("x")))
		if p.truncatedNonce != i {
			t.Fatalf("nonce %d, want %d", p.truncatedNonce, i)
		}
	}
	// Re-installing the same key domain keeps the sequence; a new one resets it.
	e.SetKeyRatchet(staticKeyRatchet{1})
	p.parseFrame(encryptFrame(t, e, MediaTypeAudio, []byte("x")))
	if p.truncatedNonce != 4 {
		t.Fatalf("nonce after reinstall %d", p.truncatedNonce)
	}
	e.SetKeyRatchet(staticKeyRatchet{2})
	p.parseFrame(encryptFrame(t, e, MediaTypeAudio, []byte("x")))
	if p.truncatedNonce != 1 {
		t.Fatalf("nonce after new domain %d", p.truncatedNonce)
	}
}

func TestWrappedGeneration(t *testing.T) {
	cases := []struct{ oldest, gen, want KeyGeneration }{
		{0, 0, 0}, {0, 5, 5}, {250, 255, 255}, {250, 3, 259}, {300, 50, 306}, {300, 40, 552},
	}
	for _, c := range cases {
		if got := computeWrappedGeneration(c.oldest, c.gen); got != c.want {
			t.Fatalf("wrap(%d, %d) = %d, want %d", c.oldest, c.gen, got, c.want)
		}
	}
}

func TestDisplayableCode(t *testing.T) {
	data := []byte{0, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff, 0xff}
	code, err := GenerateDisplayableCode(data, 10, 5)
	if err != nil {
		t.Fatal(err)
	}
	// 0x0000000001 % 1e5 = 1; 0xffffffffff % 1e5 = 1099511627775 % 100000 = 27775
	if code != "0000127775" {
		t.Fatalf("code = %s", code)
	}
	if _, err := GenerateDisplayableCode(data, 11, 5); err == nil {
		t.Fatal("expected length error")
	}
}
