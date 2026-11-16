package mls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"

	"github.com/famomatic/puredave/internal/tls"
)

// HPKE (RFC 9180) base mode for DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and
// AES-128-GCM, the only HPKE configuration used by MLS ciphersuite 2.

const (
	hpkeKEMID  = 0x0010
	hpkeKDFID  = 0x0001
	hpkeAEADID = 0x0001

	hpkeNsecret = 32
	hpkeNk      = 16
	hpkeNn      = 12
	hpkeNh      = 32
	hpkeNenc    = 65
)

var (
	kemSuiteID  = []byte{'K', 'E', 'M', hpkeKEMID >> 8, hpkeKEMID & 0xff}
	hpkeSuiteID = []byte{'H', 'P', 'K', 'E',
		hpkeKEMID >> 8, hpkeKEMID & 0xff,
		hpkeKDFID >> 8, hpkeKDFID & 0xff,
		hpkeAEADID >> 8, hpkeAEADID & 0xff}
	hpkeVersionLabel = []byte("HPKE-v1")
)

// ErrHPKEOpen is returned when an HPKE ciphertext fails to authenticate.
var ErrHPKEOpen = errors.New("mls: HPKE decryption failure")

func labeledExtract(suiteID, salt []byte, label string, ikm []byte) []byte {
	in := make([]byte, 0, len(hpkeVersionLabel)+len(suiteID)+len(label)+len(ikm))
	in = append(in, hpkeVersionLabel...)
	in = append(in, suiteID...)
	in = append(in, label...)
	in = append(in, ikm...)
	return hkdfExtract(salt, in)
}

func labeledExpand(suiteID, prk []byte, label string, info []byte, length int) []byte {
	in := make([]byte, 0, 2+len(hpkeVersionLabel)+len(suiteID)+len(label)+len(info))
	in = append(in, byte(length>>8), byte(length))
	in = append(in, hpkeVersionLabel...)
	in = append(in, suiteID...)
	in = append(in, label...)
	in = append(in, info...)
	return hkdfExpand(prk, in, length)
}

func kemExtractAndExpand(dh, kemContext []byte) []byte {
	prk := labeledExtract(kemSuiteID, nil, "eae_prk", dh)
	return labeledExpand(kemSuiteID, prk, "shared_secret", kemContext, hpkeNsecret)
}

// hpkeDeriveKeyPair implements DeriveKeyPair for DHKEM(P-256, HKDF-SHA256)
// (RFC 9180 Section 7.1.3).
func hpkeDeriveKeyPair(ikm []byte) (*ecdh.PrivateKey, error) {
	prk := labeledExtract(kemSuiteID, nil, "dkp_prk", ikm)
	for counter := 0; counter < 256; counter++ {
		candidate := labeledExpand(kemSuiteID, prk, "candidate", []byte{byte(counter)}, 32)
		candidate[0] &= 0xff
		if sk, err := ecdh.P256().NewPrivateKey(candidate); err == nil {
			return sk, nil
		}
	}
	return nil, errors.New("mls: HPKE DeriveKeyPair failed")
}

type hpkeContext struct {
	key            []byte
	baseNonce      []byte
	exporterSecret []byte
}

func hpkeKeySchedule(sharedSecret, info []byte) hpkeContext {
	pskIDHash := labeledExtract(hpkeSuiteID, nil, "psk_id_hash", nil)
	infoHash := labeledExtract(hpkeSuiteID, nil, "info_hash", info)
	ctx := make([]byte, 0, 1+len(pskIDHash)+len(infoHash))
	ctx = append(ctx, 0x00) // mode_base
	ctx = append(ctx, pskIDHash...)
	ctx = append(ctx, infoHash...)
	secret := labeledExtract(hpkeSuiteID, sharedSecret, "secret", nil)
	return hpkeContext{
		key:            labeledExpand(hpkeSuiteID, secret, "key", ctx, hpkeNk),
		baseNonce:      labeledExpand(hpkeSuiteID, secret, "base_nonce", ctx, hpkeNn),
		exporterSecret: labeledExpand(hpkeSuiteID, secret, "exp", ctx, hpkeNh),
	}
}

func (c hpkeContext) aead() cipher.AEAD {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return gcm
}

func (c hpkeContext) export(exporterContext []byte, length int) []byte {
	return labeledExpand(hpkeSuiteID, c.exporterSecret, "sec", exporterContext, length)
}

func hpkeSetupBaseS(rnd io.Reader, pkR *ecdh.PublicKey, info []byte) (enc []byte, ctx hpkeContext, err error) {
	skE, err := ecdh.P256().GenerateKey(rnd)
	if err != nil {
		return nil, hpkeContext{}, err
	}
	return hpkeSetupBaseSWithKey(skE, pkR, info)
}

func hpkeSetupBaseSWithKey(skE *ecdh.PrivateKey, pkR *ecdh.PublicKey, info []byte) ([]byte, hpkeContext, error) {
	dh, err := skE.ECDH(pkR)
	if err != nil {
		return nil, hpkeContext{}, err
	}
	enc := skE.PublicKey().Bytes()
	kemContext := append(append([]byte{}, enc...), pkR.Bytes()...)
	shared := kemExtractAndExpand(dh, kemContext)
	return enc, hpkeKeySchedule(shared, info), nil
}

func hpkeSetupBaseR(enc []byte, skR *ecdh.PrivateKey, info []byte) (hpkeContext, error) {
	pkE, err := ecdh.P256().NewPublicKey(enc)
	if err != nil {
		return hpkeContext{}, err
	}
	dh, err := skR.ECDH(pkE)
	if err != nil {
		return hpkeContext{}, err
	}
	kemContext := append(append([]byte{}, enc...), skR.PublicKey().Bytes()...)
	shared := kemExtractAndExpand(dh, kemContext)
	return hpkeKeySchedule(shared, info), nil
}

// HPKECiphertext is the MLS HPKECiphertext struct.
type HPKECiphertext struct {
	KEMOutput  []byte
	Ciphertext []byte
}

func (c *HPKECiphertext) marshal(w *tls.Writer) {
	w.Opaque(c.KEMOutput)
	w.Opaque(c.Ciphertext)
}

func (c *HPKECiphertext) unmarshal(r *tls.Reader) {
	c.KEMOutput = r.Opaque()
	c.Ciphertext = r.Opaque()
}

// HPKEPrivateKey is an HPKE (DHKEM P-256) private key.
type HPKEPrivateKey struct {
	key *ecdh.PrivateKey
}

// GenerateHPKEPrivateKey creates a fresh HPKE private key.
func GenerateHPKEPrivateKey() (*HPKEPrivateKey, error) {
	sk, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &HPKEPrivateKey{key: sk}, nil
}

// DeriveHPKEPrivateKey derives an HPKE key pair from secret (DeriveKeyPair).
func DeriveHPKEPrivateKey(secret []byte) (*HPKEPrivateKey, error) {
	sk, err := hpkeDeriveKeyPair(secret)
	if err != nil {
		return nil, err
	}
	return &HPKEPrivateKey{key: sk}, nil
}

// ParseHPKEPrivateKey parses a serialized (32-byte scalar) private key.
func ParseHPKEPrivateKey(b []byte) (*HPKEPrivateKey, error) {
	sk, err := ecdh.P256().NewPrivateKey(b)
	if err != nil {
		return nil, err
	}
	return &HPKEPrivateKey{key: sk}, nil
}

// Bytes returns the serialized private key.
func (k *HPKEPrivateKey) Bytes() []byte { return k.key.Bytes() }

// PublicKey returns the serialized (uncompressed) public key.
func (k *HPKEPrivateKey) PublicKey() HPKEPublicKey { return k.key.PublicKey().Bytes() }

// HPKEPublicKey is a serialized HPKE public key.
type HPKEPublicKey []byte

func encryptContext(label string, context []byte) []byte {
	w := tls.NewWriter()
	w.Opaque([]byte("MLS 1.0 " + label))
	w.Opaque(context)
	return w.Bytes()
}

// EncryptWithLabel implements MLS EncryptWithLabel (RFC 9420 Section 5.1.3).
func EncryptWithLabel(pub HPKEPublicKey, label string, context, plaintext []byte) (*HPKECiphertext, error) {
	pkR, err := ecdh.P256().NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	enc, ctx, err := hpkeSetupBaseS(rand.Reader, pkR, encryptContext(label, context))
	if err != nil {
		return nil, err
	}
	ct := ctx.aead().Seal(nil, ctx.baseNonce, plaintext, nil)
	return &HPKECiphertext{KEMOutput: enc, Ciphertext: ct}, nil
}

// DecryptWithLabel implements MLS DecryptWithLabel (RFC 9420 Section 5.1.3).
func (k *HPKEPrivateKey) DecryptWithLabel(label string, context []byte, ct *HPKECiphertext) ([]byte, error) {
	ctx, err := hpkeSetupBaseR(ct.KEMOutput, k.key, encryptContext(label, context))
	if err != nil {
		return nil, err
	}
	pt, err := ctx.aead().Open(nil, ctx.baseNonce, ct.Ciphertext, nil)
	if err != nil {
		return nil, ErrHPKEOpen
	}
	return pt, nil
}
