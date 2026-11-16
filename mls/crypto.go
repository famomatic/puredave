package mls

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"

	"github.com/famomatic/puredave/internal/tls"
)

// CipherSuite identifies an MLS ciphersuite.
type CipherSuite uint16

// Supported ciphersuites.
const (
	// CipherSuiteP256 is MLS_128_DHKEMP256_AES128GCM_SHA256_P256, the
	// ciphersuite used by DAVE protocol version 1.
	CipherSuiteP256 CipherSuite = 0x0002
)

// ProtocolVersionMLS10 is the mls10 protocol version.
const ProtocolVersionMLS10 uint16 = 1

// ErrUnsupportedCipherSuite is returned for any ciphersuite other than P-256.
var ErrUnsupportedCipherSuite = errors.New("mls: unsupported ciphersuite")

// Supported reports whether the ciphersuite is implemented.
func (cs CipherSuite) Supported() bool { return cs == CipherSuiteP256 }

// SecretSize is Nh, the KDF output size.
func (cs CipherSuite) SecretSize() int { return sha256.Size }

// KeySize is the AEAD key size.
func (cs CipherSuite) KeySize() int { return hpkeNk }

// NonceSize is the AEAD nonce size.
func (cs CipherSuite) NonceSize() int { return hpkeNn }

// Zero returns Nh zero bytes.
func (cs CipherSuite) Zero() []byte { return make([]byte, cs.SecretSize()) }

func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	out, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		panic(err)
	}
	return out
}

func hkdfExpand(prk, info []byte, length int) []byte {
	out, err := hkdf.Expand(sha256.New, prk, string(info), length)
	if err != nil {
		panic(err)
	}
	return out
}

// Extract is KDF.Extract(salt, ikm).
func (cs CipherSuite) Extract(salt, ikm []byte) []byte { return hkdfExtract(salt, ikm) }

// Expand is KDF.Expand(prk, info, length).
func (cs CipherSuite) Expand(prk, info []byte, length int) []byte {
	return hkdfExpand(prk, info, length)
}

// Hash is the ciphersuite hash function.
func (cs CipherSuite) Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// MAC is the ciphersuite MAC (HMAC-SHA256).
func (cs CipherSuite) MAC(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// ExpandWithLabel implements RFC 9420 ExpandWithLabel.
func (cs CipherSuite) ExpandWithLabel(secret []byte, label string, context []byte, length int) []byte {
	w := tls.NewWriter()
	w.U16(uint16(length))
	w.Opaque([]byte("MLS 1.0 " + label))
	w.Opaque(context)
	return hkdfExpand(secret, w.Bytes(), length)
}

// DeriveSecret implements RFC 9420 DeriveSecret.
func (cs CipherSuite) DeriveSecret(secret []byte, label string) []byte {
	return cs.ExpandWithLabel(secret, label, nil, cs.SecretSize())
}

// DeriveTreeSecret implements RFC 9420 DeriveTreeSecret.
func (cs CipherSuite) DeriveTreeSecret(secret []byte, label string, generation uint32, length int) []byte {
	ctx := []byte{byte(generation >> 24), byte(generation >> 16), byte(generation >> 8), byte(generation)}
	return cs.ExpandWithLabel(secret, label, ctx, length)
}

// RefHash implements RFC 9420 RefHash.
func (cs CipherSuite) RefHash(label string, value []byte) []byte {
	w := tls.NewWriter()
	w.Opaque([]byte(label))
	w.Opaque(value)
	return cs.Hash(w.Bytes())
}

// SignaturePublicKey is a serialized (uncompressed SEC1) ECDSA P-256 key.
type SignaturePublicKey []byte

// SignaturePrivateKey is an ECDSA P-256 signing key.
type SignaturePrivateKey struct {
	priv *ecdsa.PrivateKey
	pub  SignaturePublicKey
}

// GenerateSignaturePrivateKey creates a fresh signing key.
func GenerateSignaturePrivateKey() (*SignaturePrivateKey, error) {
	sk, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ParseSignaturePrivateKey(sk.Bytes())
}

// ParseSignaturePrivateKey parses a 32-byte big-endian private scalar.
func ParseSignaturePrivateKey(scalar []byte) (*SignaturePrivateKey, error) {
	sk, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		return nil, err
	}
	pubBytes := sk.PublicKey().Bytes()
	pub, err := ecdsaPublicKey(pubBytes)
	if err != nil {
		return nil, err
	}
	return &SignaturePrivateKey{
		priv: &ecdsa.PrivateKey{PublicKey: *pub, D: new(big.Int).SetBytes(scalar)},
		pub:  pubBytes,
	}, nil
}

// Bytes returns the 32-byte private scalar.
func (k *SignaturePrivateKey) Bytes() []byte {
	out := make([]byte, 32)
	return k.priv.D.FillBytes(out)
}

// PublicKey returns the serialized public key.
func (k *SignaturePrivateKey) PublicKey() SignaturePublicKey {
	return append(SignaturePublicKey{}, k.pub...)
}

// Sign signs a raw message with ECDSA-SHA256, returning a DER signature.
func (k *SignaturePrivateKey) Sign(message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)
	return ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
}

func ecdsaPublicKey(b []byte) (*ecdsa.PublicKey, error) {
	// crypto/ecdh rejects invalid and off-curve points.
	if _, err := ecdh.P256().NewPublicKey(b); err != nil {
		return nil, err
	}
	if len(b) != 65 || b[0] != 4 {
		return nil, fmt.Errorf("mls: signature key must be an uncompressed point")
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(b[1:33]),
		Y:     new(big.Int).SetBytes(b[33:65]),
	}, nil
}

// Verify verifies a DER ECDSA-SHA256 signature over a raw message.
func (pub SignaturePublicKey) Verify(message, signature []byte) bool {
	pk, err := ecdsaPublicKey(pub)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(message)
	return ecdsa.VerifyASN1(pk, digest[:], signature)
}

func signContent(label string, content []byte) []byte {
	w := tls.NewWriter()
	w.Opaque([]byte("MLS 1.0 " + label))
	w.Opaque(content)
	return w.Bytes()
}

// SignWithLabel implements RFC 9420 SignWithLabel.
func (k *SignaturePrivateKey) SignWithLabel(label string, content []byte) ([]byte, error) {
	return k.Sign(signContent(label, content))
}

// VerifyWithLabel implements RFC 9420 VerifyWithLabel.
func (pub SignaturePublicKey) VerifyWithLabel(label string, content, signature []byte) bool {
	return pub.Verify(signContent(label, content), signature)
}

func bytesEqual(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
