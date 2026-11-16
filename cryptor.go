package dave

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

// cryptor performs AES-128-GCM with 64-bit truncated authentication tags.
type cryptor struct {
	block cipher.Block
	gcm   cipher.AEAD
}

var errInvalidKey = errors.New("dave: invalid AES-128 key")

func newCryptor(key []byte) (*cryptor, error) {
	if len(key) != aesGCM128KeyBytes {
		return nil, errInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &cryptor{block: block, gcm: gcm}, nil
}

// encrypt writes the ciphertext of plaintext into ciphertext (same length)
// and the truncated tag into tag.
func (c *cryptor) encrypt(ciphertext, plaintext, nonce, aad, tag []byte) bool {
	if len(ciphertext) < len(plaintext) || len(tag) < aesGCM128TruncatedTagBytes || len(nonce) != aesGCM128NonceBytes {
		return false
	}
	sealed := c.gcm.Seal(nil, nonce, plaintext, aad)
	copy(ciphertext, sealed[:len(plaintext)])
	copy(tag, sealed[len(plaintext):len(plaintext)+aesGCM128TruncatedTagBytes])
	return true
}

// decrypt authenticates ciphertext against the truncated tag and writes the
// plaintext. Go's AEAD API does not accept 8-byte tags, so the keystream is
// applied with CTR mode (GCM's counter starts at 2 for 96-bit nonces) and the
// full tag is recomputed by re-sealing the recovered plaintext. Plaintext is
// only written on success.
func (c *cryptor) decrypt(plaintext, ciphertext, tag, nonce, aad []byte) bool {
	if len(plaintext) < len(ciphertext) || len(tag) != aesGCM128TruncatedTagBytes || len(nonce) != aesGCM128NonceBytes {
		return false
	}
	var iv [aes.BlockSize]byte
	copy(iv[:], nonce)
	iv[aes.BlockSize-1] = 2
	candidate := make([]byte, len(ciphertext))
	cipher.NewCTR(c.block, iv[:]).XORKeyStream(candidate, ciphertext)
	sealed := c.gcm.Seal(nil, nonce, candidate, aad)
	expected := sealed[len(candidate) : len(candidate)+aesGCM128TruncatedTagBytes]
	if subtle.ConstantTimeCompare(expected, tag) != 1 {
		clear(candidate)
		return false
	}
	copy(plaintext, candidate)
	return true
}
