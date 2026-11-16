package dave

import (
	"bytes"

	"github.com/famomatic/puredave/mls"
)

// KeyRatchet yields per-generation media keys for one sender in one epoch.
type KeyRatchet interface {
	// GetKey returns the key for a generation, or nil if it was erased.
	GetKey(generation KeyGeneration) []byte
	// DeleteKey erases a generation.
	DeleteKey(generation KeyGeneration)
	// DomainIdentity identifies the key domain (sender and epoch). Ratchets
	// with equal identities produce identical keys.
	DomainIdentity() []byte
}

// MLSKeyRatchet is the sender key ratchet derived from an MLS exporter
// secret, using the MLS hash ratchet construction.
type MLSKeyRatchet struct {
	ratchet        *mls.HashRatchet
	domainIdentity []byte
}

// NewMLSKeyRatchet returns a ratchet seeded with baseSecret.
func NewMLSKeyRatchet(suite mls.CipherSuite, baseSecret []byte) *MLSKeyRatchet {
	return &MLSKeyRatchet{
		ratchet:        mls.NewHashRatchet(suite, baseSecret),
		domainIdentity: bytes.Clone(baseSecret),
	}
}

// GetKey implements KeyRatchet.
func (r *MLSKeyRatchet) GetKey(generation KeyGeneration) []byte {
	kn, err := r.ratchet.Get(generation)
	if err != nil {
		logf(LogError, "failed to retrieve key for generation %d: %v", generation, err)
		return nil
	}
	return kn.Key
}

// DeleteKey implements KeyRatchet.
func (r *MLSKeyRatchet) DeleteKey(generation KeyGeneration) { r.ratchet.Erase(generation) }

// DomainIdentity implements KeyRatchet.
func (r *MLSKeyRatchet) DomainIdentity() []byte { return bytes.Clone(r.domainIdentity) }
