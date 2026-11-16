package mls

import (
	"errors"
	"sync"

	"github.com/famomatic/puredave/internal/tls"
)

// KeyAndNonce is an AEAD key and nonce pair.
type KeyAndNonce struct {
	Key   []byte
	Nonce []byte
}

// ErrExpiredKey is returned by HashRatchet.Get for an erased generation.
var ErrExpiredKey = errors.New("mls: request for expired key")

// HashRatchet is the MLS secret-tree hash ratchet (RFC 9420 Section 9.1),
// mirroring mlspp's HashRatchet including its key cache.
type HashRatchet struct {
	mu             sync.Mutex
	suite          CipherSuite
	nextSecret     []byte
	nextGeneration uint32
	cache          map[uint32]KeyAndNonce
}

// NewHashRatchet creates a ratchet from a base secret.
func NewHashRatchet(suite CipherSuite, baseSecret []byte) *HashRatchet {
	return &HashRatchet{suite: suite, nextSecret: append([]byte{}, baseSecret...), cache: map[uint32]KeyAndNonce{}}
}

func (h *HashRatchet) next() {
	g := h.nextGeneration
	key := h.suite.DeriveTreeSecret(h.nextSecret, "key", g, h.suite.KeySize())
	nonce := h.suite.DeriveTreeSecret(h.nextSecret, "nonce", g, h.suite.NonceSize())
	secret := h.suite.DeriveTreeSecret(h.nextSecret, "secret", g, h.suite.SecretSize())
	h.nextGeneration++
	h.nextSecret = secret
	h.cache[g] = KeyAndNonce{Key: key, Nonce: nonce}
}

// Get returns the key and nonce for a generation, ratcheting forward as
// needed. Generations that were erased, or skipped past and never cached,
// return ErrExpiredKey.
func (h *HashRatchet) Get(generation uint32) (KeyAndNonce, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if kn, ok := h.cache[generation]; ok {
		return kn, nil
	}
	if h.nextGeneration > generation {
		return KeyAndNonce{}, ErrExpiredKey
	}
	for h.nextGeneration <= generation {
		h.next()
	}
	return h.cache[generation], nil
}

// Erase removes a generation from the cache.
func (h *HashRatchet) Erase(generation uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.cache, generation)
}

// keyScheduleEpoch holds the secrets of one epoch (mlspp KeyScheduleEpoch).
type keyScheduleEpoch struct {
	suite              CipherSuite
	joinerSecret       []byte
	epochSecret        []byte
	senderDataSecret   []byte
	encryptionSecret   []byte
	exporterSecret     []byte
	epochAuthenticator []byte
	externalSecret     []byte
	confirmationKey    []byte
	membershipKey      []byte
	resumptionPSK      []byte
	initSecret         []byte
	confirmationTag    []byte
}

func makeJoinerSecret(suite CipherSuite, context, initSecret, commitSecret []byte) []byte {
	pre := suite.Extract(initSecret, commitSecret)
	return suite.ExpandWithLabel(pre, "joiner", context, suite.SecretSize())
}

func newKeyScheduleFromJoiner(suite CipherSuite, joinerSecret, pskSecret, confirmedTranscriptHash, context []byte) *keyScheduleEpoch {
	member := suite.Extract(joinerSecret, pskSecret)
	epoch := suite.ExpandWithLabel(member, "epoch", context, suite.SecretSize())
	ks := &keyScheduleEpoch{
		suite:              suite,
		joinerSecret:       joinerSecret,
		epochSecret:        epoch,
		senderDataSecret:   suite.DeriveSecret(epoch, "sender data"),
		encryptionSecret:   suite.DeriveSecret(epoch, "encryption"),
		exporterSecret:     suite.DeriveSecret(epoch, "exporter"),
		epochAuthenticator: suite.DeriveSecret(epoch, "authentication"),
		externalSecret:     suite.DeriveSecret(epoch, "external"),
		confirmationKey:    suite.DeriveSecret(epoch, "confirm"),
		membershipKey:      suite.DeriveSecret(epoch, "membership"),
		resumptionPSK:      suite.DeriveSecret(epoch, "resumption"),
		initSecret:         suite.DeriveSecret(epoch, "init"),
	}
	ks.confirmationTag = suite.MAC(ks.confirmationKey, confirmedTranscriptHash)
	return ks
}

// newInitialKeySchedule is the epoch-0 schedule of a freshly created group.
func newInitialKeySchedule(suite CipherSuite, initSecret, context []byte) *keyScheduleEpoch {
	joiner := makeJoinerSecret(suite, context, initSecret, suite.Zero())
	return newKeyScheduleFromJoiner(suite, joiner, suite.Zero(), nil, context)
}

func (ks *keyScheduleEpoch) next(commitSecret, pskSecret, forceInitSecret, confirmedTranscriptHash, context []byte) *keyScheduleEpoch {
	init := ks.initSecret
	if forceInitSecret != nil {
		init = forceInitSecret
	}
	joiner := makeJoinerSecret(ks.suite, context, init, commitSecret)
	return newKeyScheduleFromJoiner(ks.suite, joiner, pskSecret, confirmedTranscriptHash, context)
}

// export implements MLS-Exporter.
func (ks *keyScheduleEpoch) export(label string, context []byte, length int) []byte {
	secret := ks.suite.DeriveSecret(ks.exporterSecret, label)
	return ks.suite.ExpandWithLabel(secret, "exported", ks.suite.Hash(context), length)
}

// PSKWithSecret pairs a PreSharedKeyID with its secret.
type PSKWithSecret struct {
	ID     PreSharedKeyID
	Secret []byte
}

func makePSKSecret(suite CipherSuite, psks []PSKWithSecret) []byte {
	pskSecret := suite.Zero()
	count := uint16(len(psks))
	for i := range psks {
		extracted := suite.Extract(suite.Zero(), psks[i].Secret)
		label := marshalOf(func(w *tls.Writer) {
			psks[i].ID.marshal(w)
			w.U16(uint16(i))
			w.U16(count)
		})
		input := suite.ExpandWithLabel(extracted, "derived psk", label, suite.SecretSize())
		pskSecret = suite.Extract(input, pskSecret)
	}
	return pskSecret
}

// transcriptHash tracks the confirmed and interim transcript hashes.
type transcriptHash struct {
	suite     CipherSuite
	confirmed []byte
	interim   []byte
}

func (t *transcriptHash) newConfirmed(input []byte) []byte {
	return t.suite.Hash(append(append([]byte{}, t.interim...), input...))
}

func (t *transcriptHash) updateInterim(confirmationTag []byte) {
	in := marshalOf(func(w *tls.Writer) { w.Opaque(confirmationTag) })
	t.interim = t.suite.Hash(append(append([]byte{}, t.confirmed...), in...))
}
