package dave

import (
	"bytes"
	"sync"
	"time"
)

// DecryptorResult is the result of Decryptor.Decrypt. Values match libdave.
type DecryptorResult int

// Decryptor results.
const (
	DecryptSuccess           DecryptorResult = 0
	DecryptFailure           DecryptorResult = 1
	DecryptMissingKeyRatchet DecryptorResult = 2
	DecryptInvalidNonce      DecryptorResult = 3
	DecryptMissingCryptor    DecryptorResult = 4
)

func (r DecryptorResult) Error() string {
	switch r {
	case DecryptSuccess:
		return "dave: success"
	case DecryptFailure:
		return "dave: decryption failure"
	case DecryptMissingKeyRatchet:
		return "dave: missing key ratchet"
	case DecryptInvalidNonce:
		return "dave: invalid nonce"
	case DecryptMissingCryptor:
		return "dave: missing cryptor"
	}
	return "dave: unknown decryptor result"
}

// DecryptorStats are cumulative decryption statistics. Durations are in
// microseconds.
type DecryptorStats struct {
	PassthroughCount         uint64
	DecryptSuccessCount      uint64
	DecryptFailureCount      uint64
	DecryptDuration          uint64
	DecryptAttempts          uint64
	DecryptMissingKeyCount   uint64
	DecryptInvalidNonceCount uint64
}

// Decryptor decrypts incoming media frames from one sender. It retains the
// key ratchets of previous epochs for a transition period. It is safe for
// concurrent use.
type Decryptor struct {
	mu                    sync.Mutex
	clock                 Clock
	managers              []*cryptorManager
	processor             inboundFrameProcessor
	allowPassthroughUntil time.Time
	lastStatsTime         time.Time
	stats                 [2]DecryptorStats
}

// NewDecryptor creates a Decryptor using the system clock.
func NewDecryptor() *Decryptor { return NewDecryptorWithClock(SystemClock) }

// NewDecryptorWithClock creates a Decryptor with an injected clock.
func NewDecryptorWithClock(clock Clock) *Decryptor {
	return &Decryptor{clock: clock}
}

// TransitionToKeyRatchet installs a new key ratchet; existing ones expire
// after transitionExpiry. A ratchet for a key domain that is already live is
// ignored.
func (d *Decryptor) TransitionToKeyRatchet(r KeyRatchet, transitionExpiry time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cleanupExpiredManagers()
	if r != nil {
		id := r.DomainIdentity()
		for _, m := range d.managers {
			if bytes.Equal(m.domainIdentity(), id) {
				return
			}
		}
	}
	d.updateManagerExpiry(transitionExpiry)
	if r != nil {
		d.managers = append(d.managers, newCryptorManager(d.clock, r))
	}
}

// TransitionToPassthroughMode enables passthrough, or disables it after
// transitionExpiry.
func (d *Decryptor) TransitionToPassthroughMode(passthrough bool, transitionExpiry time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if passthrough {
		d.allowPassthroughUntil = farFuture
		return
	}
	maxExpiry := d.clock.Now().Add(transitionExpiry)
	if maxExpiry.Before(d.allowPassthroughUntil) {
		d.allowPassthroughUntil = maxExpiry
	}
}

// MaxPlaintextByteSize returns the buffer size needed to decrypt a frame.
func (d *Decryptor) MaxPlaintextByteSize(_ MediaType, encryptedFrameSize int) int {
	return encryptedFrameSize
}

// Stats returns cumulative statistics for a media type.
func (d *Decryptor) Stats(mt MediaType) DecryptorStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	if mt > MediaTypeVideo {
		return DecryptorStats{}
	}
	return d.stats[mt]
}

// Decrypt decrypts encryptedFrame into out (which may alias it) and returns
// the number of bytes written.
func (d *Decryptor) Decrypt(mt MediaType, encryptedFrame, out []byte) (int, DecryptorResult) {
	if mt != MediaTypeAudio && mt != MediaTypeVideo {
		logf(LogWarning, "decrypt failed, invalid media type %d", mt)
		return 0, DecryptFailure
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	start := d.clock.Now()
	st := &d.stats[mt]

	if mt == MediaTypeAudio && bytes.Equal(encryptedFrame, OpusSilencePacket) {
		return copy(out, encryptedFrame), DecryptSuccess
	}

	d.cleanupExpiredManagers()
	p := &d.processor
	p.parseFrame(encryptedFrame)

	if !p.encrypted && d.allowPassthroughUntil.After(start) {
		st.PassthroughCount++
		return copy(out, encryptedFrame), DecryptSuccess
	}
	if !p.encrypted {
		st.DecryptFailureCount++
		return 0, DecryptFailure
	}

	result := DecryptMissingKeyRatchet
	for i := len(d.managers) - 1; i >= 0; i-- {
		result = d.decryptWith(d.managers[i], mt)
		if result == DecryptSuccess {
			break
		}
	}
	n := 0
	if result == DecryptSuccess {
		st.DecryptSuccessCount++
		n = p.reconstructFrame(out)
	} else {
		st.DecryptFailureCount++
		switch result {
		case DecryptInvalidNonce:
			st.DecryptInvalidNonceCount++
		case DecryptMissingKeyRatchet:
			st.DecryptMissingKeyCount++
		}
		logf(LogWarning, "decryption failed: %v, frame size %d", result, len(encryptedFrame))
	}
	end := d.clock.Now()
	if end.Sub(d.lastStatsTime) > statsInterval {
		d.lastStatsTime = end
		logf(LogInfo, "decrypted audio: %d, video: %d. failed audio: %d, video: %d",
			d.stats[MediaTypeAudio].DecryptSuccessCount, d.stats[MediaTypeVideo].DecryptSuccessCount,
			d.stats[MediaTypeAudio].DecryptFailureCount, d.stats[MediaTypeVideo].DecryptFailureCount)
	}
	st.DecryptDuration += uint64(end.Sub(start) / time.Microsecond)
	return n, result
}

func (d *Decryptor) decryptWith(m *cryptorManager, mt MediaType) DecryptorResult {
	p := &d.processor
	nonce := expandTruncatedNonce(p.truncatedNonce)
	gen := m.computeWrappedGeneration(p.truncatedNonce >> ratchetGenerationShiftBits)
	if !m.canProcessNonce(gen, p.truncatedNonce) {
		return DecryptInvalidNonce
	}
	c := m.getCryptor(gen)
	if c == nil {
		return DecryptMissingCryptor
	}
	ok := c.decrypt(p.plaintext, p.ciphertext, p.tag, nonce[:], p.authenticated)
	d.stats[mt].DecryptAttempts++
	if !ok {
		return DecryptFailure
	}
	m.reportCryptorSuccess(gen, p.truncatedNonce)
	return DecryptSuccess
}

func (d *Decryptor) updateManagerExpiry(expiry time.Duration) {
	max := d.clock.Now().Add(expiry)
	for _, m := range d.managers {
		m.updateExpiry(max)
	}
}

func (d *Decryptor) cleanupExpiredManagers() {
	for len(d.managers) > 0 && d.managers[0].isExpired() {
		d.managers = d.managers[1:]
	}
}
