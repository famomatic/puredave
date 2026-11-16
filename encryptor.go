package dave

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// EncryptorResult is the result of Encryptor.Encrypt. Values match libdave.
type EncryptorResult int

// Encryptor results.
const (
	EncryptSuccess           EncryptorResult = 0
	EncryptFailure           EncryptorResult = 1
	EncryptMissingKeyRatchet EncryptorResult = 2
	EncryptMissingCryptor    EncryptorResult = 3
	EncryptTooManyAttempts   EncryptorResult = 4
)

func (r EncryptorResult) Error() string {
	switch r {
	case EncryptSuccess:
		return "dave: success"
	case EncryptFailure:
		return "dave: encryption failure"
	case EncryptMissingKeyRatchet:
		return "dave: missing key ratchet"
	case EncryptMissingCryptor:
		return "dave: missing cryptor"
	case EncryptTooManyAttempts:
		return "dave: too many encryption attempts"
	}
	return "dave: unknown encryptor result"
}

// EncryptorStats are cumulative encryption statistics. Durations are in
// microseconds.
type EncryptorStats struct {
	PassthroughCount       uint64
	EncryptSuccessCount    uint64
	EncryptFailureCount    uint64
	EncryptDuration        uint64
	EncryptAttempts        uint64
	EncryptMaxAttempts     uint64
	EncryptMissingKeyCount uint64
}

const maxCiphertextValidationRetries = 10
const statsInterval = 10 * time.Second

// Encryptor encrypts outgoing media frames with the local sender's key
// ratchet. It is safe for concurrent use.
type Encryptor struct {
	passthrough atomic.Bool

	keyMu             sync.Mutex
	keyRatchet        KeyRatchet
	keyDomainIdentity []byte
	cryptor           *cryptor
	currentGeneration KeyGeneration
	truncatedNonce    uint32

	processors sync.Pool

	codecMu sync.Mutex
	codecs  map[uint32]Codec

	statsMu       sync.Mutex
	stats         [2]EncryptorStats
	lastStatsTime time.Time

	versionMu       sync.Mutex
	versionCallback func()
	currentVersion  ProtocolVersion
}

// NewEncryptor creates an Encryptor. Like libdave it starts out encrypting
// (not in passthrough mode) and without a key ratchet.
func NewEncryptor() *Encryptor {
	e := &Encryptor{codecs: map[uint32]Codec{}, currentVersion: MaxSupportedProtocolVersion()}
	e.processors.New = func() any { return &outboundFrameProcessor{} }
	return e
}

// SetKeyRatchet installs the local sender key ratchet. Installing a ratchet
// for a new key domain restarts the nonce sequence.
func (e *Encryptor) SetKeyRatchet(r KeyRatchet) {
	e.keyMu.Lock()
	defer e.keyMu.Unlock()
	if r != nil {
		id := r.DomainIdentity()
		if !bytes.Equal(id, e.keyDomainIdentity) {
			e.keyDomainIdentity = id
			e.currentGeneration = 0
			e.truncatedNonce = 0
		} else {
			logf(LogInfo, "key ratchet re-installed for current key domain, keeping nonce sequence")
		}
	}
	e.keyRatchet = r
	e.cryptor = nil
}

// SetPassthroughMode toggles passthrough (no encryption).
func (e *Encryptor) SetPassthroughMode(passthrough bool) {
	e.passthrough.Store(passthrough)
	v := MaxSupportedProtocolVersion()
	if passthrough {
		v = DisabledVersion
	}
	e.updateProtocolVersion(v)
}

// HasKeyRatchet reports whether a key ratchet is installed.
func (e *Encryptor) HasKeyRatchet() bool {
	e.keyMu.Lock()
	defer e.keyMu.Unlock()
	return e.keyRatchet != nil
}

// IsPassthroughMode reports whether passthrough is enabled.
func (e *Encryptor) IsPassthroughMode() bool { return e.passthrough.Load() }

// AssignSsrcToCodec records the codec of an outgoing stream.
func (e *Encryptor) AssignSsrcToCodec(ssrc uint32, codec Codec) {
	e.codecMu.Lock()
	defer e.codecMu.Unlock()
	e.codecs[ssrc] = codec
}

// CodecForSsrc returns the codec of an outgoing stream.
func (e *Encryptor) CodecForSsrc(ssrc uint32) Codec {
	e.codecMu.Lock()
	defer e.codecMu.Unlock()
	return e.codecs[ssrc]
}

// MaxCiphertextByteSize returns the buffer size needed to encrypt a frame.
func (e *Encryptor) MaxCiphertextByteSize(_ MediaType, frameSize int) int {
	return frameSize + supplementalBytes + transformPaddingBytes
}

// Stats returns cumulative statistics for a media type.
func (e *Encryptor) Stats(mt MediaType) EncryptorStats {
	e.statsMu.Lock()
	defer e.statsMu.Unlock()
	if mt > MediaTypeVideo {
		return EncryptorStats{}
	}
	return e.stats[mt]
}

// SetProtocolVersionChangedCallback registers a callback for passthrough
// changes.
func (e *Encryptor) SetProtocolVersionChangedCallback(cb func()) {
	e.versionMu.Lock()
	defer e.versionMu.Unlock()
	e.versionCallback = cb
}

// ProtocolVersion returns the protocol version in effect for sending.
func (e *Encryptor) ProtocolVersion() ProtocolVersion {
	e.versionMu.Lock()
	defer e.versionMu.Unlock()
	return e.currentVersion
}

func (e *Encryptor) updateProtocolVersion(v ProtocolVersion) {
	e.versionMu.Lock()
	if v == e.currentVersion {
		e.versionMu.Unlock()
		return
	}
	e.currentVersion = v
	cb := e.versionCallback
	e.versionMu.Unlock()
	if cb != nil {
		cb()
	}
}

func (e *Encryptor) nextCryptorAndNonce() (*cryptor, uint32) {
	e.keyMu.Lock()
	defer e.keyMu.Unlock()
	if e.keyRatchet == nil {
		return nil, 0
	}
	e.truncatedNonce++
	gen := computeWrappedGeneration(e.currentGeneration, e.truncatedNonce>>ratchetGenerationShiftBits)
	if gen != e.currentGeneration || e.cryptor == nil {
		e.currentGeneration = gen
		c, err := newCryptor(e.keyRatchet.GetKey(gen))
		if err != nil {
			logf(LogError, "failed to create cryptor for generation %d: %v", gen, err)
			e.cryptor = nil
			return nil, 0
		}
		e.cryptor = c
	}
	return e.cryptor, e.truncatedNonce
}

// ErrBufferTooSmall is returned when an output buffer cannot hold a frame.
var ErrBufferTooSmall = errors.New("dave: output buffer too small")

// Encrypt encrypts frame into out and returns the number of bytes written.
// out should be at least MaxCiphertextByteSize bytes. In passthrough mode the
// frame is copied unchanged.
func (e *Encryptor) Encrypt(mt MediaType, ssrc uint32, frame, out []byte) (int, EncryptorResult) {
	if mt != MediaTypeAudio && mt != MediaTypeVideo {
		logf(LogWarning, "encrypt failed, invalid media type %d", mt)
		return 0, EncryptFailure
	}
	if e.passthrough.Load() {
		n := copy(out, frame)
		e.statsMu.Lock()
		e.stats[mt].PassthroughCount++
		e.statsMu.Unlock()
		return n, EncryptSuccess
	}
	if !e.HasKeyRatchet() {
		e.statsMu.Lock()
		e.stats[mt].EncryptFailureCount++
		e.stats[mt].EncryptMissingKeyCount++
		e.statsMu.Unlock()
		return 0, EncryptMissingKeyRatchet
	}

	start := time.Now()
	codec := e.CodecForSsrc(ssrc)
	p := e.processors.Get().(*outboundFrameProcessor)
	defer e.processors.Put(p)
	p.processFrame(frame, codec)

	rangesSize := unencryptedRangesSize(p.ranges)
	frameSize := len(p.encryptedBytes) + len(p.unencryptedBytes)

	result := EncryptSuccess
	written := 0
	attempts := uint64(0)
	missingKey := false
	for attempt := 1; attempt <= maxCiphertextValidationRetries; attempt++ {
		c, nonce := e.nextCryptorAndNonce()
		if c == nil {
			missingKey = true
			result = EncryptMissingCryptor
			break
		}
		nonceSize := leb128Size(uint64(nonce))
		total := frameSize + aesGCM128TruncatedTagBytes + nonceSize + rangesSize + 1 + 2
		if len(out) < total {
			result = EncryptFailure
			break
		}
		fullNonce := expandTruncatedNonce(nonce)
		tag := out[frameSize : frameSize+aesGCM128TruncatedTagBytes]
		attempts++
		if !c.encrypt(p.ciphertextBytes, p.encryptedBytes, fullNonce[:], p.unencryptedBytes, tag) {
			result = EncryptFailure
			break
		}
		if p.reconstructFrame(out) != frameSize {
			result = EncryptFailure
			break
		}
		supp := out[frameSize+aesGCM128TruncatedTagBytes : frameSize+aesGCM128TruncatedTagBytes]
		supp = appendLeb128(supp, uint64(nonce))
		supp = appendUnencryptedRanges(supp, p.ranges)
		suppTotal := supplementalBytes + nonceSize + rangesSize
		if suppTotal > 0xff {
			result = EncryptFailure
			break
		}
		supp = append(supp, byte(suppTotal), markerBytes[0], markerBytes[1])
		_ = supp
		if validateEncryptedFrame(p, out[:total]) {
			written = total
			break
		}
		if attempt >= maxCiphertextValidationRetries {
			result = EncryptTooManyAttempts
		}
	}

	now := time.Now()
	e.statsMu.Lock()
	st := &e.stats[mt]
	st.EncryptAttempts += attempts
	if attempts > st.EncryptMaxAttempts {
		st.EncryptMaxAttempts = attempts
	}
	if missingKey {
		st.EncryptMissingKeyCount++
	}
	st.EncryptDuration += uint64(now.Sub(start) / time.Microsecond)
	if result == EncryptSuccess {
		st.EncryptSuccessCount++
	} else {
		st.EncryptFailureCount++
	}
	if now.Sub(e.lastStatsTime) > statsInterval {
		e.lastStatsTime = now
		logf(LogInfo, "encrypted audio: %d, video: %d. failed audio: %d, video: %d",
			e.stats[MediaTypeAudio].EncryptSuccessCount, e.stats[MediaTypeVideo].EncryptSuccessCount,
			e.stats[MediaTypeAudio].EncryptFailureCount, e.stats[MediaTypeVideo].EncryptFailureCount)
	}
	e.statsMu.Unlock()
	return written, result
}
