// Package dave is a pure Go implementation of Discord's audio/video
// end-to-end encryption (DAVE) protocol, ported from Discord's libdave.
//
// It provides the MLS group session (Session), the media frame Encryptor and
// Decryptor, sender key ratchets and identity verification helpers, with no
// dependencies outside the Go standard library.
//
// Import it as:
//
//	import dave "github.com/famomatic/puredave"
package dave

import "time"

// ProtocolVersion is a DAVE protocol version. Version 0 means DAVE is
// disabled (transport encryption only).
type ProtocolVersion = uint16

const (
	// DisabledVersion disables end-to-end encryption.
	DisabledVersion ProtocolVersion = 0
	// CurrentProtocolVersion is the highest protocol version implemented.
	CurrentProtocolVersion ProtocolVersion = 1

	// InitTransitionID is the transition ID of (re)initialization
	// transitions, which execute immediately.
	InitTransitionID uint16 = 0

	// DefaultTransitionDuration is how long keys for a previous epoch or
	// protocol version are retained after a transition.
	DefaultTransitionDuration = 10 * time.Second
)

// MaxSupportedProtocolVersion returns the highest supported DAVE version.
func MaxSupportedProtocolVersion() ProtocolVersion { return CurrentProtocolVersion }

// MediaType distinguishes audio from video frames.
type MediaType uint8

// Media types.
const (
	MediaTypeAudio MediaType = 0
	MediaTypeVideo MediaType = 1
)

// Codec identifies the codec of a media stream. The values match libdave.
type Codec uint8

// Codecs.
const (
	CodecUnknown Codec = 0
	CodecOpus    Codec = 1
	CodecVP8     Codec = 2
	CodecVP9     Codec = 3
	CodecH264    Codec = 4
	CodecH265    Codec = 5
	CodecAV1     Codec = 6
)

func (c Codec) String() string {
	switch c {
	case CodecOpus:
		return "Opus"
	case CodecVP8:
		return "VP8"
	case CodecVP9:
		return "VP9"
	case CodecH264:
		return "H264"
	case CodecH265:
		return "H265"
	case CodecAV1:
		return "AV1"
	default:
		return "Unknown"
	}
}

// OpusSilencePacket is the canonical Opus silence frame, which decryptors
// pass through untouched.
var OpusSilencePacket = []byte{0xF8, 0xFF, 0xFE}

// Frame layout constants.
const (
	aesGCM128KeyBytes                = 16
	aesGCM128NonceBytes              = 12
	aesGCM128TruncatedSyncNonceBytes = 4
	aesGCM128TruncatedSyncNonceOff   = aesGCM128NonceBytes - aesGCM128TruncatedSyncNonceBytes
	aesGCM128TruncatedTagBytes       = 8
	ratchetGenerationBytes           = 1
	ratchetGenerationShiftBits       = 8 * (aesGCM128TruncatedSyncNonceBytes - ratchetGenerationBytes)
	supplementalBytes                = aesGCM128TruncatedTagBytes + 1 + 2 // tag + size byte + marker
	transformPaddingBytes            = 64

	cryptorExpiry      = 10 * time.Second
	maxGenerationGap   = 250
	maxMissingNonces   = 1000
	generationWrap     = 1 << (8 * ratchetGenerationBytes)
	maxFramesPerSecond = 50 + 2*60 // 50 audio frames + 2 * 60fps video streams
)

var markerBytes = [2]byte{0xFA, 0xFA}

// KeyGeneration is a sender key ratchet generation.
type KeyGeneration = uint32

// expandTruncatedNonce writes the 32-bit truncated nonce into the trailing
// bytes of a 96-bit AES-GCM nonce, little endian.
func expandTruncatedNonce(n uint32) [aesGCM128NonceBytes]byte {
	var out [aesGCM128NonceBytes]byte
	for i := 0; i < aesGCM128TruncatedSyncNonceBytes; i++ {
		out[aesGCM128TruncatedSyncNonceOff+i] = byte(n >> (8 * i))
	}
	return out
}

// computeWrappedGeneration maps an 8-bit generation from a nonce onto the
// full generation, assuming it is not older than oldest.
func computeWrappedGeneration(oldest, generation KeyGeneration) KeyGeneration {
	remainder := oldest % generationWrap
	factor := oldest / generationWrap
	if generation < remainder {
		factor++
	}
	return factor*generationWrap + generation
}

// computeWrappedBigNonce combines a wrapped generation with a nonce.
func computeWrappedBigNonce(generation KeyGeneration, nonce uint32) uint64 {
	masked := uint64(nonce) & ((1 << ratchetGenerationShiftBits) - 1)
	return uint64(generation)<<ratchetGenerationShiftBits | masked
}

// Clock abstracts the monotonic clock used for key expiry.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// SystemClock is the default Clock.
var SystemClock Clock = systemClock{}

// farFuture stands in for TimePoint::max().
var farFuture = time.Unix(1<<62, 0)
