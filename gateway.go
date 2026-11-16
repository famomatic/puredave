package dave

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/famomatic/puredave/mls"
)

// GatewayCallbacks sends DAVE messages to the voice gateway. Each method
// receives the opcode payload without the opcode byte.
type GatewayCallbacks interface {
	// SendMLSKeyPackage sends dave_mls_key_package (26).
	SendMLSKeyPackage(keyPackage []byte) error
	// SendMLSCommitWelcome sends dave_mls_commit_welcome (28).
	SendMLSCommitWelcome(commitWelcome []byte) error
	// SendReadyForTransition sends dave_protocol_ready_for_transition (23).
	SendReadyForTransition(transitionID uint16) error
	// SendInvalidCommitWelcome sends dave_mls_invalid_commit_welcome (31).
	SendInvalidCommitWelcome(transitionID uint16) error
}

const mlsNewGroupExpectedEpoch = 1

// GatewaySession drives a Session, an Encryptor and per-user Decryptors
// from voice gateway events, implementing the client side of the DAVE
// transition protocol. It is safe for concurrent use; gateway events must be
// delivered in order.
type GatewaySession struct {
	mu sync.Mutex

	selfUserID string
	channelID  uint64
	callbacks  GatewayCallbacks
	signingKey *mls.SignaturePrivateKey

	session     *Session
	encryptor   *Encryptor
	decryptors  map[string]*Decryptor
	prepared    map[uint16]ProtocolVersion
	lastVersion ProtocolVersion

	onError func(op string, err error)

	// disabled reports whether the protocol version in effect for the local
	// encryptor is DisabledVersion, so E2EE is never established.
	disabled atomic.Bool
}

// GatewaySessionOption configures a GatewaySession.
type GatewaySessionOption func(*GatewaySession)

// WithSigningKey shares an identity key across voice connections, as DAVE
// requires for a client's concurrent media sessions.
func WithSigningKey(key *mls.SignaturePrivateKey) GatewaySessionOption {
	return func(g *GatewaySession) { g.signingKey = key }
}

// WithSessionOptions passes options to the underlying Session.
func WithSessionOptions(opts ...SessionOption) GatewaySessionOption {
	return func(g *GatewaySession) { g.session = NewSession(opts...) }
}

// WithErrorHandler receives callback and protocol errors.
func WithErrorHandler(fn func(op string, err error)) GatewaySessionOption {
	return func(g *GatewaySession) { g.onError = fn }
}

// NewGatewaySession creates a GatewaySession for the local user. The
// encryptor starts in passthrough mode until DAVE is negotiated.
func NewGatewaySession(selfUserID string, callbacks GatewayCallbacks, opts ...GatewaySessionOption) *GatewaySession {
	g := &GatewaySession{
		selfUserID: selfUserID,
		callbacks:  callbacks,
		encryptor:  NewEncryptor(),
		decryptors: map[string]*Decryptor{},
		prepared:   map[uint16]ProtocolVersion{},
	}
	for _, o := range opts {
		o(g)
	}
	if g.session == nil {
		g.session = NewSession()
	}
	g.encryptor.SetPassthroughMode(true)
	return g
}

func (g *GatewaySession) report(op string, err error) {
	if err != nil && g.onError != nil {
		g.onError(op, err)
	}
}

// Ready reports whether outgoing frames can be sent: true once the local
// encryptor has a key ratchet for an established epoch, or when DAVE is
// disabled for the connection. It is false while DAVE is being negotiated
// or a group is being joined (for example right after joining or moving
// voice channels); senders should hold frames until then instead of
// sending them unencrypted. Encrypt itself still passes frames through
// during that window.
func (g *GatewaySession) Ready() bool {
	if g.disabled.Load() {
		return true
	}
	return !g.encryptor.IsPassthroughMode() && g.encryptor.HasKeyRatchet()
}

// Session returns the underlying MLS session.
func (g *GatewaySession) Session() *Session { return g.session }

// Encryptor returns the local sender's encryptor.
func (g *GatewaySession) Encryptor() *Encryptor { return g.encryptor }

// SetChannelID sets the channel ID used as the MLS group ID.
func (g *GatewaySession) SetChannelID(channelID uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.channelID = channelID
}

// AssignSsrcToCodec maps an outgoing SSRC to a codec.
func (g *GatewaySession) AssignSsrcToCodec(ssrc uint32, codec Codec) {
	g.encryptor.AssignSsrcToCodec(ssrc, codec)
}

// MaxEncryptedFrameSize returns the buffer size needed to encrypt a frame.
func (g *GatewaySession) MaxEncryptedFrameSize(mt MediaType, frameSize int) int {
	return g.encryptor.MaxCiphertextByteSize(mt, frameSize)
}

// Encrypt encrypts an outgoing frame.
func (g *GatewaySession) Encrypt(mt MediaType, ssrc uint32, frame, out []byte) (int, error) {
	n, r := g.encryptor.Encrypt(mt, ssrc, frame, out)
	if r != EncryptSuccess {
		return 0, r
	}
	return n, nil
}

// MaxDecryptedFrameSize returns the buffer size needed to decrypt a frame.
func (g *GatewaySession) MaxDecryptedFrameSize(_ string, _ MediaType, frameSize int) int {
	return frameSize
}

// Decrypt decrypts an incoming frame from a user. Frames from users without
// a decryptor are passed through.
func (g *GatewaySession) Decrypt(userID string, mt MediaType, frame, out []byte) (int, error) {
	g.mu.Lock()
	d := g.decryptors[userID]
	g.mu.Unlock()
	if d == nil {
		if len(out) < len(frame) {
			return 0, ErrBufferTooSmall
		}
		return copy(out, frame), nil
	}
	n, r := d.Decrypt(mt, frame, out)
	if r != DecryptSuccess {
		return 0, r
	}
	return n, nil
}

// AddUser handles clients_connect (11) for one user.
func (g *GatewaySession) AddUser(userID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.session.AddRecognizedUser(userID)
	if _, ok := g.decryptors[userID]; !ok {
		g.decryptors[userID] = NewDecryptor()
	}
	g.setupKeyRatchetForUser(userID, g.lastVersion)
}

// RemoveUser handles client_disconnect (13).
func (g *GatewaySession) RemoveUser(userID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.session.RemoveRecognizedUser(userID)
	delete(g.decryptors, userID)
}

// OnSelectProtocolAck handles select_protocol_ack (4).
func (g *GatewaySession) OnSelectProtocolAck(version ProtocolVersion) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.protocolInit(version)
}

// OnPrepareTransition handles dave_protocol_prepare_transition (21).
func (g *GatewaySession) OnPrepareTransition(transitionID uint16, version ProtocolVersion) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.prepareTransition(transitionID, version)
	if transitionID != InitTransitionID {
		g.report("SendReadyForTransition", g.callbacks.SendReadyForTransition(transitionID))
	}
}

// OnExecuteTransition handles dave_protocol_execute_transition (22).
func (g *GatewaySession) OnExecuteTransition(transitionID uint16) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.executeTransition(transitionID)
}

// OnPrepareEpoch handles dave_protocol_prepare_epoch (24).
func (g *GatewaySession) OnPrepareEpoch(epoch uint64, version ProtocolVersion) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.prepareEpoch(epoch, version)
	if epoch == mlsNewGroupExpectedEpoch {
		g.sendKeyPackage()
	}
}

// OnExternalSenderPackage handles dave_mls_external_sender_package (25).
func (g *GatewaySession) OnExternalSenderPackage(externalSender []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.report("SetExternalSender", g.session.SetExternalSender(externalSender))
}

// OnProposals handles dave_mls_proposals (27).
func (g *GatewaySession) OnProposals(proposals []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	cw, err := g.session.ProcessProposals(proposals)
	if err != nil {
		g.report("ProcessProposals", err)
		return
	}
	if cw != nil {
		g.report("SendMLSCommitWelcome", g.callbacks.SendMLSCommitWelcome(cw))
	}
}

// OnAnnounceCommitTransition handles dave_mls_announce_commit_transition (29).
func (g *GatewaySession) OnAnnounceCommitTransition(transitionID uint16, commit []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, err := g.session.ProcessCommit(commit)
	if errors.Is(err, ErrIgnored) {
		return
	}
	if err != nil {
		g.report("ProcessCommit", err)
		g.report("SendInvalidCommitWelcome", g.callbacks.SendInvalidCommitWelcome(transitionID))
		g.protocolInit(g.session.ProtocolVersion())
		return
	}
	g.prepareTransition(transitionID, g.session.ProtocolVersion())
	if transitionID != InitTransitionID {
		g.report("SendReadyForTransition", g.callbacks.SendReadyForTransition(transitionID))
	}
}

// OnWelcome handles dave_mls_welcome (30).
func (g *GatewaySession) OnWelcome(transitionID uint16, welcome []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, err := g.session.ProcessWelcome(welcome); err != nil {
		g.report("ProcessWelcome", err)
		g.report("SendInvalidCommitWelcome", g.callbacks.SendInvalidCommitWelcome(transitionID))
		g.sendKeyPackage()
		return
	}
	g.prepareTransition(transitionID, g.session.ProtocolVersion())
	if transitionID != InitTransitionID {
		g.report("SendReadyForTransition", g.callbacks.SendReadyForTransition(transitionID))
	}
}

// EpochAuthenticator returns the current epoch authenticator, or nil.
func (g *GatewaySession) EpochAuthenticator() []byte { return g.session.LastEpochAuthenticator() }

func (g *GatewaySession) protocolInit(version ProtocolVersion) {
	if version > DisabledVersion {
		g.prepareEpoch(mlsNewGroupExpectedEpoch, version)
		g.sendKeyPackage()
	} else {
		g.prepareTransition(InitTransitionID, version)
		g.executeTransition(InitTransitionID)
	}
}

func (g *GatewaySession) prepareEpoch(epoch uint64, version ProtocolVersion) {
	if epoch != mlsNewGroupExpectedEpoch {
		return
	}
	g.signingKey = g.session.Init(version, g.channelID, g.selfUserID, g.signingKey)
}

func (g *GatewaySession) executeTransition(transitionID uint16) {
	version, ok := g.prepared[transitionID]
	if !ok {
		return
	}
	delete(g.prepared, transitionID)
	if version == DisabledVersion {
		g.session.Reset()
	}
	g.setupKeyRatchetForUser(g.selfUserID, version)
}

func (g *GatewaySession) prepareTransition(transitionID uint16, version ProtocolVersion) {
	for userID := range g.decryptors {
		g.setupKeyRatchetForUser(userID, version)
	}
	if transitionID == InitTransitionID {
		g.setupKeyRatchetForUser(g.selfUserID, version)
	} else {
		g.prepared[transitionID] = version
	}
	g.lastVersion = version
}

func (g *GatewaySession) setupKeyRatchetForUser(userID string, version ProtocolVersion) {
	disabled := version == DisabledVersion
	if userID == g.selfUserID {
		g.disabled.Store(disabled)
		g.encryptor.SetPassthroughMode(disabled)
		if !disabled {
			g.encryptor.SetKeyRatchet(g.session.KeyRatchet(userID))
		}
		return
	}
	d := g.decryptors[userID]
	if d == nil {
		return
	}
	d.TransitionToPassthroughMode(disabled, DefaultTransitionDuration)
	if !disabled {
		if r := g.session.KeyRatchet(userID); r != nil {
			d.TransitionToKeyRatchet(r, DefaultTransitionDuration)
		}
	}
}

func (g *GatewaySession) sendKeyPackage() {
	kp, err := g.session.MarshalledKeyPackage()
	if err != nil {
		g.report("MarshalledKeyPackage", err)
		return
	}
	g.report("SendMLSKeyPackage", g.callbacks.SendMLSKeyPackage(kp))
}
