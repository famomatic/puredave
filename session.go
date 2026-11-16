package dave

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"

	"github.com/famomatic/puredave/internal/scrypt"
	"github.com/famomatic/puredave/internal/tls"
	"github.com/famomatic/puredave/mls"
)

// UserMediaKeyBaseLabel is the MLS exporter label of sender key ratchets.
const UserMediaKeyBaseLabel = "Discord Secure Frames v0"

// MaxRetainedOutboundCommits bounds the commits a Session remembers per
// epoch, since the voice gateway may pick any of them.
const MaxRetainedOutboundCommits = 16

// RosterMap maps user IDs to signature public keys. In commit and welcome
// results it lists users whose keys were added or changed; an empty value
// means the user was removed.
type RosterMap map[uint64][]byte

// ErrIgnored is returned by ProcessCommit when a commit is soft-rejected
// (for example, it arrived while the session was resetting) and must not
// trigger recovery.
var ErrIgnored = errors.New("dave: message ignored")

// FailureCallback receives MLS failures as (source function, reason), like
// libdave's MLSFailureCallback.
type FailureCallback func(source, reason string)

// PersistedKeyProvider loads or creates a persistent signature key for a
// session ID (libdave's GetPersistedKeyPair). Platform key stores are left to
// the application.
type PersistedKeyProvider func(sessionID string, version ProtocolVersion) (*mls.SignaturePrivateKey, error)

// Session is a DAVE MLS session for one media session (libdave
// mls::Session). Its methods are safe for concurrent use, but protocol
// messages must be processed in signaling order.
type Session struct {
	mu sync.Mutex

	protocolVersion ProtocolVersion
	groupID         []byte
	signingKeyID    string
	selfUserID      string
	recognized      map[string]bool
	keyProvider     PersistedKeyProvider
	onFailure       FailureCallback

	selfLeafNode       *mls.LeafNode
	selfSigPrivateKey  *mls.SignaturePrivateKey
	selfHPKEPrivateKey *mls.HPKEPrivateKey
	joinInitPrivateKey *mls.HPKEPrivateKey
	joinKeyPackage     *mls.KeyPackage
	externalSender     *mls.ExternalSender

	pendingGroupState  *mls.State
	outboundCommits    []outboundCommit
	currentState       *mls.State
	roster             RosterMap
	stateWithProposals *mls.State
	proposalQueue      []queuedProposal
}

type queuedProposal struct {
	content *mls.AuthenticatedContent
	ref     []byte
}

type outboundCommit struct {
	message   []byte
	nextState *mls.State
}

// SessionOption configures a Session.
type SessionOption func(*Session)

// WithPersistedKeyProvider enables persistent signature keys. authSessionID
// is the Discord auth session ID used as the key identifier.
func WithPersistedKeyProvider(authSessionID string, p PersistedKeyProvider) SessionOption {
	return func(s *Session) {
		s.signingKeyID = authSessionID
		s.keyProvider = p
	}
}

// WithFailureCallback registers a failure callback.
func WithFailureCallback(cb FailureCallback) SessionOption {
	return func(s *Session) { s.onFailure = cb }
}

// NewSession creates a Session.
func NewSession(opts ...SessionOption) *Session {
	s := &Session{recognized: map[string]bool{}, roster: RosterMap{}}
	for _, o := range opts {
		o(s)
	}
	logf(LogInfo, "creating a new MLS session")
	return s
}

func (s *Session) fail(source string, err error) {
	logf(LogError, "%s: %v", source, err)
	if s.onFailure != nil {
		s.onFailure(source, err.Error())
	}
}

// Init (re)initializes the session for a protocol version, group (channel)
// ID and local user ID. signingKey is an optional transient signature key to
// reuse across sessions; when nil and no persistent key is configured a new
// one is generated. The key in use is returned so it can be shared, as DAVE
// requires the same identity key for all voice connections of a client.
func (s *Session) Init(version ProtocolVersion, groupID uint64, selfUserID string, signingKey *mls.SignaturePrivateKey) *mls.SignaturePrivateKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reset()
	s.selfUserID = selfUserID
	logf(LogInfo, "initializing MLS session with protocol version %d and group ID %d", version, groupID)
	s.protocolVersion = version
	s.groupID = bigEndianBytes(groupID)
	key := s.initLeafNode(selfUserID, signingKey)
	if s.externalSender != nil {
		s.createPendingGroup()
	} else {
		logf(LogInfo, "waiting for external sender to create a pending group")
	}
	return key
}

// Reset discards all group state.
func (s *Session) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reset()
}

func (s *Session) reset() {
	logf(LogInfo, "resetting MLS session")
	s.clearPendingState()
	s.currentState = nil
	s.protocolVersion = DisabledVersion
	s.groupID = nil
}

// SetProtocolVersion updates the protocol version.
func (s *Session) SetProtocolVersion(v ProtocolVersion) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.protocolVersion = v
}

// ProtocolVersion returns the protocol version.
func (s *Session) ProtocolVersion() ProtocolVersion {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.protocolVersion
}

// LastEpochAuthenticator returns the epoch authenticator of the established
// group, or nil.
func (s *Session) LastEpochAuthenticator() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currentState == nil {
		logf(LogError, "cannot get epoch authenticator without an established MLS group")
		return nil
	}
	return s.currentState.EpochAuthenticator()
}

// SetExternalSender sets the voice gateway external sender from the body of
// a dave_mls_external_sender_package opcode (25).
func (s *Session) SetExternalSender(marshalled []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currentState != nil {
		err := errors.New("cannot set external sender after joining/creating an MLS group")
		s.fail("SetExternalSender", err)
		return err
	}
	es, err := mls.UnmarshalExternalSender(marshalled)
	if err != nil {
		s.fail("SetExternalSender", err)
		return err
	}
	if s.pendingGroupState != nil && s.externalSender != nil && s.externalSender.Equal(es) {
		logf(LogInfo, "external sender unchanged, keeping pending MLS group")
		return nil
	}
	s.externalSender = es
	if len(s.groupID) != 0 {
		s.createPendingGroup()
	} else {
		logf(LogInfo, "waiting for group ID to create a pending group")
	}
	return nil
}

// AddRecognizedUser records a user announced as connected (clients_connect).
// The local user is always recognized.
func (s *Session) AddRecognizedUser(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recognized[userID] = true
}

// RemoveRecognizedUser forgets a disconnected user (client_disconnect).
func (s *Session) RemoveRecognizedUser(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.recognized, userID)
}

func (s *Session) isRecognizedCredential(cred *mls.Credential) bool {
	uid := userCredentialToString(cred)
	if uid == "" {
		logf(LogError, "attempted to verify credential of unexpected type")
		return false
	}
	if uid != s.selfUserID && !s.recognized[uid] {
		logf(LogError, "attempted to verify credential for unrecognized user ID %s", uid)
		return false
	}
	return true
}

func (s *Session) validateProposalMessage(ac *mls.AuthenticatedContent, target *mls.State) error {
	if ac.WireFormat != mls.WireFormatPublicMessage {
		return errors.New("MLS proposal message must be PublicMessage")
	}
	if ac.Content.Epoch != target.Epoch() {
		return fmt.Errorf("MLS proposal message must be for current epoch (%d != %d)", ac.Content.Epoch, target.Epoch())
	}
	if ac.Content.ContentType != mls.ContentTypeProposal {
		return errors.New("ProcessProposals called with non-proposal message")
	}
	if ac.Content.Sender.Type != mls.SenderTypeExternal {
		return errors.New("MLS proposal must be from external sender")
	}
	switch ac.Content.Proposal.Type {
	case mls.ProposalTypeAdd:
		if !s.isRecognizedCredential(&ac.Content.Proposal.KeyPackage.LeafNode.Credential) {
			return errors.New("MLS add proposal must be for recognized user")
		}
	case mls.ProposalTypeRemove:
		// The MLS layer validates the removed leaf.
	default:
		return errors.New("MLS proposal must be add or remove")
	}
	return nil
}

func (s *Session) validateQueuedProposals(queue []queuedProposal, target *mls.State) error {
	for _, q := range queue {
		if err := s.validateProposalMessage(q.content, target); err != nil {
			return err
		}
	}
	return nil
}

// ProcessProposals handles the body of a dave_mls_proposals opcode (27)
// (operation type followed by proposals or refs). When proposals remain
// queued it returns the dave_mls_commit_welcome (28) body to send; nil with
// a nil error means there is nothing to send.
func (s *Session) ProcessProposals(proposals []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out, err := s.processProposals(proposals)
	if err != nil {
		s.fail("ProcessProposals", err)
	}
	return out, err
}

func (s *Session) processProposals(proposals []byte) ([]byte, error) {
	if s.pendingGroupState == nil && s.currentState == nil {
		return nil, errors.New("cannot process proposals without any pending or established MLS group state")
	}
	base := s.currentState
	if s.pendingGroupState != nil {
		base = s.pendingGroupState
	}
	logf(LogInfo, "processing MLS proposals message of %d bytes", len(proposals))
	r := tls.NewReader(proposals)
	isRevoke := r.Bool()
	nextQueue := append([]queuedProposal{}, s.proposalQueue...)
	var next *mls.State
	if isRevoke {
		var refs [][]byte
		r.VectorEach(func(r *tls.Reader) { refs = append(refs, r.Opaque()) })
		if err := r.Done(); err != nil {
			return nil, err
		}
		next = base.Clone()
		revoked := 0
		kept := nextQueue[:0]
		for _, q := range nextQueue {
			found := false
			for _, ref := range refs {
				if bytes.Equal(ref, q.ref) {
					found = true
					break
				}
			}
			if found {
				revoked++
				continue
			}
			if err := next.HandleProposal(q.content); err != nil {
				return nil, err
			}
			kept = append(kept, q)
		}
		nextQueue = kept
		if revoked != len(refs) {
			return nil, errors.New("cannot revoke unrecognized or repeated proposal ref")
		}
	} else {
		var messages []*mls.MLSMessage
		r.VectorEach(func(r *tls.Reader) { messages = append(messages, mls.ReadMLSMessage(r)) })
		if err := r.Done(); err != nil {
			return nil, err
		}
		if s.stateWithProposals != nil {
			next = s.stateWithProposals.Clone()
		} else {
			next = base.Clone()
		}
		for _, m := range messages {
			ac, err := next.Unwrap(m)
			if err != nil {
				return nil, err
			}
			ref := next.ProposalRef(ac)
			for _, q := range nextQueue {
				if bytes.Equal(q.ref, ref) {
					return nil, errors.New("duplicate MLS proposal ref")
				}
			}
			if err := s.validateProposalMessage(ac, next); err != nil {
				return nil, err
			}
			if err := next.HandleProposal(ac); err != nil {
				return nil, err
			}
			nextQueue = append(nextQueue, queuedProposal{content: ac, ref: ref})
		}
	}
	if err := s.validateQueuedProposals(nextQueue, next); err != nil {
		return nil, err
	}
	if len(nextQueue) == 0 {
		logf(LogInfo, "no queued MLS proposals to commit")
		s.stateWithProposals = next
		s.proposalQueue = nextQueue
		return nil, nil
	}

	commitSecret := make([]byte, next.CipherSuite().SecretSize())
	if _, err := rand.Read(commitSecret); err != nil {
		return nil, err
	}
	commitMsg, welcome, newState, err := next.Commit(commitSecret, &mls.CommitOptions{InlineTree: true})
	if err != nil {
		return nil, err
	}
	logf(LogInfo, "prepared commit/welcome/next state for MLS group from received proposals")
	commitBytes, err := commitMsg.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, commitBytes...)
	if len(welcome.Secrets) > 0 {
		wb, err := welcome.MarshalBinary()
		if err != nil {
			return nil, err
		}
		out = append(out, wb...)
	}
	s.stateWithProposals = next
	s.proposalQueue = nextQueue
	if len(s.outboundCommits) >= MaxRetainedOutboundCommits {
		s.outboundCommits = s.outboundCommits[1:]
	}
	s.outboundCommits = append(s.outboundCommits, outboundCommit{message: commitBytes, nextState: newState})
	return out, nil
}

// ProcessCommit handles the MLS commit of a dave_mls_announce_commit_transition
// opcode (29). It returns the roster changes, ErrIgnored for a soft
// rejection, or another error for a hard rejection that should be reported
// with dave_mls_invalid_commit_welcome (31).
func (s *Session) ProcessCommit(commit []byte) (RosterMap, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	logf(LogInfo, "processing MLS commit of %d bytes", len(commit))
	if s.stateWithProposals == nil && s.currentState == nil {
		// An in-flight commit arriving during a reset must not cause
		// thrashing.
		s.fail("ProcessCommit", errors.New("received commit without state"))
		return nil, ErrIgnored
	}
	roster, err := s.processCommit(commit)
	if err != nil {
		s.fail("ProcessCommit", err)
		return nil, err
	}
	return roster, nil
}

func (s *Session) processCommit(commit []byte) (RosterMap, error) {
	if s.stateWithProposals == nil {
		return nil, errors.New("ProcessCommit called without queued proposals")
	}
	msg, err := mls.UnmarshalMLSMessage(commit)
	if err != nil {
		return nil, err
	}
	canonical, err := msg.MarshalBinary()
	if err != nil {
		return nil, err
	}
	outbound := -1
	for i, oc := range s.outboundCommits {
		if bytes.Equal(oc.message, canonical) {
			outbound = i
			break
		}
	}
	if s.currentState == nil && outbound < 0 {
		return nil, errors.New("unexpected commit before welcome")
	}
	if !bytes.Equal(msg.GroupID(), s.groupID) {
		return nil, errors.New("MLS commit message was for unexpected group")
	}
	ac, err := s.stateWithProposals.Unwrap(msg)
	if err != nil {
		return nil, err
	}
	if ac.WireFormat != mls.WireFormatPublicMessage {
		return nil, errors.New("invalid commit wire format")
	}
	if ac.Content.Epoch != s.stateWithProposals.Epoch() {
		return nil, errors.New("commit epoch mismatch")
	}
	if ac.Content.ContentType != mls.ContentTypeCommit {
		return nil, errors.New("unexpected message type")
	}
	if ac.Content.Sender.Type != mls.SenderTypeMember {
		return nil, errors.New("unexpected commit sender type")
	}
	committed := map[string]bool{}
	for _, p := range ac.Content.Commit.Proposals {
		if p.Proposal != nil {
			return nil, errors.New("unexpected non-ref proposal")
		}
		if committed[string(p.Ref)] {
			return nil, errors.New("commit references a proposal more than once")
		}
		committed[string(p.Ref)] = true
	}
	queued := map[string]bool{}
	for _, q := range s.proposalQueue {
		queued[string(q.ref)] = true
	}
	if len(queued) != len(s.proposalQueue) {
		return nil, errors.New("queued proposals contain a duplicate ref")
	}
	if len(committed) != len(queued) {
		return nil, errors.New("commit does not cover queued proposals")
	}
	for ref := range committed {
		if !queued[ref] {
			return nil, errors.New("commit does not cover queued proposals")
		}
	}
	if err := s.validateQueuedProposals(s.proposalQueue, s.stateWithProposals); err != nil {
		return nil, fmt.Errorf("commit includes invalid queued proposal: %w", err)
	}
	var cached *mls.State
	if outbound >= 0 {
		if outbound != len(s.outboundCommits)-1 {
			logf(LogInfo, "commit matches an earlier one of the %d outbound commits retained for this epoch", len(s.outboundCommits))
		}
		cached = s.outboundCommits[outbound].nextState
	}
	newState, err := s.stateWithProposals.Handle(ac, cached)
	if err != nil {
		return nil, err
	}
	if newState == nil {
		return nil, errors.New("commit handling did not produce a new state")
	}
	committer := mls.LeafIndex(ac.Content.Sender.Index)
	before := s.stateWithProposals.Tree().LeafNode(committer)
	after := newState.Tree().LeafNode(committer)
	if before == nil || after == nil || !before.Credential.Equal(&after.Credential) {
		return nil, errors.New("commit changes committer credential")
	}
	logf(LogInfo, "successfully processed MLS commit; our leaf index is %d; current epoch is %d", newState.Index(), newState.Epoch())
	ret, err := s.replaceState(newState)
	if err != nil {
		return nil, err
	}
	s.clearPendingState()
	return ret, nil
}

// ProcessWelcome handles the Welcome of a dave_mls_welcome opcode (30).
func (s *Session) ProcessWelcome(welcome []byte) (RosterMap, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ret, err := s.processWelcome(welcome)
	if err != nil {
		s.fail("ProcessWelcome", err)
		return nil, err
	}
	return ret, nil
}

func (s *Session) processWelcome(welcome []byte) (RosterMap, error) {
	switch {
	case s.joinKeyPackage == nil:
		return nil, errors.New("missing join key package")
	case s.joinInitPrivateKey == nil:
		return nil, errors.New("missing join init private key")
	case s.selfSigPrivateKey == nil:
		return nil, errors.New("missing self-sig private key")
	case s.selfHPKEPrivateKey == nil:
		return nil, errors.New("missing self-HPKE private key")
	case s.externalSender == nil:
		return nil, errors.New("missing external sender")
	case s.currentState != nil:
		return nil, errors.New("already joined/created group")
	}
	logf(LogInfo, "processing MLS welcome of %d bytes", len(welcome))
	w, err := mls.UnmarshalWelcome(welcome)
	if err != nil {
		return nil, err
	}
	state, err := mls.JoinFromWelcome(s.joinInitPrivateKey, s.selfHPKEPrivateKey, s.selfSigPrivateKey, s.joinKeyPackage, w, nil)
	if err != nil {
		return nil, err
	}
	if err := s.verifyWelcomeState(state); err != nil {
		return nil, fmt.Errorf("group received in MLS welcome is not valid: %w", err)
	}
	logf(LogInfo, "successfully welcomed to MLS group; our leaf index is %d; current epoch is %d", state.Index(), state.Epoch())
	ret, err := s.replaceState(state)
	if err != nil {
		return nil, err
	}
	s.clearPendingState()
	return ret, nil
}

func (s *Session) replaceState(state *mls.State) (RosterMap, error) {
	newRoster := RosterMap{}
	for _, leaf := range state.Roster() {
		if leaf.Credential.Type != mls.CredentialTypeBasic {
			return nil, errors.New("unexpected credential type in roster")
		}
		id := fromBigEndianBytes(leaf.Credential.Identity)
		if _, dup := newRoster[id]; dup {
			return nil, errors.New("duplicate identity in roster")
		}
		newRoster[id] = []byte(leaf.SignatureKey)
	}
	changes := RosterMap{}
	for id, key := range newRoster {
		if old, ok := s.roster[id]; !ok || !bytes.Equal(old, key) {
			changes[id] = key
		}
	}
	for id := range s.roster {
		if _, ok := newRoster[id]; !ok {
			changes[id] = []byte{}
		}
	}
	s.roster = newRoster
	s.currentState = state
	return changes, nil
}

func (s *Session) verifyWelcomeState(state *mls.State) error {
	if s.externalSender == nil {
		return errors.New("missing external sender when processing Welcome")
	}
	if !bytes.Equal(state.GroupID(), s.groupID) {
		return errors.New("unexpected group ID in Welcome")
	}
	data, ok := state.Extensions().Find(mls.ExtensionExternalSenders)
	if !ok {
		return errors.New("Welcome message missing external sender extension")
	}
	senders, err := mls.UnmarshalExternalSenders(data)
	if err != nil {
		return err
	}
	if len(senders) != 1 {
		return fmt.Errorf("Welcome message lists unexpected external sender count %d", len(senders))
	}
	if !senders[0].Equal(s.externalSender) {
		return errors.New("Welcome message lists unexpected external sender")
	}
	for _, leaf := range state.Roster() {
		if !s.isRecognizedCredential(&leaf.Credential) {
			return errors.New("Welcome message lists unrecognized user ID")
		}
	}
	return nil
}

func (s *Session) initLeafNode(selfUserID string, transient *mls.SignaturePrivateKey) *mls.SignaturePrivateKey {
	s.selfSigPrivateKey = nil
	if transient == nil && s.signingKeyID != "" && s.keyProvider != nil {
		key, err := s.keyProvider(s.signingKeyID, s.protocolVersion)
		if err != nil || key == nil {
			if err == nil {
				err = errors.New("generic failure in GetPersistedKeyPair")
			}
			logf(LogInfo, "failed to retrieve persisted key pair; falling back on transient: %v", err)
			if s.onFailure != nil {
				s.onFailure("GetPersistedKeyPair", err.Error())
			}
		} else {
			s.selfSigPrivateKey = key
		}
	}
	if s.selfSigPrivateKey == nil {
		if transient == nil {
			k, err := mls.GenerateSignaturePrivateKey()
			if err != nil {
				s.fail("InitLeafNode", err)
				return nil
			}
			transient = k
		}
		s.selfSigPrivateKey = transient
	}
	cred, err := createUserCredential(selfUserID)
	if err != nil {
		s.fail("InitLeafNode", err)
		return transient
	}
	hpkeKey, err := mls.GenerateHPKEPrivateKey()
	if err != nil {
		s.fail("InitLeafNode", err)
		return transient
	}
	s.selfHPKEPrivateKey = hpkeKey
	leaf := &mls.LeafNode{
		EncryptionKey: hpkeKey.PublicKey(),
		SignatureKey:  s.selfSigPrivateKey.PublicKey(),
		Credential:    cred,
		Capabilities:  leafNodeCapabilitiesForProtocolVersion(s.protocolVersion),
		Source:        mls.LeafNodeSourceKeyPackage,
		Lifetime:      mls.DefaultLifetime(),
		Extensions:    mls.ExtensionList{},
	}
	if err := leaf.Sign(s.selfSigPrivateKey, nil, 0); err != nil {
		s.fail("InitLeafNode", err)
		return transient
	}
	s.selfLeafNode = leaf
	logf(LogInfo, "created MLS leaf node")
	return s.selfSigPrivateKey
}

func (s *Session) resetJoinKeyPackage() error {
	if s.selfLeafNode == nil {
		return errors.New("missing leaf node")
	}
	initKey, err := mls.GenerateHPKEPrivateKey()
	if err != nil {
		return err
	}
	kp := &mls.KeyPackage{
		Version:     mls.ProtocolVersionMLS10,
		CipherSuite: ciphersuiteForProtocolVersion(s.protocolVersion),
		InitKey:     initKey.PublicKey(),
		LeafNode:    *s.selfLeafNode.Clone(),
		Extensions:  mls.ExtensionList{},
	}
	if err := kp.Sign(s.selfSigPrivateKey); err != nil {
		return err
	}
	s.joinInitPrivateKey = initKey
	s.joinKeyPackage = kp
	logf(LogInfo, "generated key package")
	return nil
}

func (s *Session) createPendingGroup() {
	s.pendingGroupState = nil
	s.clearNextEpochState()
	switch {
	case len(s.groupID) == 0:
		logf(LogError, "cannot create MLS group without a group ID")
		return
	case s.externalSender == nil:
		logf(LogError, "cannot create MLS group without ExternalSender")
		return
	case s.selfLeafNode == nil:
		logf(LogError, "cannot create MLS group without self leaf node")
		return
	}
	logf(LogInfo, "creating a pending MLS group")
	state, err := mls.NewGroup(s.groupID, ciphersuiteForProtocolVersion(s.protocolVersion), s.selfHPKEPrivateKey,
		s.selfSigPrivateKey, s.selfLeafNode, groupExtensionsForProtocolVersion(s.protocolVersion, s.externalSender))
	if err != nil {
		s.fail("CreatePendingGroup", err)
		return
	}
	s.pendingGroupState = state
	logf(LogInfo, "created a pending MLS group")
}

// MarshalledKeyPackage generates a fresh key package and returns its
// encoding for a dave_mls_key_package opcode (26). Key packages are never
// reused.
func (s *Session) MarshalledKeyPackage() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.resetJoinKeyPackage(); err != nil {
		s.fail("GetMarshalledKeyPackage", err)
		return nil, err
	}
	return s.joinKeyPackage.MarshalBinary()
}

// KeyRatchet returns the media key ratchet of a user in the current epoch,
// or nil without an established group.
func (s *Session) KeyRatchet(userID string) KeyRatchet {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currentState == nil {
		logf(LogInfo, "cannot get key ratchet without an established MLS group")
		return nil
	}
	id, _ := strconv.ParseUint(userID, 10, 64)
	base := s.currentState.Export(UserMediaKeyBaseLabel, littleEndianBytes(id), aesGCM128KeyBytes)
	return NewMLSKeyRatchet(s.currentState.CipherSuite(), base)
}

// Roster returns the user IDs and signature keys of the established group.
func (s *Session) Roster() RosterMap {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := RosterMap{}
	for k, v := range s.roster {
		out[k] = bytes.Clone(v)
	}
	return out
}

// SigningKey returns the signature key in use, if any.
func (s *Session) SigningKey() *mls.SignaturePrivateKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.selfSigPrivateKey
}

var fingerprintSalt = []byte{0x24, 0xca, 0xb1, 0x7a, 0x7a, 0xf8, 0xec, 0x2b, 0x82, 0xb4, 0x12, 0xb9, 0x2d, 0xab, 0x19, 0x2e}

// PairwiseFingerprint computes the 64-byte pairwise identity fingerprint
// with a remote user of the established group. It runs scrypt and is
// expensive; libdave computes it on a background thread.
func (s *Session) PairwiseFingerprint(version uint16, userID string) ([]byte, error) {
	s.mu.Lock()
	if s.currentState == nil || s.selfSigPrivateKey == nil {
		s.mu.Unlock()
		return nil, errors.New("dave: no established MLS group")
	}
	remoteID, _ := strconv.ParseUint(userID, 10, 64)
	selfID, _ := strconv.ParseUint(s.selfUserID, 10, 64)
	remoteKey, ok := s.roster[remoteID]
	if !ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("dave: unknown user ID %s", userID)
	}
	selfKey := s.selfSigPrivateKey.PublicKey()
	s.mu.Unlock()
	return PairwiseFingerprint(version, remoteID, remoteKey, selfID, selfKey)
}

// PairwiseFingerprint computes the fingerprint of two (user ID, signature
// public key) identities.
func PairwiseFingerprint(version uint16, userA uint64, keyA []byte, userB uint64, keyB []byte) ([]byte, error) {
	buf := func(user uint64, key []byte) []byte {
		w := tls.NewWriter()
		w.U16(version)
		w.Raw(key)
		w.U64(user)
		return w.Bytes()
	}
	parts := [][]byte{buf(userA, keyA), buf(userB, keyB)}
	sort.Slice(parts, func(i, j int) bool { return bytes.Compare(parts[i], parts[j]) < 0 })
	data := append(append([]byte{}, parts[0]...), parts[1]...)
	return scrypt.Key(data, fingerprintSalt, 16384, 8, 2, 64)
}

func (s *Session) clearPendingState() {
	s.pendingGroupState = nil
	s.joinInitPrivateKey = nil
	s.joinKeyPackage = nil
	s.selfHPKEPrivateKey = nil
	s.selfLeafNode = nil
	s.clearNextEpochState()
}

func (s *Session) clearNextEpochState() {
	s.outboundCommits = nil
	s.stateWithProposals = nil
	s.proposalQueue = nil
}

// Protocol parameters (libdave mls/parameters.cpp).

func ciphersuiteForProtocolVersion(ProtocolVersion) mls.CipherSuite { return mls.CipherSuiteP256 }

func leafNodeCapabilitiesForProtocolVersion(v ProtocolVersion) mls.Capabilities {
	return mls.Capabilities{
		Versions:     []uint16{mls.ProtocolVersionMLS10},
		CipherSuites: []uint16{uint16(ciphersuiteForProtocolVersion(v))},
		Extensions:   []uint16{},
		Proposals:    []uint16{},
		Credentials:  []uint16{mls.CredentialTypeBasic},
	}
}

func groupExtensionsForProtocolVersion(_ ProtocolVersion, es *mls.ExternalSender) mls.ExtensionList {
	return mls.ExtensionList{}.With(mls.ExtensionExternalSenders, mls.MarshalExternalSenders([]mls.ExternalSender{*es}))
}

func createUserCredential(userID string) (mls.Credential, error) {
	id, err := strconv.ParseUint(userID, 10, 64)
	if err != nil {
		return mls.Credential{}, fmt.Errorf("dave: invalid user ID %q", userID)
	}
	return mls.NewBasicCredential(bigEndianBytes(id)), nil
}

func userCredentialToString(cred *mls.Credential) string {
	if cred.Type != mls.CredentialTypeBasic {
		return ""
	}
	return strconv.FormatUint(fromBigEndianBytes(cred.Identity), 10)
}

func bigEndianBytes(v uint64) []byte {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b
}

func littleEndianBytes(v uint64) []byte {
	b := make([]byte, 8)
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
	return b
}

func fromBigEndianBytes(b []byte) uint64 {
	var v uint64
	if len(b) <= 8 {
		for _, c := range b {
			v = v<<8 | uint64(c)
		}
	}
	return v
}
