package mls

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/famomatic/puredave/internal/tls"
)

// CachedProposal is a proposal queued for the next commit.
type CachedProposal struct {
	Ref      []byte
	Proposal *Proposal
	Sender   *LeafIndex // member sender, if any
}

type epochRef struct {
	groupID string
	epoch   uint64
}

// State is the state of one member in one epoch of an MLS group
// (mlspp State). A State is immutable apart from proposal caching via
// HandleProposal; commits produce a new State.
type State struct {
	suite      CipherSuite
	groupID    []byte
	epoch      uint64
	tree       *RatchetTree
	treePriv   *treePrivateKey
	transcript transcriptHash
	extensions ExtensionList
	keys       *keyScheduleEpoch
	index      LeafIndex
	sigPriv    *SignaturePrivateKey

	pending        []CachedProposal
	externalPSKs   map[string][]byte
	resumptionPSKs map[epochRef][]byte
}

// CommitOptions controls commit creation.
type CommitOptions struct {
	ExtraProposals []*Proposal
	InlineTree     bool
	ForcePath      bool
}

// NewGroup creates a one-member group at epoch 0.
func NewGroup(groupID []byte, suite CipherSuite, encPriv *HPKEPrivateKey, sigPriv *SignaturePrivateKey, leaf *LeafNode, extensions ExtensionList) (*State, error) {
	if !suite.Supported() {
		return nil, ErrUnsupportedCipherSuite
	}
	if !leaf.Capabilities.SupportsExtensions(extensions) || !requiredCapabilitiesSupported(leaf, extensions) {
		return nil, errors.New("mls: client does not support required extensions")
	}
	s := &State{
		suite:          suite,
		groupID:        append([]byte{}, groupID...),
		tree:           newRatchetTree(suite),
		transcript:     transcriptHash{suite: suite},
		extensions:     append(ExtensionList{}, extensions...),
		sigPriv:        sigPriv,
		externalPSKs:   map[string][]byte{},
		resumptionPSKs: map[epochRef][]byte{},
	}
	idx, err := s.tree.addLeaf(leaf)
	if err != nil {
		return nil, err
	}
	s.index = idx
	s.treePriv = soloTreePrivateKey(suite, idx, encPriv)
	if !s.treePriv.consistent(s.tree) {
		return nil, errors.New("mls: leaf node inconsistent with private key")
	}
	s.tree.setHashAll()
	ctx := s.GroupContext()
	s.keys = newInitialKeySchedule(suite, randomBytes(suite.SecretSize()), ctx.Bytes())
	s.transcript.updateInterim(s.keys.confirmationTag)
	return s, nil
}

func requiredCapabilitiesSupported(leaf *LeafNode, exts ExtensionList) bool {
	data, ok := exts.Find(ExtensionRequiredCapabilities)
	if !ok {
		return true
	}
	var extTypes, propTypes, credTypes []uint16
	if err := decode(data, func(r *tls.Reader) {
		extTypes = readU16s(r)
		propTypes = readU16s(r)
		credTypes = readU16s(r)
	}); err != nil {
		return false
	}
	for _, t := range extTypes {
		if !defaultExtensionType(t) && !containsU16(leaf.Capabilities.Extensions, t) {
			return false
		}
	}
	for _, t := range propTypes {
		if !(t >= ProposalTypeAdd && t <= ProposalTypeGroupContextExtensions) && !containsU16(leaf.Capabilities.Proposals, t) {
			return false
		}
	}
	// mlspp does not check required credential types here.
	_ = credTypes
	return true
}

func leafSupportsExtensions(leaf *LeafNode, exts ExtensionList) bool {
	return leaf.Capabilities.SupportsExtensions(exts) && requiredCapabilitiesSupported(leaf, exts)
}

// JoinOptions carries optional inputs for joining from a Welcome.
type JoinOptions struct {
	// Tree is an out-of-band ratchet tree, used instead of the ratchet_tree
	// GroupInfo extension.
	Tree *RatchetTree
	// ExternalPSKs maps external PSK IDs to secrets.
	ExternalPSKs map[string][]byte
}

// JoinFromWelcome initializes a State from a Welcome addressed to keyPackage.
func JoinFromWelcome(initPriv, leafPriv *HPKEPrivateKey, sigPriv *SignaturePrivateKey, keyPackage *KeyPackage, welcome *Welcome, opts *JoinOptions) (*State, error) {
	if opts == nil {
		opts = &JoinOptions{}
	}
	suite := welcome.CipherSuite
	if !suite.Supported() {
		return nil, ErrUnsupportedCipherSuite
	}
	s := &State{
		suite:          suite,
		transcript:     transcriptHash{suite: suite},
		sigPriv:        sigPriv,
		externalPSKs:   map[string][]byte{},
		resumptionPSKs: map[epochRef][]byte{},
	}
	for k, v := range opts.ExternalPSKs {
		s.externalPSKs[k] = v
	}
	kpi, ok := welcome.find(keyPackage.Ref())
	if !ok {
		return nil, errors.New("mls: Welcome not intended for key package")
	}
	if keyPackage.CipherSuite != suite {
		return nil, errors.New("mls: ciphersuite mismatch")
	}
	secrets, err := welcome.decryptSecrets(kpi, initPriv)
	if err != nil {
		return nil, err
	}
	psks, err := s.resolvePSKs(secrets.PSKs)
	if err != nil {
		return nil, err
	}
	pskSecret := makePSKSecret(suite, psks)
	gi, err := welcome.decryptGroupInfo(secrets.JoinerSecret, pskSecret)
	if err != nil {
		return nil, err
	}
	if gi.GroupContext.CipherSuite != suite {
		return nil, errors.New("mls: GroupInfo and Welcome ciphersuites disagree")
	}
	tree, err := importTree(suite, gi.GroupContext.TreeHash, opts.Tree, gi.Extensions)
	if err != nil {
		return nil, err
	}
	s.tree = tree
	signer := tree.LeafNode(gi.Signer)
	if signer == nil || !gi.verify(signer.SignatureKey) {
		return nil, errors.New("mls: invalid GroupInfo")
	}
	s.epoch = gi.GroupContext.Epoch
	s.groupID = gi.GroupContext.GroupID
	s.transcript.confirmed = gi.GroupContext.ConfirmedTranscriptHash
	s.transcript.updateInterim(gi.ConfirmationTag)
	s.extensions = gi.GroupContext.Extensions
	if !s.validateTree() {
		return nil, errors.New("mls: invalid tree")
	}
	idx, ok := s.tree.find(&keyPackage.LeafNode)
	if !ok {
		return nil, errors.New("mls: new joiner not in tree")
	}
	s.index = idx
	ancestor := idx.Ancestor(gi.Signer)
	s.treePriv = joinerTreePrivateKey(s.tree, idx, leafPriv, ancestor, secrets.PathSecret)
	if !s.treePriv.consistent(s.tree) {
		return nil, errors.New("mls: path secret inconsistent with tree")
	}
	ctx := s.GroupContext()
	s.keys = newKeyScheduleFromJoiner(suite, secrets.JoinerSecret, pskSecret, s.transcript.confirmed, ctx.Bytes())
	if !bytesEqual(s.keys.confirmationTag, gi.ConfirmationTag) {
		return nil, errors.New("mls: confirmation failed to verify")
	}
	return s, nil
}

func importTree(suite CipherSuite, treeHash []byte, external *RatchetTree, exts ExtensionList) (*RatchetTree, error) {
	var tree *RatchetTree
	if external != nil {
		tree = external.clone()
	} else if data, ok := exts.Find(ExtensionRatchetTree); ok {
		t, err := UnmarshalRatchetTree(suite, data)
		if err != nil {
			return nil, err
		}
		tree = t
	} else {
		return nil, errors.New("mls: no tree available")
	}
	tree.suite = suite
	tree.hashes = map[NodeIndex][]byte{}
	tree.setHashAll()
	if !bytes.Equal(tree.rootHash(), treeHash) {
		return nil, errors.New("mls: tree does not match GroupInfo")
	}
	return tree, nil
}

func (s *State) validateTree() bool {
	if !s.tree.parentHashValid() {
		return false
	}
	ok := s.tree.Leaves(func(i LeafIndex, l *LeafNode) bool {
		switch l.Source {
		case LeafNodeSourceCommit, LeafNodeSourceUpdate:
			return l.Verify(s.groupID, i)
		default:
			return l.Verify(nil, 0)
		}
	})
	if !ok {
		return false
	}
	n := 0
	enc := map[string]bool{}
	sig := map[string]bool{}
	creds := map[uint16]bool{}
	s.tree.Leaves(func(_ LeafIndex, l *LeafNode) bool {
		n++
		enc[string(l.EncryptionKey)] = true
		sig[string(l.SignatureKey)] = true
		creds[l.Credential.Type] = true
		return true
	})
	if len(enc) != n || len(sig) != n {
		return false
	}
	return s.tree.Leaves(func(_ LeafIndex, l *LeafNode) bool {
		if !leafSupportsExtensions(l, s.extensions) || !leafSupportsExtensions(l, l.Extensions) {
			return false
		}
		for t := range creds {
			if !l.Capabilities.SupportsCredential(t) {
				return false
			}
		}
		return true
	})
}

// Clone returns an independent copy of the state.
func (s *State) Clone() *State {
	c := *s
	c.tree = s.tree.clone()
	c.treePriv = s.treePriv.clone()
	c.extensions = append(ExtensionList{}, s.extensions...)
	c.pending = append([]CachedProposal{}, s.pending...)
	c.externalPSKs = map[string][]byte{}
	for k, v := range s.externalPSKs {
		c.externalPSKs[k] = v
	}
	c.resumptionPSKs = map[epochRef][]byte{}
	for k, v := range s.resumptionPSKs {
		c.resumptionPSKs[k] = v
	}
	return &c
}

// CipherSuite returns the group ciphersuite.
func (s *State) CipherSuite() CipherSuite { return s.suite }

// GroupID returns the group ID.
func (s *State) GroupID() []byte { return append([]byte{}, s.groupID...) }

// Epoch returns the current epoch.
func (s *State) Epoch() uint64 { return s.epoch }

// Index returns this member's leaf index.
func (s *State) Index() LeafIndex { return s.index }

// Tree returns a copy of the ratchet tree.
func (s *State) Tree() *RatchetTree { return s.tree.clone() }

// Extensions returns the group context extensions.
func (s *State) Extensions() ExtensionList { return append(ExtensionList{}, s.extensions...) }

// EpochAuthenticator returns the epoch authenticator.
func (s *State) EpochAuthenticator() []byte { return append([]byte{}, s.keys.epochAuthenticator...) }

// Export implements MLS-Exporter.
func (s *State) Export(label string, context []byte, length int) []byte {
	return s.keys.export(label, context, length)
}

// Roster returns the occupied leaf nodes in leaf order.
func (s *State) Roster() []*LeafNode {
	var out []*LeafNode
	s.tree.Leaves(func(_ LeafIndex, l *LeafNode) bool {
		out = append(out, l.Clone())
		return true
	})
	return out
}

// PendingProposals returns the cached proposals.
func (s *State) PendingProposals() []CachedProposal { return append([]CachedProposal{}, s.pending...) }

// AddExternalPSK registers an external PSK.
func (s *State) AddExternalPSK(id, secret []byte) { s.externalPSKs[string(id)] = secret }

// GroupContext returns the current group context.
func (s *State) GroupContext() GroupContext {
	return GroupContext{
		CipherSuite:             s.suite,
		GroupID:                 s.groupID,
		Epoch:                   s.epoch,
		TreeHash:                s.tree.rootHash(),
		ConfirmedTranscriptHash: s.transcript.confirmed,
		Extensions:              s.extensions,
	}
}

// ProposalRef computes the ProposalRef of an authenticated proposal.
func (s *State) ProposalRef(ac *AuthenticatedContent) []byte {
	return s.suite.RefHash("MLS 1.0 Proposal Reference", ac.Bytes())
}

// Unwrap verifies a PublicMessage and returns its authenticated content.
func (s *State) Unwrap(msg *MLSMessage) (*AuthenticatedContent, error) {
	if msg.WireFormat != WireFormatPublicMessage || msg.Public == nil {
		return nil, errors.New("mls: only PublicMessage is supported")
	}
	pm := msg.Public
	if !bytes.Equal(pm.Content.GroupID, s.groupID) {
		return nil, errors.New("mls: PublicMessage not for this group")
	}
	if pm.Content.Epoch != s.epoch {
		return nil, errors.New("mls: PublicMessage not for this epoch")
	}
	ctx := s.GroupContext()
	ac, err := pm.unprotect(s.suite, s.keys.membershipKey, &ctx)
	if err != nil {
		return nil, err
	}
	ok, err := s.verify(ac)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("mls: message signature failed to verify")
	}
	return ac, nil
}

func (s *State) verify(ac *AuthenticatedContent) (bool, error) {
	ctx := s.GroupContext()
	switch ac.Content.Sender.Type {
	case SenderTypeMember:
		leaf := s.tree.LeafNode(LeafIndex(ac.Content.Sender.Index))
		if leaf == nil {
			return false, errors.New("mls: signature from blank node")
		}
		return ac.VerifySignature(leaf.SignatureKey, &ctx), nil
	case SenderTypeExternal:
		data, ok := s.extensions.Find(ExtensionExternalSenders)
		if !ok {
			return false, errors.New("mls: no external senders")
		}
		senders, err := UnmarshalExternalSenders(data)
		if err != nil {
			return false, err
		}
		if int(ac.Content.Sender.Index) >= len(senders) {
			return false, errors.New("mls: unknown external sender")
		}
		return ac.VerifySignature(senders[ac.Content.Sender.Index].SignatureKey, &ctx), nil
	case SenderTypeNewMemberProposal:
		if ac.Content.ContentType != ContentTypeProposal || ac.Content.Proposal.Type != ProposalTypeAdd {
			return false, errors.New("mls: invalid new member proposal")
		}
		return ac.VerifySignature(ac.Content.Proposal.KeyPackage.LeafNode.SignatureKey, &ctx), nil
	case SenderTypeNewMemberCommit:
		if ac.Content.ContentType != ContentTypeCommit || ac.Content.Commit.Path == nil {
			return false, errors.New("mls: invalid new member commit")
		}
		return ac.VerifySignature(ac.Content.Commit.Path.LeafNode.SignatureKey, &ctx), nil
	default:
		return false, errors.New("mls: invalid sender type")
	}
}

// Handle processes an unwrapped message. Proposals are cached in s and nil
// is returned; commits return the successor state. cached is the successor
// prepared when this member created the commit.
func (s *State) Handle(ac *AuthenticatedContent, cached *State) (*State, error) {
	switch ac.Content.ContentType {
	case ContentTypeProposal:
		return nil, s.HandleProposal(ac)
	case ContentTypeCommit:
		return s.handleCommit(ac, cached)
	default:
		return nil, errors.New("mls: invalid content type")
	}
}

func validExternalProposalType(t uint16) bool {
	switch t {
	case ProposalTypeAdd, ProposalTypeRemove, ProposalTypePSK, ProposalTypeReInit, ProposalTypeGroupContextExtensions:
		return true
	}
	return false
}

// HandleProposal caches a proposal for the next commit.
func (s *State) HandleProposal(ac *AuthenticatedContent) error {
	if ac.Content.ContentType != ContentTypeProposal {
		return errors.New("mls: not a proposal")
	}
	ref := s.ProposalRef(ac)
	for _, c := range s.pending {
		if bytes.Equal(c.Ref, ref) {
			return nil
		}
	}
	var sender *LeafIndex
	if ac.Content.Sender.Type == SenderTypeMember {
		l := LeafIndex(ac.Content.Sender.Index)
		sender = &l
	}
	p := ac.Content.Proposal
	if ac.Content.Sender.Type == SenderTypeExternal && !validExternalProposalType(p.Type) {
		return errors.New("mls: invalid external proposal")
	}
	if !s.validProposal(sender, p) {
		return errors.New("mls: invalid proposal")
	}
	s.pending = append(s.pending, CachedProposal{Ref: ref, Proposal: p, Sender: sender})
	return nil
}

func (s *State) validLeafNode(leaf *LeafNode, source LeafNodeSource, index *LeafIndex) bool {
	if leaf.Source != source {
		return false
	}
	var sigOK bool
	switch source {
	case LeafNodeSourceCommit, LeafNodeSourceUpdate:
		if index == nil {
			return false
		}
		sigOK = leaf.Verify(s.groupID, *index)
	default:
		sigOK = leaf.Verify(nil, 0)
	}
	if !sigOK || !leafSupportsExtensions(leaf, s.extensions) || !leafSupportsExtensions(leaf, leaf.Extensions) {
		return false
	}
	return s.tree.Leaves(func(_ LeafIndex, other *LeafNode) bool {
		return other.Capabilities.SupportsCredential(leaf.Credential.Type) &&
			leaf.Capabilities.SupportsCredential(other.Credential.Type)
	})
}

func (s *State) validKeyPackage(kp *KeyPackage) bool {
	return kp.CipherSuite == s.suite &&
		kp.Verify() &&
		s.validLeafNode(&kp.LeafNode, LeafNodeSourceKeyPackage, nil) &&
		!bytes.Equal(kp.InitKey, kp.LeafNode.EncryptionKey)
}

func (s *State) validPSK(p *PreSharedKeyID) bool {
	switch p.Type {
	case PSKTypeExternal:
		_, ok := s.externalPSKs[string(p.PSKID)]
		return ok
	case PSKTypeResumption:
		if p.Usage != 1 { // application
			return false
		}
		_, ok := s.resumptionPSKs[epochRef{string(p.PSKGroupID), p.PSKEpoch}]
		return p.PSKEpoch == s.epoch || ok
	}
	return false
}

func (s *State) extensionsSupported(exts ExtensionList) bool {
	return s.tree.Leaves(func(_ LeafIndex, l *LeafNode) bool { return leafSupportsExtensions(l, exts) })
}

func (s *State) validProposal(sender *LeafIndex, p *Proposal) bool {
	switch p.Type {
	case ProposalTypeAdd:
		return s.validKeyPackage(p.KeyPackage)
	case ProposalTypeUpdate:
		if sender == nil || s.tree.LeafNode(*sender) == nil {
			return false
		}
		return s.validLeafNode(p.LeafNode, LeafNodeSourceUpdate, sender)
	case ProposalTypeRemove:
		return uint32(p.Removed) < s.tree.size && s.tree.HasLeaf(p.Removed) && p.Removed != s.index
	case ProposalTypePSK:
		return s.validPSK(p.PSK)
	case ProposalTypeReInit:
		return p.ReInitVersion == ProtocolVersionMLS10 && p.ReInitCipherSuite.Supported()
	case ProposalTypeExternalInit:
		return len(p.KEMOutput) == hpkeNenc
	case ProposalTypeGroupContextExtensions:
		return s.extensionsSupported(p.Extensions)
	}
	return false
}

func (s *State) resolveProposals(ids []ProposalOrRef, sender *LeafIndex) ([]CachedProposal, error) {
	out := make([]CachedProposal, 0, len(ids))
	for _, id := range ids {
		if id.Proposal != nil {
			out = append(out, CachedProposal{Proposal: id.Proposal, Sender: sender})
			continue
		}
		found := false
		for _, c := range s.pending {
			if bytes.Equal(c.Ref, id.Ref) {
				out = append(out, c)
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("mls: unknown proposal reference")
		}
	}
	return out, nil
}

func (s *State) resolvePSKs(ids []PreSharedKeyID) ([]PSKWithSecret, error) {
	out := make([]PSKWithSecret, 0, len(ids))
	for _, id := range ids {
		var secret []byte
		switch id.Type {
		case PSKTypeExternal:
			v, ok := s.externalPSKs[string(id.PSKID)]
			if !ok {
				return nil, errors.New("mls: unknown external PSK")
			}
			secret = v
		case PSKTypeResumption:
			if bytes.Equal(id.PSKGroupID, s.groupID) && id.PSKEpoch == s.epoch && s.keys != nil {
				secret = s.keys.resumptionPSK
			} else if v, ok := s.resumptionPSKs[epochRef{string(id.PSKGroupID), id.PSKEpoch}]; ok {
				secret = v
			} else {
				return nil, errors.New("mls: unknown resumption PSK")
			}
		default:
			return nil, errors.New("mls: invalid PSK type")
		}
		out = append(out, PSKWithSecret{ID: id, Secret: secret})
	}
	return out, nil
}

type applyResult struct {
	tree       *RatchetTree
	joiners    []LeafIndex
	psks       []PSKWithSecret
	extensions ExtensionList
}

func (s *State) apply(proposals []CachedProposal) (*applyResult, error) {
	tree := s.tree.clone()
	for _, c := range proposals {
		if c.Proposal.Type == ProposalTypeUpdate {
			if c.Sender == nil {
				return nil, errors.New("mls: update without target leaf")
			}
			if err := tree.updateLeaf(*c.Sender, c.Proposal.LeafNode); err != nil {
				return nil, err
			}
		}
	}
	for _, c := range proposals {
		if c.Proposal.Type == ProposalTypeRemove {
			if !tree.HasLeaf(c.Proposal.Removed) {
				return nil, errors.New("mls: attempt to remove non-member")
			}
			tree.blankPath(c.Proposal.Removed)
		}
	}
	var joiners []LeafIndex
	for _, c := range proposals {
		if c.Proposal.Type == ProposalTypeAdd {
			idx, err := tree.addLeaf(&c.Proposal.KeyPackage.LeafNode)
			if err != nil {
				return nil, err
			}
			joiners = append(joiners, idx)
		}
	}
	exts := s.extensions
	for _, c := range proposals {
		if c.Proposal.Type == ProposalTypeGroupContextExtensions {
			if !s.extensionsSupported(c.Proposal.Extensions) {
				return nil, errors.New("mls: unsupported extensions in GroupContextExtensions")
			}
			exts = c.Proposal.Extensions
			break
		}
	}
	var ids []PreSharedKeyID
	for _, c := range proposals {
		if c.Proposal.Type == ProposalTypePSK {
			ids = append(ids, *c.Proposal.PSK)
		}
	}
	psks, err := s.resolvePSKs(ids)
	if err != nil {
		return nil, err
	}
	tree.truncate()
	tree.setHashAll()
	return &applyResult{tree: tree, joiners: joiners, psks: psks, extensions: exts}, nil
}

func pathRequired(proposals []CachedProposal) bool {
	if len(proposals) == 0 {
		return true
	}
	for _, c := range proposals {
		switch c.Proposal.Type {
		case ProposalTypeUpdate, ProposalTypeRemove, ProposalTypeExternalInit, ProposalTypeGroupContextExtensions:
			return true
		}
	}
	return false
}

func (s *State) validNormal(proposals []CachedProposal, committer LeafIndex) bool {
	updatedOrRemoved := map[LeafIndex]bool{}
	sigKeys := map[string]bool{}
	pskIDs := map[string]bool{}
	encKeys := map[string]bool{}
	gce := 0
	for _, c := range proposals {
		p := c.Proposal
		if !s.validProposal(c.Sender, p) {
			return false
		}
		switch p.Type {
		case ProposalTypeUpdate:
			if *c.Sender == committer || updatedOrRemoved[*c.Sender] {
				return false
			}
			updatedOrRemoved[*c.Sender] = true
			k := string(p.LeafNode.EncryptionKey)
			if encKeys[k] {
				return false
			}
			encKeys[k] = true
		case ProposalTypeRemove:
			if p.Removed == committer || updatedOrRemoved[p.Removed] {
				return false
			}
			updatedOrRemoved[p.Removed] = true
		case ProposalTypeAdd:
			sk := string(p.KeyPackage.LeafNode.SignatureKey)
			if sigKeys[sk] {
				return false
			}
			sigKeys[sk] = true
			k := string(p.KeyPackage.LeafNode.EncryptionKey)
			if encKeys[k] {
				return false
			}
			encKeys[k] = true
		case ProposalTypePSK:
			k := string(marshalOf(p.PSK.marshal))
			if pskIDs[k] {
				return false
			}
			pskIDs[k] = true
		case ProposalTypeGroupContextExtensions:
			gce++
		case ProposalTypeReInit, ProposalTypeExternalInit:
			return false
		}
	}
	return gce <= 1
}

func (s *State) validExternalCommit(proposals []CachedProposal) bool {
	extInit, removes := 0, 0
	for _, c := range proposals {
		switch c.Proposal.Type {
		case ProposalTypeExternalInit:
			extInit++
		case ProposalTypeRemove:
			removes++
		case ProposalTypePSK:
			if !s.validPSK(c.Proposal.PSK) {
				return false
			}
		default:
			return false
		}
	}
	return extInit == 1 && removes <= 1
}

// Commit creates a commit covering all cached proposals plus extra ones.
// It returns the commit message, a Welcome (with no secrets when nobody is
// added) and the successor state.
func (s *State) Commit(leafSecret []byte, opts *CommitOptions) (*MLSMessage, *Welcome, *State, error) {
	if opts == nil {
		opts = &CommitOptions{}
	}
	var refs []ProposalOrRef
	var joinerKPs []*KeyPackage
	for _, c := range s.pending {
		if c.Proposal.Type == ProposalTypeAdd {
			joinerKPs = append(joinerKPs, c.Proposal.KeyPackage)
		}
		refs = append(refs, ProposalOrRef{Ref: c.Ref})
	}
	for _, p := range opts.ExtraProposals {
		if p.Type == ProposalTypeAdd {
			joinerKPs = append(joinerKPs, p.KeyPackage)
		}
		refs = append(refs, ProposalOrRef{Proposal: p})
	}
	self := s.index
	cached, err := s.resolveProposals(refs, &self)
	if err != nil {
		return nil, nil, nil, err
	}
	if !s.validNormal(cached, s.index) {
		return nil, nil, nil, errors.New("mls: invalid proposal list")
	}
	ar, err := s.apply(cached)
	if err != nil {
		return nil, nil, nil, err
	}
	newTreePriv := s.treePriv.clone()
	var path *UpdatePath
	pathSecrets := make([][]byte, len(ar.joiners))
	if opts.ForcePath || pathRequired(cached) {
		newTreePriv, err = ar.tree.update(s.index, leafSecret, s.groupID, s.sigPriv)
		if err != nil {
			return nil, nil, nil, err
		}
		ctx := GroupContext{
			CipherSuite:             s.suite,
			GroupID:                 s.groupID,
			Epoch:                   s.epoch + 1,
			TreeHash:                ar.tree.rootHash(),
			ConfirmedTranscriptHash: s.transcript.confirmed,
			Extensions:              ar.extensions,
		}
		path, err = ar.tree.encap(newTreePriv, ctx.Bytes(), ar.joiners)
		if err != nil {
			return nil, nil, nil, err
		}
		for i, j := range ar.joiners {
			_, secret, _ := newTreePriv.sharedPathSecret(j)
			pathSecrets[i] = secret
		}
	}

	commit := &Commit{Proposals: refs, Path: path}
	content := FramedContent{
		GroupID:     s.groupID,
		Epoch:       s.epoch,
		Sender:      Sender{Type: SenderTypeMember, Index: uint32(s.index)},
		ContentType: ContentTypeCommit,
		Commit:      commit,
	}
	ctx := s.GroupContext()
	ac, err := signAuthenticatedContent(WireFormatPublicMessage, content, s.sigPriv, &ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	confirmed := s.transcript.newConfirmed(ac.confirmedTranscriptHashInput())
	next := s.successor(s.index, ar.tree, newTreePriv, ar.extensions, confirmed, path != nil, ar.psks, nil)
	ac.Auth.ConfirmationTag = next.keys.confirmationTag
	msg := &MLSMessage{WireFormat: WireFormatPublicMessage, Public: protectPublic(ac, s.suite, s.keys.membershipKey, &ctx)}

	welcome, err := next.welcome(opts.InlineTree, ar.psks, joinerKPs, pathSecrets)
	if err != nil {
		return nil, nil, nil, err
	}
	return msg, welcome, next, nil
}

func (s *State) groupInfo(inlineTree bool) (*GroupInfo, error) {
	gi := &GroupInfo{
		GroupContext:    s.GroupContext(),
		ConfirmationTag: s.keys.confirmationTag,
		Signer:          s.index,
	}
	if inlineTree {
		gi.Extensions = gi.Extensions.With(ExtensionRatchetTree, marshalOf(s.tree.marshal))
	}
	if err := gi.sign(s.sigPriv); err != nil {
		return nil, err
	}
	return gi, nil
}

func (s *State) welcome(inlineTree bool, psks []PSKWithSecret, joiners []*KeyPackage, pathSecrets [][]byte) (*Welcome, error) {
	gi, err := s.groupInfo(inlineTree)
	if err != nil {
		return nil, err
	}
	pskIDs := make([]PreSharedKeyID, len(psks))
	for i := range psks {
		pskIDs[i] = psks[i].ID
	}
	wl := newWelcome(s.suite, s.keys.joinerSecret, makePSKSecret(s.suite, psks), gi)
	for i, kp := range joiners {
		gs := &GroupSecrets{JoinerSecret: s.keys.joinerSecret, PathSecret: pathSecrets[i], PSKs: pskIDs}
		if err := wl.encryptFor(kp, gs); err != nil {
			return nil, err
		}
	}
	return wl, nil
}

func (s *State) handleCommit(ac *AuthenticatedContent, cachedState *State) (*State, error) {
	content := &ac.Content
	var sender *LeafIndex
	switch content.Sender.Type {
	case SenderTypeMember:
		l := LeafIndex(content.Sender.Index)
		sender = &l
	case SenderTypeNewMemberCommit:
	default:
		return nil, errors.New("mls: invalid commit sender type")
	}
	if sender != nil && *sender == s.index {
		if cachedState == nil {
			return nil, errors.New("mls: handle own commits with caching")
		}
		if !bytes.Equal(cachedState.groupID, s.groupID) || cachedState.epoch != s.epoch+1 || cachedState.index != s.index {
			return nil, errors.New("mls: invalid successor state")
		}
		return cachedState, nil
	}
	commit := content.Commit
	proposals, err := s.resolveProposals(commit.Proposals, sender)
	if err != nil {
		return nil, err
	}
	ar, err := s.apply(proposals)
	if err != nil {
		return nil, err
	}
	external := false
	switch {
	case sender == nil && s.validExternalCommit(proposals):
		external = true
	case sender != nil && s.validNormal(proposals, *sender):
	default:
		return nil, errors.New("mls: invalid proposal list")
	}
	var forceInit []byte
	var senderLoc LeafIndex
	if !external {
		senderLoc = *sender
	} else {
		senderLoc = ar.tree.allocateLeaf()
		var kem []byte
		for _, c := range proposals {
			if c.Proposal.Type == ProposalTypeExternalInit {
				kem = c.Proposal.KEMOutput
			}
		}
		if kem == nil || commit.Path == nil {
			return nil, errors.New("mls: invalid external commit")
		}
		forceInit, err = s.receiveExternalInit(kem)
		if err != nil {
			return nil, err
		}
	}
	if pathRequired(proposals) && commit.Path == nil {
		return nil, errors.New("mls: path required but not present")
	}
	var decryptNode *NodeIndex
	var encryptedSecret *HPKECiphertext
	if commit.Path != nil {
		path := commit.Path
		if !s.validLeafNode(&path.LeafNode, LeafNodeSourceCommit, &senderLoc) {
			return nil, errors.New("mls: commit path has invalid leaf node")
		}
		if !ar.tree.parentHashValidPath(senderLoc, path) {
			return nil, errors.New("mls: commit path has invalid parent hash")
		}
		if err := ar.tree.merge(senderLoc, path); err != nil {
			return nil, err
		}
		coords, err := ar.tree.decapCoords(s.index, senderLoc, ar.joiners, s.treePriv)
		if err != nil {
			return nil, err
		}
		if coords.ancestorNodeIndex >= len(path.Nodes) || coords.resolutionNodeIndex >= len(path.Nodes[coords.ancestorNodeIndex].EncryptedPathSecret) {
			return nil, errors.New("mls: malformed update path")
		}
		n := coords.resolutionNode
		decryptNode = &n
		encryptedSecret = &path.Nodes[coords.ancestorNodeIndex].EncryptedPathSecret[coords.resolutionNodeIndex]
	}
	confirmed := s.transcript.newConfirmed(ac.confirmedTranscriptHashInput())
	return s.ratchet(ar.tree, senderLoc, decryptNode, encryptedSecret, ar.extensions, ar.psks, forceInit, confirmed, ac.Auth.ConfirmationTag)
}

func (s *State) receiveExternalInit(kemOutput []byte) ([]byte, error) {
	priv, err := DeriveHPKEPrivateKey(s.keys.externalSecret)
	if err != nil {
		return nil, err
	}
	ctx, err := hpkeSetupBaseR(kemOutput, priv.key, nil)
	if err != nil {
		return nil, err
	}
	return ctx.export([]byte("MLS 1.0 external init secret"), s.suite.SecretSize()), nil
}

func (s *State) ratchet(tree *RatchetTree, committer LeafIndex, decryptNode *NodeIndex, encryptedSecret *HPKECiphertext, exts ExtensionList, psks []PSKWithSecret, forceInit, confirmed, confirmationTag []byte) (*State, error) {
	priv := s.treePriv.clone()
	priv.truncate(tree.size)
	myLeaf := tree.LeafNode(s.index)
	if myLeaf == nil {
		return nil, errors.New("mls: this member was removed")
	}
	myPriv, err := priv.privateKey(s.index.Node())
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(myLeaf.EncryptionKey, myPriv.PublicKey()) {
		return nil, errors.New("mls: self-update without cached update")
	}
	hasPath := decryptNode != nil && encryptedSecret != nil
	if hasPath {
		ctx := GroupContext{
			CipherSuite:             s.suite,
			GroupID:                 s.groupID,
			Epoch:                   s.epoch + 1,
			TreeHash:                tree.rootHash(),
			ConfirmedTranscriptHash: s.transcript.confirmed,
			Extensions:              exts,
		}
		if err := priv.decap(committer, tree, ctx.Bytes(), *decryptNode, encryptedSecret); err != nil {
			return nil, err
		}
	}
	next := s.successor(s.index, tree, priv, exts, confirmed, hasPath, psks, forceInit)
	if !bytesEqual(next.keys.confirmationTag, confirmationTag) {
		return nil, errors.New("mls: confirmation failed to verify")
	}
	return next, nil
}

func (s *State) successor(index LeafIndex, tree *RatchetTree, priv *treePrivateKey, exts ExtensionList, confirmed []byte, hasPath bool, psks []PSKWithSecret, forceInit []byte) *State {
	next := s.Clone()
	next.epoch++
	next.index = index
	next.tree = tree
	next.treePriv = priv
	next.extensions = exts
	next.pending = nil
	next.resumptionPSKs[epochRef{string(s.groupID), s.epoch}] = s.keys.resumptionPSK
	commitSecret := s.suite.Zero()
	if hasPath {
		commitSecret = priv.updateSecret
	}
	next.transcript.confirmed = confirmed
	ctx := next.GroupContext()
	next.keys = s.keys.next(commitSecret, makePSKSecret(s.suite, psks), forceInit, confirmed, ctx.Bytes())
	next.transcript.updateInterim(next.keys.confirmationTag)
	return next
}

// String describes the state for debugging.
func (s *State) String() string {
	return fmt.Sprintf("mls.State{epoch=%d index=%d leaves=%d}", s.epoch, s.index, s.tree.size)
}

// NewExternalProposal builds a PublicMessage proposal signed by an external
// sender (as the DAVE voice gateway does).
func NewExternalProposal(groupID []byte, epoch uint64, senderIndex uint32, p *Proposal, key *SignaturePrivateKey) (*MLSMessage, error) {
	content := FramedContent{
		GroupID:     groupID,
		Epoch:       epoch,
		Sender:      Sender{Type: SenderTypeExternal, Index: senderIndex},
		ContentType: ContentTypeProposal,
		Proposal:    p,
	}
	ac, err := signAuthenticatedContent(WireFormatPublicMessage, content, key, nil)
	if err != nil {
		return nil, err
	}
	return &MLSMessage{WireFormat: WireFormatPublicMessage, Public: &PublicMessage{Content: ac.Content, Auth: ac.Auth}}, nil
}
