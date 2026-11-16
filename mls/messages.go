package mls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/famomatic/puredave/internal/tls"
)

// PSK types.
const (
	PSKTypeExternal   uint8 = 1
	PSKTypeResumption uint8 = 2
)

// PreSharedKeyID is the MLS PreSharedKeyID struct.
type PreSharedKeyID struct {
	Type uint8
	// external
	PSKID []byte
	// resumption
	Usage      uint8
	PSKGroupID []byte
	PSKEpoch   uint64

	Nonce []byte
}

func (p *PreSharedKeyID) marshal(w *tls.Writer) {
	w.U8(p.Type)
	switch p.Type {
	case PSKTypeExternal:
		w.Opaque(p.PSKID)
	case PSKTypeResumption:
		w.U8(p.Usage)
		w.Opaque(p.PSKGroupID)
		w.U64(p.PSKEpoch)
	default:
		w.SetErr(errMalformed)
	}
	w.Opaque(p.Nonce)
}

func (p *PreSharedKeyID) unmarshal(r *tls.Reader) {
	p.Type = r.U8()
	switch p.Type {
	case PSKTypeExternal:
		p.PSKID = r.Opaque()
	case PSKTypeResumption:
		p.Usage = r.U8()
		p.PSKGroupID = r.Opaque()
		p.PSKEpoch = r.U64()
	default:
		r.SetErr(errMalformed)
	}
	p.Nonce = r.Opaque()
}

// Proposal is an MLS Proposal. Exactly the field matching Type is used.
type Proposal struct {
	Type uint16

	KeyPackage *KeyPackage     // add
	LeafNode   *LeafNode       // update
	Removed    LeafIndex       // remove
	PSK        *PreSharedKeyID // psk

	// reinit
	ReInitGroupID     []byte
	ReInitVersion     uint16
	ReInitCipherSuite CipherSuite
	ReInitExtensions  ExtensionList

	KEMOutput []byte // external_init

	Extensions ExtensionList // group_context_extensions
}

func (p *Proposal) marshal(w *tls.Writer) {
	w.U16(p.Type)
	switch p.Type {
	case ProposalTypeAdd:
		p.KeyPackage.marshal(w)
	case ProposalTypeUpdate:
		p.LeafNode.marshal(w)
	case ProposalTypeRemove:
		w.U32(uint32(p.Removed))
	case ProposalTypePSK:
		p.PSK.marshal(w)
	case ProposalTypeReInit:
		w.Opaque(p.ReInitGroupID)
		w.U16(p.ReInitVersion)
		w.U16(uint16(p.ReInitCipherSuite))
		p.ReInitExtensions.marshal(w)
	case ProposalTypeExternalInit:
		w.Opaque(p.KEMOutput)
	case ProposalTypeGroupContextExtensions:
		p.Extensions.marshal(w)
	default:
		w.SetErr(fmt.Errorf("mls: unsupported proposal type %d", p.Type))
	}
}

func (p *Proposal) unmarshal(r *tls.Reader) {
	p.Type = r.U16()
	switch p.Type {
	case ProposalTypeAdd:
		p.KeyPackage = &KeyPackage{}
		p.KeyPackage.unmarshal(r)
	case ProposalTypeUpdate:
		p.LeafNode = &LeafNode{}
		p.LeafNode.unmarshal(r)
	case ProposalTypeRemove:
		p.Removed = LeafIndex(r.U32())
	case ProposalTypePSK:
		p.PSK = &PreSharedKeyID{}
		p.PSK.unmarshal(r)
	case ProposalTypeReInit:
		p.ReInitGroupID = r.Opaque()
		p.ReInitVersion = r.U16()
		p.ReInitCipherSuite = CipherSuite(r.U16())
		p.ReInitExtensions.unmarshal(r)
	case ProposalTypeExternalInit:
		p.KEMOutput = r.Opaque()
	case ProposalTypeGroupContextExtensions:
		p.Extensions.unmarshal(r)
	default:
		r.SetErr(fmt.Errorf("mls: unsupported proposal type %d", p.Type))
	}
}

// ProposalOrRef types.
const (
	proposalOrRefProposal  = 1
	proposalOrRefReference = 2
)

// ProposalOrRef is either an inline proposal or a proposal reference.
type ProposalOrRef struct {
	Proposal *Proposal
	Ref      []byte
}

func (p *ProposalOrRef) marshal(w *tls.Writer) {
	if p.Proposal != nil {
		w.U8(proposalOrRefProposal)
		p.Proposal.marshal(w)
	} else {
		w.U8(proposalOrRefReference)
		w.Opaque(p.Ref)
	}
}

func (p *ProposalOrRef) unmarshal(r *tls.Reader) {
	switch r.U8() {
	case proposalOrRefProposal:
		p.Proposal = &Proposal{}
		p.Proposal.unmarshal(r)
	case proposalOrRefReference:
		p.Ref = r.Opaque()
	default:
		r.SetErr(errMalformed)
	}
}

// UpdatePathNode is an MLS UpdatePathNode.
type UpdatePathNode struct {
	EncryptionKey       HPKEPublicKey
	EncryptedPathSecret []HPKECiphertext
}

// UpdatePath is an MLS UpdatePath.
type UpdatePath struct {
	LeafNode LeafNode
	Nodes    []UpdatePathNode
}

func (u *UpdatePath) marshal(w *tls.Writer) {
	u.LeafNode.marshal(w)
	w.Vector(func(w *tls.Writer) {
		for i := range u.Nodes {
			n := &u.Nodes[i]
			w.Opaque(n.EncryptionKey)
			w.Vector(func(w *tls.Writer) {
				for j := range n.EncryptedPathSecret {
					n.EncryptedPathSecret[j].marshal(w)
				}
			})
		}
	})
}

func (u *UpdatePath) unmarshal(r *tls.Reader) {
	u.LeafNode.unmarshal(r)
	r.VectorEach(func(r *tls.Reader) {
		var n UpdatePathNode
		n.EncryptionKey = r.Opaque()
		r.VectorEach(func(r *tls.Reader) {
			var ct HPKECiphertext
			ct.unmarshal(r)
			n.EncryptedPathSecret = append(n.EncryptedPathSecret, ct)
		})
		u.Nodes = append(u.Nodes, n)
	})
}

// Commit is an MLS Commit.
type Commit struct {
	Proposals []ProposalOrRef
	Path      *UpdatePath
}

func (c *Commit) marshal(w *tls.Writer) {
	w.Vector(func(w *tls.Writer) {
		for i := range c.Proposals {
			c.Proposals[i].marshal(w)
		}
	})
	w.Optional(c.Path != nil, func(w *tls.Writer) { c.Path.marshal(w) })
}

func (c *Commit) unmarshal(r *tls.Reader) {
	r.VectorEach(func(r *tls.Reader) {
		var p ProposalOrRef
		p.unmarshal(r)
		c.Proposals = append(c.Proposals, p)
	})
	r.Optional(func(r *tls.Reader) {
		c.Path = &UpdatePath{}
		c.Path.unmarshal(r)
	})
}

// SenderType values.
type SenderType uint8

// Sender types.
const (
	SenderTypeMember            SenderType = 1
	SenderTypeExternal          SenderType = 2
	SenderTypeNewMemberProposal SenderType = 3
	SenderTypeNewMemberCommit   SenderType = 4
)

// Sender is an MLS Sender.
type Sender struct {
	Type  SenderType
	Index uint32 // leaf index (member) or sender index (external)
}

func (s *Sender) marshal(w *tls.Writer) {
	w.U8(uint8(s.Type))
	switch s.Type {
	case SenderTypeMember, SenderTypeExternal:
		w.U32(s.Index)
	case SenderTypeNewMemberProposal, SenderTypeNewMemberCommit:
	default:
		w.SetErr(errMalformed)
	}
}

func (s *Sender) unmarshal(r *tls.Reader) {
	s.Type = SenderType(r.U8())
	switch s.Type {
	case SenderTypeMember, SenderTypeExternal:
		s.Index = r.U32()
	case SenderTypeNewMemberProposal, SenderTypeNewMemberCommit:
	default:
		r.SetErr(errMalformed)
	}
}

// WireFormat values.
type WireFormat uint16

// Wire formats.
const (
	WireFormatPublicMessage  WireFormat = 1
	WireFormatPrivateMessage WireFormat = 2
	WireFormatWelcome        WireFormat = 3
	WireFormatGroupInfo      WireFormat = 4
	WireFormatKeyPackage     WireFormat = 5
)

// ContentType values.
type ContentType uint8

// Content types.
const (
	ContentTypeApplication ContentType = 1
	ContentTypeProposal    ContentType = 2
	ContentTypeCommit      ContentType = 3
)

// FramedContent is the MLS FramedContent struct.
type FramedContent struct {
	GroupID           []byte
	Epoch             uint64
	Sender            Sender
	AuthenticatedData []byte
	ContentType       ContentType

	ApplicationData []byte
	Proposal        *Proposal
	Commit          *Commit
}

func (c *FramedContent) marshal(w *tls.Writer) {
	w.Opaque(c.GroupID)
	w.U64(c.Epoch)
	c.Sender.marshal(w)
	w.Opaque(c.AuthenticatedData)
	w.U8(uint8(c.ContentType))
	switch c.ContentType {
	case ContentTypeApplication:
		w.Opaque(c.ApplicationData)
	case ContentTypeProposal:
		c.Proposal.marshal(w)
	case ContentTypeCommit:
		c.Commit.marshal(w)
	default:
		w.SetErr(errMalformed)
	}
}

func (c *FramedContent) unmarshal(r *tls.Reader) {
	c.GroupID = r.Opaque()
	c.Epoch = r.U64()
	c.Sender.unmarshal(r)
	c.AuthenticatedData = r.Opaque()
	c.ContentType = ContentType(r.U8())
	switch c.ContentType {
	case ContentTypeApplication:
		c.ApplicationData = r.Opaque()
	case ContentTypeProposal:
		c.Proposal = &Proposal{}
		c.Proposal.unmarshal(r)
	case ContentTypeCommit:
		c.Commit = &Commit{}
		c.Commit.unmarshal(r)
	default:
		r.SetErr(errMalformed)
	}
}

// FramedContentAuthData is the MLS FramedContentAuthData struct.
type FramedContentAuthData struct {
	Signature       []byte
	ConfirmationTag []byte // commit only
}

func (a *FramedContentAuthData) marshal(w *tls.Writer, ct ContentType) {
	w.Opaque(a.Signature)
	if ct == ContentTypeCommit {
		w.Opaque(a.ConfirmationTag)
	}
}

func (a *FramedContentAuthData) unmarshal(r *tls.Reader, ct ContentType) {
	a.Signature = r.Opaque()
	if ct == ContentTypeCommit {
		a.ConfirmationTag = r.Opaque()
	}
}

// AuthenticatedContent is the MLS AuthenticatedContent struct.
type AuthenticatedContent struct {
	WireFormat WireFormat
	Content    FramedContent
	Auth       FramedContentAuthData
}

func (a *AuthenticatedContent) marshal(w *tls.Writer) {
	w.U16(uint16(a.WireFormat))
	a.Content.marshal(w)
	a.Auth.marshal(w, a.Content.ContentType)
}

func (a *AuthenticatedContent) unmarshal(r *tls.Reader) {
	a.WireFormat = WireFormat(r.U16())
	a.Content.unmarshal(r)
	a.Auth.unmarshal(r, a.Content.ContentType)
}

// Bytes returns the encoded AuthenticatedContent.
func (a *AuthenticatedContent) Bytes() []byte { return marshalOf(a.marshal) }

func framedContentTBS(wf WireFormat, content *FramedContent, ctx *GroupContext) []byte {
	return marshalOf(func(w *tls.Writer) {
		w.U16(ProtocolVersionMLS10)
		w.U16(uint16(wf))
		content.marshal(w)
		switch content.Sender.Type {
		case SenderTypeMember, SenderTypeNewMemberCommit:
			ctx.marshal(w)
		}
	})
}

// signAuthenticatedContent signs content for the given wire format.
func signAuthenticatedContent(wf WireFormat, content FramedContent, key *SignaturePrivateKey, ctx *GroupContext) (*AuthenticatedContent, error) {
	sig, err := key.SignWithLabel("FramedContentTBS", framedContentTBS(wf, &content, ctx))
	if err != nil {
		return nil, err
	}
	return &AuthenticatedContent{WireFormat: wf, Content: content, Auth: FramedContentAuthData{Signature: sig}}, nil
}

// VerifySignature verifies the content signature with pub.
func (a *AuthenticatedContent) VerifySignature(pub SignaturePublicKey, ctx *GroupContext) bool {
	return pub.VerifyWithLabel("FramedContentTBS", framedContentTBS(a.WireFormat, &a.Content, ctx), a.Auth.Signature)
}

func (a *AuthenticatedContent) confirmedTranscriptHashInput() []byte {
	return marshalOf(func(w *tls.Writer) {
		w.U16(uint16(a.WireFormat))
		a.Content.marshal(w)
		w.Opaque(a.Auth.Signature)
	})
}

func (a *AuthenticatedContent) tbm(ctx *GroupContext) []byte {
	return marshalOf(func(w *tls.Writer) {
		w.Raw(framedContentTBS(a.WireFormat, &a.Content, ctx))
		a.Auth.marshal(w, a.Content.ContentType)
	})
}

// PublicMessage is the MLS PublicMessage struct.
type PublicMessage struct {
	Content       FramedContent
	Auth          FramedContentAuthData
	MembershipTag []byte
}

func (p *PublicMessage) marshal(w *tls.Writer) {
	p.Content.marshal(w)
	p.Auth.marshal(w, p.Content.ContentType)
	if p.Content.Sender.Type == SenderTypeMember {
		w.Opaque(p.MembershipTag)
	}
}

func (p *PublicMessage) unmarshal(r *tls.Reader) {
	p.Content.unmarshal(r)
	p.Auth.unmarshal(r, p.Content.ContentType)
	if p.Content.Sender.Type == SenderTypeMember {
		p.MembershipTag = r.Opaque()
	}
}

func protectPublic(ac *AuthenticatedContent, suite CipherSuite, membershipKey []byte, ctx *GroupContext) *PublicMessage {
	pm := &PublicMessage{Content: ac.Content, Auth: ac.Auth}
	if ac.Content.Sender.Type == SenderTypeMember {
		pm.MembershipTag = suite.MAC(membershipKey, ac.tbm(ctx))
	}
	return pm
}

func (p *PublicMessage) unprotect(suite CipherSuite, membershipKey []byte, ctx *GroupContext) (*AuthenticatedContent, error) {
	ac := &AuthenticatedContent{WireFormat: WireFormatPublicMessage, Content: p.Content, Auth: p.Auth}
	if p.Content.Sender.Type == SenderTypeMember {
		if !bytesEqual(suite.MAC(membershipKey, ac.tbm(ctx)), p.MembershipTag) {
			return nil, errors.New("mls: membership tag failed to verify")
		}
	}
	return ac, nil
}

// GroupContext is the MLS GroupContext struct.
type GroupContext struct {
	CipherSuite             CipherSuite
	GroupID                 []byte
	Epoch                   uint64
	TreeHash                []byte
	ConfirmedTranscriptHash []byte
	Extensions              ExtensionList
}

func (g *GroupContext) marshal(w *tls.Writer) {
	w.U16(ProtocolVersionMLS10)
	w.U16(uint16(g.CipherSuite))
	w.Opaque(g.GroupID)
	w.U64(g.Epoch)
	w.Opaque(g.TreeHash)
	w.Opaque(g.ConfirmedTranscriptHash)
	g.Extensions.marshal(w)
}

func (g *GroupContext) unmarshal(r *tls.Reader) {
	if v := r.U16(); v != ProtocolVersionMLS10 && r.Err() == nil {
		r.SetErr(fmt.Errorf("mls: unsupported protocol version %d", v))
	}
	g.CipherSuite = CipherSuite(r.U16())
	g.GroupID = r.Opaque()
	g.Epoch = r.U64()
	g.TreeHash = r.Opaque()
	g.ConfirmedTranscriptHash = r.Opaque()
	g.Extensions.unmarshal(r)
}

// Bytes returns the encoded GroupContext.
func (g *GroupContext) Bytes() []byte { return marshalOf(g.marshal) }

// GroupInfo is the MLS GroupInfo struct.
type GroupInfo struct {
	GroupContext    GroupContext
	Extensions      ExtensionList
	ConfirmationTag []byte
	Signer          LeafIndex
	Signature       []byte
}

func (g *GroupInfo) marshalTBS(w *tls.Writer) {
	g.GroupContext.marshal(w)
	g.Extensions.marshal(w)
	w.Opaque(g.ConfirmationTag)
	w.U32(uint32(g.Signer))
}

func (g *GroupInfo) marshal(w *tls.Writer) {
	g.marshalTBS(w)
	w.Opaque(g.Signature)
}

func (g *GroupInfo) unmarshal(r *tls.Reader) {
	g.GroupContext.unmarshal(r)
	g.Extensions.unmarshal(r)
	g.ConfirmationTag = r.Opaque()
	g.Signer = LeafIndex(r.U32())
	g.Signature = r.Opaque()
}

func (g *GroupInfo) sign(key *SignaturePrivateKey) error {
	sig, err := key.SignWithLabel("GroupInfoTBS", marshalOf(g.marshalTBS))
	if err != nil {
		return err
	}
	g.Signature = sig
	return nil
}

func (g *GroupInfo) verify(pub SignaturePublicKey) bool {
	return pub.VerifyWithLabel("GroupInfoTBS", marshalOf(g.marshalTBS), g.Signature)
}

// GroupSecrets is the MLS GroupSecrets struct.
type GroupSecrets struct {
	JoinerSecret []byte
	PathSecret   []byte // optional
	PSKs         []PreSharedKeyID
}

func (g *GroupSecrets) marshal(w *tls.Writer) {
	w.Opaque(g.JoinerSecret)
	w.Optional(g.PathSecret != nil, func(w *tls.Writer) { w.Opaque(g.PathSecret) })
	w.Vector(func(w *tls.Writer) {
		for i := range g.PSKs {
			g.PSKs[i].marshal(w)
		}
	})
}

func (g *GroupSecrets) unmarshal(r *tls.Reader) {
	g.JoinerSecret = r.Opaque()
	r.Optional(func(r *tls.Reader) {
		g.PathSecret = r.Opaque()
		if g.PathSecret == nil {
			g.PathSecret = []byte{}
		}
	})
	r.VectorEach(func(r *tls.Reader) {
		var p PreSharedKeyID
		p.unmarshal(r)
		g.PSKs = append(g.PSKs, p)
	})
}

// EncryptedGroupSecrets is the MLS EncryptedGroupSecrets struct.
type EncryptedGroupSecrets struct {
	NewMember             []byte
	EncryptedGroupSecrets HPKECiphertext
}

// Welcome is the MLS Welcome struct.
type Welcome struct {
	CipherSuite        CipherSuite
	Secrets            []EncryptedGroupSecrets
	EncryptedGroupInfo []byte
}

func (wl *Welcome) marshal(w *tls.Writer) {
	w.U16(uint16(wl.CipherSuite))
	w.Vector(func(w *tls.Writer) {
		for i := range wl.Secrets {
			w.Opaque(wl.Secrets[i].NewMember)
			wl.Secrets[i].EncryptedGroupSecrets.marshal(w)
		}
	})
	w.Opaque(wl.EncryptedGroupInfo)
}

func (wl *Welcome) unmarshal(r *tls.Reader) {
	wl.CipherSuite = CipherSuite(r.U16())
	r.VectorEach(func(r *tls.Reader) {
		var s EncryptedGroupSecrets
		s.NewMember = r.Opaque()
		s.EncryptedGroupSecrets.unmarshal(r)
		wl.Secrets = append(wl.Secrets, s)
	})
	wl.EncryptedGroupInfo = r.Opaque()
}

// MarshalBinary encodes the Welcome.
func (wl *Welcome) MarshalBinary() ([]byte, error) { return finish(wl.marshal) }

// UnmarshalWelcome decodes a Welcome (not wrapped in an MLSMessage).
func UnmarshalWelcome(b []byte) (*Welcome, error) {
	wl := &Welcome{}
	if err := decode(b, wl.unmarshal); err != nil {
		return nil, err
	}
	return wl, nil
}

func welcomeKeyNonce(suite CipherSuite, joinerSecret, pskSecret []byte) (key, nonce []byte) {
	welcomeSecret := suite.DeriveSecret(suite.Extract(joinerSecret, pskSecret), "welcome")
	return suite.ExpandWithLabel(welcomeSecret, "key", nil, suite.KeySize()),
		suite.ExpandWithLabel(welcomeSecret, "nonce", nil, suite.NonceSize())
}

func aesGCM(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return gcm
}

func newWelcome(suite CipherSuite, joinerSecret, pskSecret []byte, gi *GroupInfo) *Welcome {
	key, nonce := welcomeKeyNonce(suite, joinerSecret, pskSecret)
	return &Welcome{
		CipherSuite:        suite,
		EncryptedGroupInfo: aesGCM(key).Seal(nil, nonce, marshalOf(gi.marshal), nil),
	}
}

func (wl *Welcome) encryptFor(kp *KeyPackage, gs *GroupSecrets) error {
	ct, err := EncryptWithLabel(kp.InitKey, "Welcome", wl.EncryptedGroupInfo, marshalOf(gs.marshal))
	if err != nil {
		return err
	}
	wl.Secrets = append(wl.Secrets, EncryptedGroupSecrets{NewMember: kp.Ref(), EncryptedGroupSecrets: *ct})
	return nil
}

func (wl *Welcome) find(ref []byte) (int, bool) {
	for i := range wl.Secrets {
		if bytes.Equal(wl.Secrets[i].NewMember, ref) {
			return i, true
		}
	}
	return 0, false
}

func (wl *Welcome) decryptSecrets(i int, initPriv *HPKEPrivateKey) (*GroupSecrets, error) {
	pt, err := initPriv.DecryptWithLabel("Welcome", wl.EncryptedGroupInfo, &wl.Secrets[i].EncryptedGroupSecrets)
	if err != nil {
		return nil, err
	}
	gs := &GroupSecrets{}
	if err := decode(pt, gs.unmarshal); err != nil {
		return nil, err
	}
	return gs, nil
}

func (wl *Welcome) decryptGroupInfo(joinerSecret, pskSecret []byte) (*GroupInfo, error) {
	key, nonce := welcomeKeyNonce(wl.CipherSuite, joinerSecret, pskSecret)
	pt, err := aesGCM(key).Open(nil, nonce, wl.EncryptedGroupInfo, nil)
	if err != nil {
		return nil, errors.New("mls: GroupInfo decryption failure")
	}
	gi := &GroupInfo{}
	if err := decode(pt, gi.unmarshal); err != nil {
		return nil, err
	}
	return gi, nil
}

// MLSMessage is the MLS MLSMessage struct.
type MLSMessage struct {
	WireFormat WireFormat
	Public     *PublicMessage
	Private    []byte // PrivateMessage body, carried opaquely
	Welcome    *Welcome
	GroupInfo  *GroupInfo
	KeyPackage *KeyPackage
}

func (m *MLSMessage) marshal(w *tls.Writer) {
	w.U16(ProtocolVersionMLS10)
	w.U16(uint16(m.WireFormat))
	switch m.WireFormat {
	case WireFormatPublicMessage:
		m.Public.marshal(w)
	case WireFormatWelcome:
		m.Welcome.marshal(w)
	case WireFormatGroupInfo:
		m.GroupInfo.marshal(w)
	case WireFormatKeyPackage:
		m.KeyPackage.marshal(w)
	default:
		w.SetErr(fmt.Errorf("mls: cannot encode wire format %d", m.WireFormat))
	}
}

func (m *MLSMessage) unmarshal(r *tls.Reader) {
	if v := r.U16(); v != ProtocolVersionMLS10 && r.Err() == nil {
		r.SetErr(fmt.Errorf("mls: unsupported protocol version %d", v))
		return
	}
	m.WireFormat = WireFormat(r.U16())
	switch m.WireFormat {
	case WireFormatPublicMessage:
		m.Public = &PublicMessage{}
		m.Public.unmarshal(r)
	case WireFormatWelcome:
		m.Welcome = &Welcome{}
		m.Welcome.unmarshal(r)
	case WireFormatGroupInfo:
		m.GroupInfo = &GroupInfo{}
		m.GroupInfo.unmarshal(r)
	case WireFormatKeyPackage:
		m.KeyPackage = &KeyPackage{}
		m.KeyPackage.unmarshal(r)
	default:
		r.SetErr(fmt.Errorf("mls: unsupported wire format %d", m.WireFormat))
	}
}

// MarshalBinary encodes the message.
func (m *MLSMessage) MarshalBinary() ([]byte, error) { return finish(m.marshal) }

// ReadMLSMessage decodes one MLSMessage from r.
func ReadMLSMessage(r *tls.Reader) *MLSMessage {
	m := &MLSMessage{}
	m.unmarshal(r)
	return m
}

// DecodeMLSMessage decodes one MLSMessage from the start of b and returns
// it with the number of bytes consumed.
func DecodeMLSMessage(b []byte) (*MLSMessage, int, error) {
	r := tls.NewReader(b)
	m := ReadMLSMessage(r)
	if err := r.Err(); err != nil {
		return nil, 0, err
	}
	return m, len(b) - r.Len(), nil
}

// UnmarshalMLSMessage decodes an MLSMessage that spans all of b.
func UnmarshalMLSMessage(b []byte) (*MLSMessage, error) {
	m := &MLSMessage{}
	if err := decode(b, m.unmarshal); err != nil {
		return nil, err
	}
	return m, nil
}

// GroupID returns the group ID of a PublicMessage.
func (m *MLSMessage) GroupID() []byte {
	if m.Public != nil {
		return m.Public.Content.GroupID
	}
	return nil
}

// Epoch returns the epoch of a PublicMessage.
func (m *MLSMessage) Epoch() uint64 {
	if m.Public != nil {
		return m.Public.Content.Epoch
	}
	return 0
}
