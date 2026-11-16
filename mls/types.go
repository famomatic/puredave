package mls

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/famomatic/puredave/internal/tls"
)

// Credential types.
const (
	CredentialTypeBasic uint16 = 1
	CredentialTypeX509  uint16 = 2
)

// Extension types.
const (
	ExtensionApplicationID        uint16 = 1
	ExtensionRatchetTree          uint16 = 2
	ExtensionRequiredCapabilities uint16 = 3
	ExtensionExternalPub          uint16 = 4
	ExtensionExternalSenders      uint16 = 5
)

// Proposal types.
const (
	ProposalTypeAdd                    uint16 = 1
	ProposalTypeUpdate                 uint16 = 2
	ProposalTypeRemove                 uint16 = 3
	ProposalTypePSK                    uint16 = 4
	ProposalTypeReInit                 uint16 = 5
	ProposalTypeExternalInit           uint16 = 6
	ProposalTypeGroupContextExtensions uint16 = 7
)

// LeafNodeSource values.
type LeafNodeSource uint8

// Leaf node sources.
const (
	LeafNodeSourceKeyPackage LeafNodeSource = 1
	LeafNodeSourceUpdate     LeafNodeSource = 2
	LeafNodeSourceCommit     LeafNodeSource = 3
)

var errMalformed = errors.New("mls: malformed message")

func writeU16s(w *tls.Writer, v []uint16) {
	w.Vector(func(w *tls.Writer) {
		for _, x := range v {
			w.U16(x)
		}
	})
}

func readU16s(r *tls.Reader) []uint16 {
	var out []uint16
	r.VectorEach(func(r *tls.Reader) { out = append(out, r.U16()) })
	return out
}

// Credential is an MLS Credential.
type Credential struct {
	Type         uint16
	Identity     []byte   // basic
	Certificates [][]byte // x509
}

// NewBasicCredential returns a basic credential with the given identity.
func NewBasicCredential(identity []byte) Credential {
	return Credential{Type: CredentialTypeBasic, Identity: append([]byte{}, identity...)}
}

func (c *Credential) marshal(w *tls.Writer) {
	w.U16(c.Type)
	switch c.Type {
	case CredentialTypeBasic:
		w.Opaque(c.Identity)
	case CredentialTypeX509:
		w.Vector(func(w *tls.Writer) {
			for _, cert := range c.Certificates {
				w.Opaque(cert)
			}
		})
	default:
		w.SetErr(fmt.Errorf("mls: cannot encode credential type %d", c.Type))
	}
}

func (c *Credential) unmarshal(r *tls.Reader) {
	c.Type = r.U16()
	switch c.Type {
	case CredentialTypeBasic:
		c.Identity = r.Opaque()
	case CredentialTypeX509:
		r.VectorEach(func(r *tls.Reader) { c.Certificates = append(c.Certificates, r.Opaque()) })
	default:
		r.SetErr(fmt.Errorf("mls: unsupported credential type %d", c.Type))
	}
}

// Equal reports whether two credentials are identical.
func (c *Credential) Equal(o *Credential) bool {
	return bytes.Equal(marshalOf(c.marshal), marshalOf(o.marshal))
}

// Capabilities is the MLS Capabilities struct.
type Capabilities struct {
	Versions     []uint16
	CipherSuites []uint16
	Extensions   []uint16
	Proposals    []uint16
	Credentials  []uint16
}

func (c *Capabilities) marshal(w *tls.Writer) {
	writeU16s(w, c.Versions)
	writeU16s(w, c.CipherSuites)
	writeU16s(w, c.Extensions)
	writeU16s(w, c.Proposals)
	writeU16s(w, c.Credentials)
}

func (c *Capabilities) unmarshal(r *tls.Reader) {
	c.Versions = readU16s(r)
	c.CipherSuites = readU16s(r)
	c.Extensions = readU16s(r)
	c.Proposals = readU16s(r)
	c.Credentials = readU16s(r)
}

func containsU16(list []uint16, v uint16) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// defaultExtensionType reports whether an extension type is one every
// implementation must support (RFC 9420 Section 7.2).
func defaultExtensionType(t uint16) bool {
	return t >= ExtensionApplicationID && t <= ExtensionExternalSenders
}

// SupportsExtensions reports whether all non-default extension types are
// listed in the capabilities.
func (c *Capabilities) SupportsExtensions(exts ExtensionList) bool {
	for _, e := range exts {
		if !defaultExtensionType(e.Type) && !containsU16(c.Extensions, e.Type) {
			return false
		}
	}
	return true
}

// SupportsCredential reports whether the credential type is listed.
func (c *Capabilities) SupportsCredential(t uint16) bool { return containsU16(c.Credentials, t) }

// Lifetime is the MLS Lifetime struct.
type Lifetime struct {
	NotBefore uint64
	NotAfter  uint64
}

// DefaultLifetime spans all time, as required by DAVE.
func DefaultLifetime() Lifetime { return Lifetime{0, ^uint64(0)} }

// Extension is an MLS extension.
type Extension struct {
	Type uint16
	Data []byte
}

// ExtensionList is a list of extensions.
type ExtensionList []Extension

func (l ExtensionList) marshal(w *tls.Writer) {
	w.Vector(func(w *tls.Writer) {
		for _, e := range l {
			w.U16(e.Type)
			w.Opaque(e.Data)
		}
	})
}

func (l *ExtensionList) unmarshal(r *tls.Reader) {
	var out ExtensionList
	seen := map[uint16]bool{}
	r.VectorEach(func(r *tls.Reader) {
		e := Extension{Type: r.U16(), Data: r.Opaque()}
		if seen[e.Type] {
			r.SetErr(fmt.Errorf("mls: duplicate extension %d", e.Type))
		}
		seen[e.Type] = true
		out = append(out, e)
	})
	*l = out
}

// Find returns the data of the extension of the given type.
func (l ExtensionList) Find(t uint16) ([]byte, bool) {
	for _, e := range l {
		if e.Type == t {
			return e.Data, true
		}
	}
	return nil, false
}

// With returns a copy of l with the extension of type t set to data.
func (l ExtensionList) With(t uint16, data []byte) ExtensionList {
	out := append(ExtensionList{}, l...)
	for i := range out {
		if out[i].Type == t {
			out[i].Data = data
			return out
		}
	}
	return append(out, Extension{Type: t, Data: data})
}

// ExternalSender is an entry of the external_senders extension.
type ExternalSender struct {
	SignatureKey SignaturePublicKey
	Credential   Credential
}

func (e *ExternalSender) marshal(w *tls.Writer) {
	w.Opaque(e.SignatureKey)
	e.Credential.marshal(w)
}

func (e *ExternalSender) unmarshal(r *tls.Reader) {
	e.SignatureKey = r.Opaque()
	e.Credential.unmarshal(r)
}

// MarshalBinary encodes the ExternalSender.
func (e *ExternalSender) MarshalBinary() ([]byte, error) { return finish(e.marshal) }

// UnmarshalExternalSender decodes an ExternalSender.
func UnmarshalExternalSender(b []byte) (*ExternalSender, error) {
	e := &ExternalSender{}
	if err := decode(b, e.unmarshal); err != nil {
		return nil, err
	}
	return e, nil
}

// Equal reports whether two external senders are identical.
func (e *ExternalSender) Equal(o *ExternalSender) bool {
	return bytes.Equal(e.SignatureKey, o.SignatureKey) && e.Credential.Equal(&o.Credential)
}

// MarshalExternalSenders encodes the external_senders extension body.
func MarshalExternalSenders(senders []ExternalSender) []byte {
	return marshalOf(func(w *tls.Writer) {
		w.Vector(func(w *tls.Writer) {
			for i := range senders {
				senders[i].marshal(w)
			}
		})
	})
}

// UnmarshalExternalSenders decodes the external_senders extension body.
func UnmarshalExternalSenders(b []byte) ([]ExternalSender, error) {
	var out []ExternalSender
	err := decode(b, func(r *tls.Reader) {
		r.VectorEach(func(r *tls.Reader) {
			var e ExternalSender
			e.unmarshal(r)
			out = append(out, e)
		})
	})
	return out, err
}

// LeafNode is an MLS LeafNode.
type LeafNode struct {
	EncryptionKey HPKEPublicKey
	SignatureKey  SignaturePublicKey
	Credential    Credential
	Capabilities  Capabilities
	Source        LeafNodeSource
	Lifetime      Lifetime // key_package source
	ParentHash    []byte   // commit source
	Extensions    ExtensionList
	Signature     []byte
}

func (l *LeafNode) marshalTBSFields(w *tls.Writer) {
	w.Opaque(l.EncryptionKey)
	w.Opaque(l.SignatureKey)
	l.Credential.marshal(w)
	l.Capabilities.marshal(w)
	w.U8(uint8(l.Source))
	switch l.Source {
	case LeafNodeSourceKeyPackage:
		w.U64(l.Lifetime.NotBefore)
		w.U64(l.Lifetime.NotAfter)
	case LeafNodeSourceUpdate:
	case LeafNodeSourceCommit:
		w.Opaque(l.ParentHash)
	default:
		w.SetErr(fmt.Errorf("mls: invalid leaf node source %d", l.Source))
	}
	l.Extensions.marshal(w)
}

func (l *LeafNode) marshal(w *tls.Writer) {
	l.marshalTBSFields(w)
	w.Opaque(l.Signature)
}

func (l *LeafNode) unmarshal(r *tls.Reader) {
	l.EncryptionKey = r.Opaque()
	l.SignatureKey = r.Opaque()
	l.Credential.unmarshal(r)
	l.Capabilities.unmarshal(r)
	l.Source = LeafNodeSource(r.U8())
	switch l.Source {
	case LeafNodeSourceKeyPackage:
		l.Lifetime.NotBefore = r.U64()
		l.Lifetime.NotAfter = r.U64()
	case LeafNodeSourceUpdate:
	case LeafNodeSourceCommit:
		l.ParentHash = r.Opaque()
	default:
		r.SetErr(fmt.Errorf("mls: invalid leaf node source %d", l.Source))
	}
	l.Extensions.unmarshal(r)
	l.Signature = r.Opaque()
}

func (l *LeafNode) tbs(groupID []byte, index LeafIndex) []byte {
	return marshalOf(func(w *tls.Writer) {
		l.marshalTBSFields(w)
		if l.Source == LeafNodeSourceUpdate || l.Source == LeafNodeSourceCommit {
			w.Opaque(groupID)
			w.U32(uint32(index))
		}
	})
}

// Sign signs the leaf node. groupID and index are used for update and
// commit sources.
func (l *LeafNode) Sign(key *SignaturePrivateKey, groupID []byte, index LeafIndex) error {
	sig, err := key.SignWithLabel("LeafNodeTBS", l.tbs(groupID, index))
	if err != nil {
		return err
	}
	l.Signature = sig
	return nil
}

// Verify verifies the leaf node signature.
func (l *LeafNode) Verify(groupID []byte, index LeafIndex) bool {
	return l.SignatureKey.VerifyWithLabel("LeafNodeTBS", l.tbs(groupID, index), l.Signature)
}

// Bytes returns the encoded leaf node.
func (l *LeafNode) Bytes() []byte { return marshalOf(l.marshal) }

// Equal reports whether two leaf nodes are identical.
func (l *LeafNode) Equal(o *LeafNode) bool { return bytes.Equal(l.Bytes(), o.Bytes()) }

// Clone returns a deep copy.
func (l *LeafNode) Clone() *LeafNode {
	c := &LeafNode{}
	if err := decode(l.Bytes(), c.unmarshal); err != nil {
		panic(err)
	}
	return c
}

// SupportsOwnExtensions reports whether the leaf lists its own extensions.
func (l *LeafNode) SupportsOwnExtensions() bool {
	return l.Capabilities.SupportsExtensions(l.Extensions)
}

// KeyPackage is an MLS KeyPackage.
type KeyPackage struct {
	Version     uint16
	CipherSuite CipherSuite
	InitKey     HPKEPublicKey
	LeafNode    LeafNode
	Extensions  ExtensionList
	Signature   []byte
}

func (k *KeyPackage) marshalTBS(w *tls.Writer) {
	w.U16(k.Version)
	w.U16(uint16(k.CipherSuite))
	w.Opaque(k.InitKey)
	k.LeafNode.marshal(w)
	k.Extensions.marshal(w)
}

func (k *KeyPackage) marshal(w *tls.Writer) {
	k.marshalTBS(w)
	w.Opaque(k.Signature)
}

func (k *KeyPackage) unmarshal(r *tls.Reader) {
	k.Version = r.U16()
	k.CipherSuite = CipherSuite(r.U16())
	k.InitKey = r.Opaque()
	k.LeafNode.unmarshal(r)
	k.Extensions.unmarshal(r)
	k.Signature = r.Opaque()
}

// Sign signs the key package.
func (k *KeyPackage) Sign(key *SignaturePrivateKey) error {
	sig, err := key.SignWithLabel("KeyPackageTBS", marshalOf(k.marshalTBS))
	if err != nil {
		return err
	}
	k.Signature = sig
	return nil
}

// Verify verifies the key package and leaf node signatures.
func (k *KeyPackage) Verify() bool {
	if k.LeafNode.Source != LeafNodeSourceKeyPackage {
		return false
	}
	if !k.LeafNode.Verify(nil, 0) {
		return false
	}
	return k.LeafNode.SignatureKey.VerifyWithLabel("KeyPackageTBS", marshalOf(k.marshalTBS), k.Signature)
}

// Bytes returns the encoded key package.
func (k *KeyPackage) Bytes() []byte { return marshalOf(k.marshal) }

// Ref returns the KeyPackageRef.
func (k *KeyPackage) Ref() []byte {
	return k.CipherSuite.RefHash("MLS 1.0 KeyPackage Reference", k.Bytes())
}

// MarshalBinary encodes the key package.
func (k *KeyPackage) MarshalBinary() ([]byte, error) { return finish(k.marshal) }

// UnmarshalKeyPackage decodes a KeyPackage.
func UnmarshalKeyPackage(b []byte) (*KeyPackage, error) {
	k := &KeyPackage{}
	if err := decode(b, k.unmarshal); err != nil {
		return nil, err
	}
	return k, nil
}

// ParentNode is an MLS ParentNode.
type ParentNode struct {
	EncryptionKey  HPKEPublicKey
	ParentHash     []byte
	UnmergedLeaves []LeafIndex
}

func (p *ParentNode) marshal(w *tls.Writer) {
	w.Opaque(p.EncryptionKey)
	w.Opaque(p.ParentHash)
	w.Vector(func(w *tls.Writer) {
		for _, l := range p.UnmergedLeaves {
			w.U32(uint32(l))
		}
	})
}

func (p *ParentNode) unmarshal(r *tls.Reader) {
	p.EncryptionKey = r.Opaque()
	p.ParentHash = r.Opaque()
	p.UnmergedLeaves = nil
	r.VectorEach(func(r *tls.Reader) { p.UnmergedLeaves = append(p.UnmergedLeaves, LeafIndex(r.U32())) })
}

func (p *ParentNode) clone() *ParentNode {
	return &ParentNode{
		EncryptionKey:  append(HPKEPublicKey{}, p.EncryptionKey...),
		ParentHash:     append([]byte{}, p.ParentHash...),
		UnmergedLeaves: append([]LeafIndex{}, p.UnmergedLeaves...),
	}
}

// Node is a ratchet tree node: exactly one of Leaf or Parent is set.
type Node struct {
	Leaf   *LeafNode
	Parent *ParentNode
}

const (
	nodeTypeLeaf   = 1
	nodeTypeParent = 2
)

func (n *Node) marshal(w *tls.Writer) {
	if n.Leaf != nil {
		w.U8(nodeTypeLeaf)
		n.Leaf.marshal(w)
	} else {
		w.U8(nodeTypeParent)
		n.Parent.marshal(w)
	}
}

func (n *Node) unmarshal(r *tls.Reader) {
	switch r.U8() {
	case nodeTypeLeaf:
		n.Leaf = &LeafNode{}
		n.Leaf.unmarshal(r)
	case nodeTypeParent:
		n.Parent = &ParentNode{}
		n.Parent.unmarshal(r)
	default:
		r.SetErr(errMalformed)
	}
}

// EncryptionKey returns the node's HPKE public key.
func (n *Node) EncryptionKey() HPKEPublicKey {
	if n.Leaf != nil {
		return n.Leaf.EncryptionKey
	}
	return n.Parent.EncryptionKey
}

func (n *Node) parentHash() []byte {
	if n.Leaf != nil {
		if n.Leaf.Source == LeafNodeSourceCommit {
			return n.Leaf.ParentHash
		}
		return nil
	}
	return n.Parent.ParentHash
}

func (n *Node) clone() *Node {
	if n == nil {
		return nil
	}
	if n.Leaf != nil {
		return &Node{Leaf: n.Leaf.Clone()}
	}
	return &Node{Parent: n.Parent.clone()}
}

func marshalOf(fn func(w *tls.Writer)) []byte {
	w := tls.NewWriter()
	fn(w)
	b, err := w.Finish()
	if err != nil {
		panic(err)
	}
	return b
}

func finish(fn func(w *tls.Writer)) ([]byte, error) {
	w := tls.NewWriter()
	fn(w)
	return w.Finish()
}

func decode(b []byte, fn func(r *tls.Reader)) error {
	r := tls.NewReader(b)
	fn(r)
	return r.Done()
}
