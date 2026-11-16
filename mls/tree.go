package mls

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/famomatic/puredave/internal/tls"
)

// RatchetTree is the public state of a TreeKEM ratchet tree
// (mlspp TreeKEMPublicKey).
type RatchetTree struct {
	suite  CipherSuite
	size   uint32 // number of leaves, a power of two (or zero)
	nodes  []*Node
	hashes map[NodeIndex][]byte
}

func newRatchetTree(suite CipherSuite) *RatchetTree {
	return &RatchetTree{suite: suite, hashes: map[NodeIndex][]byte{}}
}

// Size returns the number of leaves.
func (t *RatchetTree) Size() uint32 { return t.size }

func (t *RatchetTree) clone() *RatchetTree {
	c := &RatchetTree{suite: t.suite, size: t.size, nodes: make([]*Node, len(t.nodes)), hashes: make(map[NodeIndex][]byte, len(t.hashes))}
	for i, n := range t.nodes {
		c.nodes[i] = n.clone()
	}
	for k, v := range t.hashes {
		c.hashes[k] = v
	}
	return c
}

func (t *RatchetTree) node(n NodeIndex) *Node {
	if int(n) >= len(t.nodes) {
		return nil
	}
	return t.nodes[n]
}

func (t *RatchetTree) blank(n NodeIndex) bool { return t.node(n) == nil }

// LeafNode returns the leaf node at index, or nil if blank.
func (t *RatchetTree) LeafNode(i LeafIndex) *LeafNode {
	if uint32(i) >= t.size {
		return nil
	}
	n := t.node(i.Node())
	if n == nil {
		return nil
	}
	return n.Leaf
}

// HasLeaf reports whether the leaf is occupied.
func (t *RatchetTree) HasLeaf(i LeafIndex) bool { return t.LeafNode(i) != nil }

// Leaves calls fn for each non-blank leaf, stopping if fn returns false.
func (t *RatchetTree) Leaves(fn func(LeafIndex, *LeafNode) bool) bool {
	for i := LeafIndex(0); uint32(i) < t.size; i++ {
		if l := t.LeafNode(i); l != nil {
			if !fn(i, l) {
				return false
			}
		}
	}
	return true
}

func (t *RatchetTree) anyLeaf(fn func(LeafIndex, *LeafNode) bool) bool {
	found := false
	t.Leaves(func(i LeafIndex, l *LeafNode) bool {
		if fn(i, l) {
			found = true
			return false
		}
		return true
	})
	return found
}

func (t *RatchetTree) parentNode(n NodeIndex) *ParentNode {
	x := t.node(n)
	if x == nil {
		return nil
	}
	return x.Parent
}

func (t *RatchetTree) allocateLeaf() LeafIndex {
	i := LeafIndex(0)
	for uint32(i) < t.size && !t.blank(i.Node()) {
		i++
	}
	if uint32(i) >= t.size {
		if t.size == 0 {
			t.size = 1
		} else {
			t.size *= 2
		}
		for uint32(len(t.nodes)) < NodeCount(t.size) {
			t.nodes = append(t.nodes, nil)
		}
	}
	return i
}

func (t *RatchetTree) encryptionKeyInTree(key HPKEPublicKey, except *LeafIndex) bool {
	return t.anyLeaf(func(i LeafIndex, l *LeafNode) bool {
		return (except == nil || i != *except) && bytes.Equal(l.EncryptionKey, key)
	})
}

func (t *RatchetTree) signatureKeyInTree(key SignaturePublicKey, except *LeafIndex) bool {
	return t.anyLeaf(func(i LeafIndex, l *LeafNode) bool {
		return (except == nil || i != *except) && bytes.Equal(l.SignatureKey, key)
	})
}

// addLeaf inserts the leaf at the leftmost blank position.
func (t *RatchetTree) addLeaf(leaf *LeafNode) (LeafIndex, error) {
	if t.encryptionKeyInTree(leaf.EncryptionKey, nil) {
		return 0, errors.New("mls: duplicate encryption key")
	}
	if t.signatureKeyInTree(leaf.SignatureKey, nil) {
		return 0, errors.New("mls: duplicate signature key")
	}
	i := t.allocateLeaf()
	t.nodes[i.Node()] = &Node{Leaf: leaf.Clone()}
	for _, n := range i.Node().DirectPath(t.size) {
		p := t.parentNode(n)
		if p == nil {
			continue
		}
		at := sort.Search(len(p.UnmergedLeaves), func(k int) bool { return p.UnmergedLeaves[k] > i })
		p.UnmergedLeaves = append(p.UnmergedLeaves, 0)
		copy(p.UnmergedLeaves[at+1:], p.UnmergedLeaves[at:])
		p.UnmergedLeaves[at] = i
	}
	t.clearHashPath(i)
	return i, nil
}

func (t *RatchetTree) updateLeaf(i LeafIndex, leaf *LeafNode) error {
	if t.encryptionKeyInTree(leaf.EncryptionKey, nil) {
		return errors.New("mls: duplicate encryption key")
	}
	if t.signatureKeyInTree(leaf.SignatureKey, &i) {
		return errors.New("mls: duplicate signature key")
	}
	t.blankPath(i)
	t.nodes[i.Node()] = &Node{Leaf: leaf.Clone()}
	t.clearHashPath(i)
	return nil
}

func (t *RatchetTree) blankPath(i LeafIndex) {
	if len(t.nodes) == 0 {
		return
	}
	t.nodes[i.Node()] = nil
	for _, n := range i.Node().DirectPath(t.size) {
		t.nodes[n] = nil
	}
	t.clearHashPath(i)
}

func (t *RatchetTree) clearHashPath(i LeafIndex) {
	delete(t.hashes, i.Node())
	for _, n := range i.Node().DirectPath(t.size) {
		delete(t.hashes, n)
	}
}

// truncate removes trailing blank leaves, halving the tree as possible.
func (t *RatchetTree) truncate() {
	if t.size == 0 {
		return
	}
	i := LeafIndex(t.size - 1)
	for ; i > 0; i-- {
		if !t.blank(i.Node()) {
			break
		}
		t.clearHashPath(i)
	}
	if t.blank(i.Node()) {
		// mlspp clears the node map but keeps the size.
		for k := range t.nodes {
			t.nodes[k] = nil
		}
		return
	}
	for t.size/2 > uint32(i) {
		t.size /= 2
	}
	t.nodes = t.nodes[:NodeCount(t.size)]
	for k := range t.hashes {
		if uint32(k) >= NodeCount(t.size) {
			delete(t.hashes, k)
		}
	}
}

// resolve returns the resolution of a node.
func (t *RatchetTree) resolve(n NodeIndex) []NodeIndex {
	if x := t.node(n); x != nil {
		out := []NodeIndex{n}
		if x.Parent != nil {
			for _, l := range x.Parent.UnmergedLeaves {
				out = append(out, l.Node())
			}
		}
		return out
	}
	if n.IsLeaf() {
		return nil
	}
	return append(t.resolve(n.Left()), t.resolve(n.Right())...)
}

type fdpEntry struct {
	node       NodeIndex
	resolution []NodeIndex
}

// filteredDirectPath returns the filtered direct path of n with the copath
// child resolutions.
func (t *RatchetTree) filteredDirectPath(n NodeIndex) []fdpEntry {
	var out []fdpEntry
	for _, c := range n.Copath(t.size) {
		res := t.resolve(c)
		if len(res) == 0 {
			continue
		}
		out = append(out, fdpEntry{node: c.Parent(), resolution: res})
	}
	return out
}

func (t *RatchetTree) find(leaf *LeafNode) (LeafIndex, bool) {
	enc := leaf.Bytes()
	for i := LeafIndex(0); uint32(i) < t.size; i++ {
		if l := t.LeafNode(i); l != nil && bytes.Equal(l.Bytes(), enc) {
			return i, true
		}
	}
	return 0, false
}

func (t *RatchetTree) rootHash() []byte {
	if t.size == 0 {
		return nil
	}
	return t.hash(Root(t.size))
}

func (t *RatchetTree) setHashAll() {
	if t.size > 0 {
		t.hash(Root(t.size))
	}
}

func leafHashInput(i LeafIndex, leaf *LeafNode) []byte {
	return marshalOf(func(w *tls.Writer) {
		w.U8(nodeTypeLeaf)
		w.U32(uint32(i))
		w.Optional(leaf != nil, func(w *tls.Writer) { leaf.marshal(w) })
	})
}

func parentHashInput(p *ParentNode, left, right []byte) []byte {
	return marshalOf(func(w *tls.Writer) {
		w.U8(nodeTypeParent)
		w.Optional(p != nil, func(w *tls.Writer) { p.marshal(w) })
		w.Opaque(left)
		w.Opaque(right)
	})
}

func (t *RatchetTree) hash(n NodeIndex) []byte {
	if h, ok := t.hashes[n]; ok {
		return h
	}
	var in []byte
	if n.IsLeaf() {
		var leaf *LeafNode
		if x := t.node(n); x != nil {
			leaf = x.Leaf
		}
		in = leafHashInput(n.Leaf(), leaf)
	} else {
		in = parentHashInput(t.parentNode(n), t.hash(n.Left()), t.hash(n.Right()))
	}
	h := t.suite.Hash(in)
	t.hashes[n] = h
	return h
}

func parentHashOf(suite CipherSuite, encKey HPKEPublicKey, parentHash, siblingHash []byte) []byte {
	return suite.Hash(marshalOf(func(w *tls.Writer) {
		w.Opaque(encKey)
		w.Opaque(parentHash)
		w.Opaque(siblingHash)
	}))
}

// parentHashes computes the parent hash chain for an UpdatePath from leaf
// `from` (mlspp TreeKEMPublicKey::parent_hashes).
func (t *RatchetTree) parentHashes(from LeafIndex, fdp []fdpEntry, pathNodes []UpdatePathNode) ([][]byte, error) {
	if len(fdp) == 0 {
		return nil, nil
	}
	dp := make([]NodeIndex, 0, len(fdp))
	dp = append(dp, from.Node())
	for _, e := range fdp[:len(fdp)-1] {
		dp = append(dp, e.node)
	}
	last := fdp[len(fdp)-1].node
	if len(dp) != len(pathNodes) {
		return nil, errors.New("mls: malformed UpdatePath")
	}
	ph := make([][]byte, len(dp))
	var lastHash []byte
	for i := len(dp) - 1; i >= 0; i-- {
		n := dp[i]
		s := n.SiblingUnder(last)
		sh, ok := t.hashes[s]
		if !ok {
			sh = t.hash(s)
		}
		lastHash = parentHashOf(t.suite, pathNodes[i].EncryptionKey, lastHash, sh)
		ph[i] = lastHash
		last = n
	}
	return ph, nil
}

// merge applies an UpdatePath from leaf `from`.
func (t *RatchetTree) merge(from LeafIndex, path *UpdatePath) error {
	if err := t.updateLeaf(from, &path.LeafNode); err != nil {
		return err
	}
	fdp := t.filteredDirectPath(from.Node())
	if len(fdp) != len(path.Nodes) {
		return errors.New("mls: malformed direct path")
	}
	ph, err := t.parentHashes(from, fdp, path.Nodes)
	if err != nil {
		return err
	}
	for i, e := range fdp {
		var parentHash []byte
		if i < len(fdp)-1 {
			parentHash = ph[i+1]
		}
		t.nodes[e.node] = &Node{Parent: &ParentNode{
			EncryptionKey: append(HPKEPublicKey{}, path.Nodes[i].EncryptionKey...),
			ParentHash:    parentHash,
		}}
	}
	t.hashes = map[NodeIndex][]byte{}
	t.setHashAll()
	return nil
}

// parentHashValidPath checks the parent hash of an UpdatePath against the
// tree (before merge).
func (t *RatchetTree) parentHashValidPath(from LeafIndex, path *UpdatePath) bool {
	return t.parentHashValidWith(from, path, t.filteredDirectPath(from.Node()))
}

func (t *RatchetTree) parentHashValidWith(from LeafIndex, path *UpdatePath, fdp []fdpEntry) bool {
	chain, err := t.parentHashes(from, fdp, path.Nodes)
	if err != nil {
		return false
	}
	var leafPH []byte
	hasPH := path.LeafNode.Source == LeafNodeSourceCommit
	if hasPH {
		leafPH = path.LeafNode.ParentHash
	}
	if len(chain) == 0 {
		return !hasPH
	}
	return hasPH && bytes.Equal(leafPH, chain[0])
}

func (t *RatchetTree) hasParentHash(child NodeIndex, target []byte) bool {
	for _, n := range t.resolve(child) {
		if bytes.Equal(t.node(n).parentHash(), target) {
			return true
		}
	}
	return false
}

type treeHashCacheEntry struct {
	exceptSize int
	hash       []byte
}

func (t *RatchetTree) originalTreeHash(cache map[NodeIndex]treeHashCacheEntry, n NodeIndex, parentExcept []LeafIndex) []byte {
	var except []LeafIndex
	for _, l := range parentExcept {
		if l.Node().IsBelow(n) {
			except = append(except, l)
		}
	}
	if len(except) == 0 {
		return t.hash(n)
	}
	if e, ok := cache[n]; ok && e.exceptSize == len(except) {
		return e.hash
	}
	var h []byte
	if n.IsLeaf() {
		h = t.suite.Hash(leafHashInput(n.Leaf(), nil))
	} else {
		left := t.originalTreeHash(cache, n.Left(), except)
		right := t.originalTreeHash(cache, n.Right(), except)
		var p *ParentNode
		if x := t.parentNode(n); x != nil {
			p = x.clone()
			kept := p.UnmergedLeaves[:0]
			for _, u := range p.UnmergedLeaves {
				excluded := false
				for _, e := range except {
					if u == e {
						excluded = true
						break
					}
				}
				if !excluded {
					kept = append(kept, u)
				}
			}
			p.UnmergedLeaves = kept
		}
		h = t.suite.Hash(parentHashInput(p, left, right))
	}
	cache[n] = treeHashCacheEntry{exceptSize: len(except), hash: h}
	return h
}

func (t *RatchetTree) originalParentHash(cache map[NodeIndex]treeHashCacheEntry, parent, sibling NodeIndex) []byte {
	p := t.parentNode(parent)
	sh := t.originalTreeHash(cache, sibling, p.UnmergedLeaves)
	return parentHashOf(t.suite, p.EncryptionKey, p.ParentHash, sh)
}

// parentHashValid verifies the parent hash invariant over the whole tree.
func (t *RatchetTree) parentHashValid() bool {
	cache := map[NodeIndex]treeHashCacheEntry{}
	width := NodeCount(t.size)
	height := Root(t.size).Level()
	for level := uint(1); level <= height; level++ {
		stride := uint32(2) << level
		start := (stride >> 1) - 1
		for p := start; p < width; p += stride {
			pn := NodeIndex(p)
			if t.blank(pn) {
				continue
			}
			l, r := pn.Left(), pn.Right()
			lh := t.originalParentHash(cache, pn, r)
			rh := t.originalParentHash(cache, pn, l)
			if !t.hasParentHash(l, lh) && !t.hasParentHash(r, rh) {
				return false
			}
		}
	}
	return true
}

// MarshalBinary encodes the tree as in the ratchet_tree extension.
func (t *RatchetTree) MarshalBinary() ([]byte, error) { return finish(t.marshal) }

func (t *RatchetTree) marshal(w *tls.Writer) {
	w.Vector(func(w *tls.Writer) {
		if t.size == 0 {
			return
		}
		cut := LeafIndex(t.size - 1)
		for cut > 0 && t.blank(cut.Node()) {
			cut--
		}
		end := uint32(cut.Node()) + 1
		for i := uint32(0); i < end; i++ {
			n := t.nodes[i]
			w.Optional(n != nil, func(w *tls.Writer) { n.marshal(w) })
		}
	})
}

func (t *RatchetTree) unmarshal(r *tls.Reader) {
	var nodes []*Node
	r.VectorEach(func(r *tls.Reader) {
		var n *Node
		r.Optional(func(r *tls.Reader) {
			n = &Node{}
			n.unmarshal(r)
		})
		nodes = append(nodes, n)
	})
	if r.Err() != nil || len(nodes) == 0 {
		return
	}
	if len(nodes)%2 == 0 {
		r.SetErr(errors.New("mls: malformed ratchet tree: even number of nodes"))
		return
	}
	if nodes[len(nodes)-1] == nil {
		r.SetErr(errors.New("mls: ratchet tree does not use minimal encoding"))
		return
	}
	t.size = 1
	for NodeCount(t.size) < uint32(len(nodes)) {
		t.size *= 2
	}
	t.nodes = make([]*Node, NodeCount(t.size))
	copy(t.nodes, nodes)
	for i, n := range t.nodes {
		if n == nil {
			continue
		}
		atLeaf := i%2 == 0
		if atLeaf != (n.Leaf != nil) {
			r.SetErr(fmt.Errorf("mls: node type mismatch at index %d", i))
			return
		}
	}
}

// UnmarshalRatchetTree decodes a ratchet tree.
func UnmarshalRatchetTree(suite CipherSuite, b []byte) (*RatchetTree, error) {
	t := newRatchetTree(suite)
	if err := decode(b, t.unmarshal); err != nil {
		return nil, err
	}
	return t, nil
}

// RootHash returns the tree hash.
func (t *RatchetTree) RootHash() []byte {
	t.setHashAll()
	return append([]byte{}, t.rootHash()...)
}

// treePrivateKey is the private state of a ratchet tree member
// (mlspp TreeKEMPrivateKey).
type treePrivateKey struct {
	suite        CipherSuite
	index        LeafIndex
	updateSecret []byte
	pathSecrets  map[NodeIndex][]byte
	keyCache     map[NodeIndex]*HPKEPrivateKey
}

func newTreePrivateKey(suite CipherSuite, index LeafIndex) *treePrivateKey {
	return &treePrivateKey{suite: suite, index: index, pathSecrets: map[NodeIndex][]byte{}, keyCache: map[NodeIndex]*HPKEPrivateKey{}}
}

func (p *treePrivateKey) clone() *treePrivateKey {
	c := newTreePrivateKey(p.suite, p.index)
	c.updateSecret = p.updateSecret
	for k, v := range p.pathSecrets {
		c.pathSecrets[k] = v
	}
	for k, v := range p.keyCache {
		c.keyCache[k] = v
	}
	return c
}

func soloTreePrivateKey(suite CipherSuite, index LeafIndex, leaf *HPKEPrivateKey) *treePrivateKey {
	p := newTreePrivateKey(suite, index)
	p.keyCache[index.Node()] = leaf
	return p
}

func joinerTreePrivateKey(t *RatchetTree, index LeafIndex, leaf *HPKEPrivateKey, intersect NodeIndex, pathSecret []byte) *treePrivateKey {
	p := newTreePrivateKey(t.suite, index)
	p.keyCache[index.Node()] = leaf
	if pathSecret != nil {
		p.implantMatching(t, intersect, pathSecret)
	}
	return p
}

func (p *treePrivateKey) implant(t *RatchetTree, start NodeIndex, pathSecret []byte) {
	secret := pathSecret
	p.pathSecrets[start] = secret
	delete(p.keyCache, start)
	for _, e := range t.filteredDirectPath(start) {
		secret = p.suite.DeriveSecret(secret, "path")
		p.pathSecrets[e.node] = secret
		delete(p.keyCache, e.node)
	}
	p.updateSecret = p.suite.DeriveSecret(secret, "path")
}

func (p *treePrivateKey) implantMatching(t *RatchetTree, start NodeIndex, pathSecret []byte) {
	secret := pathSecret
	p.pathSecrets[start] = secret
	delete(p.keyCache, start)
	for _, n := range start.DirectPath(t.size) {
		if t.blank(n) {
			continue
		}
		secret = p.suite.DeriveSecret(secret, "path")
		p.pathSecrets[n] = secret
		delete(p.keyCache, n)
	}
	p.updateSecret = p.suite.DeriveSecret(secret, "path")
}

func (p *treePrivateKey) privateKey(n NodeIndex) (*HPKEPrivateKey, error) {
	if k, ok := p.keyCache[n]; ok {
		return k, nil
	}
	s, ok := p.pathSecrets[n]
	if !ok {
		return nil, fmt.Errorf("mls: no private key for node %d", n)
	}
	k, err := DeriveHPKEPrivateKey(p.suite.DeriveSecret(s, "node"))
	if err != nil {
		return nil, err
	}
	p.keyCache[n] = k
	return k, nil
}

func (p *treePrivateKey) havePrivateKey(n NodeIndex) bool {
	_, a := p.pathSecrets[n]
	_, b := p.keyCache[n]
	return a || b
}

func (p *treePrivateKey) setLeafPriv(k *HPKEPrivateKey) {
	n := p.index.Node()
	delete(p.pathSecrets, n)
	p.keyCache[n] = k
}

func (p *treePrivateKey) sharedPathSecret(to LeafIndex) (NodeIndex, []byte, bool) {
	n := p.index.Ancestor(to)
	s, ok := p.pathSecrets[n]
	return n, s, ok
}

func (p *treePrivateKey) truncate(size uint32) {
	ni := LeafIndex(size - 1).Node()
	for n := range p.pathSecrets {
		if n > ni {
			delete(p.pathSecrets, n)
			delete(p.keyCache, n)
		}
	}
	for n := range p.keyCache {
		if n > ni {
			delete(p.keyCache, n)
		}
	}
}

func (p *treePrivateKey) consistent(t *RatchetTree) bool {
	for n := range p.pathSecrets {
		if _, err := p.privateKey(n); err != nil {
			return false
		}
	}
	for n, k := range p.keyCache {
		x := t.node(n)
		if x == nil {
			continue
		}
		if !bytes.Equal(k.PublicKey(), x.EncryptionKey()) {
			return false
		}
	}
	return true
}

// decap decrypts the path secret from an UpdatePath (mlspp decap with a
// pre-located node).
func (p *treePrivateKey) decap(from LeafIndex, t *RatchetTree, context []byte, decryptNode NodeIndex, ct *HPKECiphertext) error {
	overlap := from.Ancestor(p.index)
	priv, err := p.privateKey(decryptNode)
	if err != nil {
		return err
	}
	pathSecret, err := priv.DecryptWithLabel("UpdatePathNode", context, ct)
	if err != nil {
		return err
	}
	p.implantMatching(t, overlap, pathSecret)
	if !p.consistent(t) {
		return errors.New("mls: TreeKEM public and private state are inconsistent")
	}
	return nil
}

// createTreePrivateKey generates path secrets from leafSecret.
func createTreePrivateKey(t *RatchetTree, from LeafIndex, leafSecret []byte) *treePrivateKey {
	p := newTreePrivateKey(t.suite, from)
	p.implant(t, from.Node(), leafSecret)
	return p
}

// update replaces the committer's direct path with fresh keys and returns the
// new private state (mlspp TreeKEMPublicKey::update).
func (t *RatchetTree) update(from LeafIndex, leafSecret, groupID []byte, sigPriv *SignaturePrivateKey) (*treePrivateKey, error) {
	leaf := t.LeafNode(from)
	if leaf == nil {
		return nil, errors.New("mls: cannot update from blank leaf")
	}
	priv := createTreePrivateKey(t, from, leafSecret)
	fdp := t.filteredDirectPath(from.Node())
	pathNodes := make([]UpdatePathNode, len(fdp))
	for i, e := range fdp {
		k, err := priv.privateKey(e.node)
		if err != nil {
			return nil, err
		}
		pathNodes[i] = UpdatePathNode{EncryptionKey: k.PublicKey()}
	}
	ph, err := t.parentHashes(from, fdp, pathNodes)
	if err != nil {
		return nil, err
	}
	var ph0 []byte
	if len(ph) > 0 {
		ph0 = ph[0]
	}
	leafPriv, err := priv.privateKey(from.Node())
	if err != nil {
		return nil, err
	}
	newLeaf := leaf.Clone()
	newLeaf.EncryptionKey = leafPriv.PublicKey()
	newLeaf.Source = LeafNodeSourceCommit
	newLeaf.Lifetime = Lifetime{}
	newLeaf.ParentHash = ph0
	if newLeaf.ParentHash == nil {
		newLeaf.ParentHash = []byte{}
	}
	if err := newLeaf.Sign(sigPriv, groupID, from); err != nil {
		return nil, err
	}
	if err := t.merge(from, &UpdatePath{LeafNode: *newLeaf, Nodes: pathNodes}); err != nil {
		return nil, err
	}
	return priv, nil
}

// encap encrypts the path secrets to the copath resolution, excluding the
// given (newly added) leaves.
func (t *RatchetTree) encap(priv *treePrivateKey, context []byte, except []LeafIndex) (*UpdatePath, error) {
	fdp := t.filteredDirectPath(priv.index.Node())
	nodes := make([]UpdatePathNode, len(fdp))
	for i, e := range fdp {
		res := removeLeaves(e.resolution, except)
		secret := priv.pathSecrets[e.node]
		k, err := priv.privateKey(e.node)
		if err != nil {
			return nil, err
		}
		nodes[i].EncryptionKey = k.PublicKey()
		for _, nr := range res {
			ct, err := EncryptWithLabel(t.node(nr).EncryptionKey(), "UpdatePathNode", context, secret)
			if err != nil {
				return nil, err
			}
			nodes[i].EncryptedPathSecret = append(nodes[i].EncryptedPathSecret, *ct)
		}
	}
	leaf := t.LeafNode(priv.index)
	return &UpdatePath{LeafNode: *leaf.Clone(), Nodes: nodes}, nil
}

func removeLeaves(res []NodeIndex, except []LeafIndex) []NodeIndex {
	out := append([]NodeIndex{}, res...)
	for _, l := range except {
		for i, n := range out {
			if n == l.Node() {
				out = append(out[:i], out[i+1:]...)
				break
			}
		}
	}
	return out
}

type decapCoords struct {
	ancestorNodeIndex   int
	resolutionNodeIndex int
	resolutionNode      NodeIndex
}

// decapCoords locates the UpdatePath ciphertext that member `to` can
// decrypt. Among the copath resolution nodes covering `to`, the first one
// for which priv holds a private key is chosen (an unmerged leaf may be
// covered by a parent node it has no key for); without priv the first
// covering node is returned, as in mlspp.
func (t *RatchetTree) decapCoords(to, from LeafIndex, joiners []LeafIndex, priv ...*treePrivateKey) (decapCoords, error) {
	ancestor := to.Ancestor(from)
	fdp := t.filteredDirectPath(from.Node())
	ai := -1
	for i, e := range fdp {
		if e.node == ancestor {
			ai = i
			break
		}
	}
	if ai < 0 {
		return decapCoords{}, errors.New("mls: common ancestor not in filtered direct path")
	}
	res := removeLeaves(fdp[ai].resolution, joiners)
	first := -1
	for j, n := range res {
		if !to.Node().IsBelow(n) {
			continue
		}
		if first < 0 {
			first = j
		}
		if len(priv) == 0 || priv[0] == nil || priv[0].havePrivateKey(n) {
			return decapCoords{ancestorNodeIndex: ai, resolutionNodeIndex: j, resolutionNode: n}, nil
		}
	}
	if first < 0 {
		return decapCoords{}, errors.New("mls: no resolution node covers this member")
	}
	return decapCoords{ancestorNodeIndex: ai, resolutionNodeIndex: first, resolutionNode: res[first]}, nil
}
