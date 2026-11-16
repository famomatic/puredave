package mls

// Array-based binary tree math (RFC 9420 Appendix C).

// LeafIndex is the index of a leaf among the leaves of a tree.
type LeafIndex uint32

// NodeIndex is the index of a node in the array representation of a tree.
type NodeIndex uint32

// Node returns the node index of the leaf.
func (l LeafIndex) Node() NodeIndex { return NodeIndex(2 * l) }

// Ancestor returns the lowest common ancestor of two leaves.
func (l LeafIndex) Ancestor(other LeafIndex) NodeIndex {
	ln, rn := l.Node(), other.Node()
	if ln == rn {
		return ln
	}
	k := uint(0)
	for ln != rn {
		ln >>= 1
		rn >>= 1
		k++
	}
	prefix := uint32(ln) << k
	stop := uint32(1) << (k - 1)
	return NodeIndex(prefix + (stop - 1))
}

func log2(x uint32) uint {
	if x == 0 {
		return 0
	}
	k := uint(0)
	for x>>k > 0 {
		k++
	}
	return k - 1
}

// Level returns the level of the node (leaves are level 0).
func (n NodeIndex) Level() uint {
	if n&1 == 0 {
		return 0
	}
	k := uint(0)
	for (uint32(n)>>k)&1 == 1 {
		k++
	}
	return k
}

// IsLeaf reports whether the node is a leaf.
func (n NodeIndex) IsLeaf() bool { return n&1 == 0 }

// Leaf returns the leaf index of a leaf node.
func (n NodeIndex) Leaf() LeafIndex { return LeafIndex(n / 2) }

// Left returns the left child of a parent node.
func (n NodeIndex) Left() NodeIndex {
	k := n.Level()
	if k == 0 {
		return n
	}
	return n ^ (1 << (k - 1))
}

// Right returns the right child of a parent node.
func (n NodeIndex) Right() NodeIndex {
	k := n.Level()
	if k == 0 {
		return n
	}
	return n ^ (3 << (k - 1))
}

// Parent returns the parent of a node (in an infinite tree).
func (n NodeIndex) Parent() NodeIndex {
	k := n.Level()
	b := (uint32(n) >> (k + 1)) & 1
	return NodeIndex((uint32(n) | (1 << k)) ^ (b << (k + 1)))
}

// Sibling returns the other child of the node's parent.
func (n NodeIndex) Sibling() NodeIndex {
	p := n.Parent()
	if n < p {
		return p.Right()
	}
	return p.Left()
}

// SiblingUnder returns the child of ancestor that is not on n's path.
func (n NodeIndex) SiblingUnder(ancestor NodeIndex) NodeIndex {
	l, r := ancestor.Left(), ancestor.Right()
	if n.IsBelow(l) {
		return r
	}
	return l
}

// IsBelow reports whether n is in the subtree rooted at other (or equal).
func (n NodeIndex) IsBelow(other NodeIndex) bool {
	lx, ly := n.Level(), other.Level()
	if lx > ly {
		return false
	}
	return uint32(n)>>(ly+1) == uint32(other)>>(ly+1)
}

// NodeCount is the number of nodes in a tree with leafCount leaves.
func NodeCount(leafCount uint32) uint32 {
	if leafCount == 0 {
		return 0
	}
	return 2*(leafCount-1) + 1
}

// Root returns the root node of a tree with leafCount leaves (a power of two).
func Root(leafCount uint32) NodeIndex {
	w := NodeCount(leafCount)
	return NodeIndex((uint32(1) << log2(w)) - 1)
}

// DirectPath returns the direct path of n, excluding n and including the root.
func (n NodeIndex) DirectPath(leafCount uint32) []NodeIndex {
	r := Root(leafCount)
	if n == r {
		return nil
	}
	var d []NodeIndex
	for x := n; x != r; {
		x = x.Parent()
		d = append(d, x)
	}
	return d
}

// Copath returns the copath of n.
func (n NodeIndex) Copath(leafCount uint32) []NodeIndex {
	d := n.DirectPath(leafCount)
	if len(d) == 0 {
		return nil
	}
	path := append([]NodeIndex{n}, d[:len(d)-1]...)
	out := make([]NodeIndex, len(path))
	for i, x := range path {
		out[i] = x.Sibling()
	}
	return out
}
