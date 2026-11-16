package main

import (
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	mrand "math/rand"
	"os"
	"strconv"

	dave "github.com/famomatic/puredave"
	"github.com/famomatic/puredave/mls"
)

type member interface {
	UID() string
	KeyPackage() []byte
	ProcessProposals([]byte) []byte
	ProcessCommit([]byte) bool
	ProcessWelcome([]byte) bool
	EpochAuthenticator() []byte
	SetupRatchets(peers []string)
	Encrypt([]byte) []byte
	Decrypt(from string, frame []byte) []byte
}

// ---- puredave member ----

type pMember struct {
	uid string
	s   *dave.Session
	enc *dave.Encryptor
	dec map[string]*dave.Decryptor
}

func newPMember(uid string, groupID uint64, ext []byte, others []string) *pMember {
	m := &pMember{uid: uid, dec: map[string]*dave.Decryptor{}}
	m.s = dave.NewSession(dave.WithFailureCallback(func(src, reason string) {
		fmt.Fprintf(os.Stderr, "  [puredave %s] %s: %s\n", uid, src, reason)
	}))
	for _, o := range others {
		m.s.AddRecognizedUser(o)
	}
	m.s.Init(1, groupID, uid, nil)
	if err := m.s.SetExternalSender(ext); err != nil {
		panic(err)
	}
	m.enc = dave.NewEncryptor()
	m.enc.AssignSsrcToCodec(1, dave.CodecOpus)
	return m
}

func (m *pMember) UID() string { return m.uid }
func (m *pMember) KeyPackage() []byte {
	b, err := m.s.MarshalledKeyPackage()
	if err != nil {
		panic(err)
	}
	return b
}
func (m *pMember) ProcessProposals(b []byte) []byte {
	out, _ := m.s.ProcessProposals(b)
	return out
}
func (m *pMember) ProcessCommit(b []byte) bool {
	_, err := m.s.ProcessCommit(b)
	return err == nil
}
func (m *pMember) ProcessWelcome(b []byte) bool {
	_, err := m.s.ProcessWelcome(b)
	return err == nil
}
func (m *pMember) EpochAuthenticator() []byte { return m.s.LastEpochAuthenticator() }
func (m *pMember) SetupRatchets(peers []string) {
	m.enc.SetKeyRatchet(m.s.KeyRatchet(m.uid))
	for _, p := range peers {
		d, ok := m.dec[p]
		if !ok {
			d = dave.NewDecryptor()
			m.dec[p] = d
		}
		d.TransitionToKeyRatchet(m.s.KeyRatchet(p), dave.DefaultTransitionDuration)
	}
}
func (m *pMember) Encrypt(frame []byte) []byte {
	out := make([]byte, m.enc.MaxCiphertextByteSize(dave.MediaTypeAudio, len(frame)))
	n, r := m.enc.Encrypt(dave.MediaTypeAudio, 1, frame, out)
	if r != dave.EncryptSuccess {
		return nil
	}
	return out[:n]
}
func (m *pMember) Decrypt(from string, frame []byte) []byte {
	out := make([]byte, len(frame))
	n, r := m.dec[from].Decrypt(dave.MediaTypeAudio, frame, out)
	if r != dave.DecryptSuccess {
		return nil
	}
	return out[:n]
}

// ---- gateway simulation ----

type gateway struct {
	key     *mls.SignaturePrivateKey
	ext     []byte
	groupID uint64
	epoch   uint64
	leaves  []string // uid by leaf index, "" for blank
	members map[string]member
	rng     *mrand.Rand

	pendingEvict []string
}

var knownLibdaveRejections int

func (g *gateway) groupIDBytes() []byte {
	b := make([]byte, 8)
	v := g.groupID
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b
}

func appendVarint(dst []byte, n int) []byte {
	switch {
	case n < 1<<6:
		return append(dst, byte(n))
	case n < 1<<14:
		return append(dst, byte(n>>8)|0x40, byte(n))
	default:
		return append(dst, byte(n>>24)|0x80, byte(n>>16), byte(n>>8), byte(n))
	}
}

func (g *gateway) proposalsMsg(ps ...*mls.Proposal) []byte {
	var body []byte
	for _, p := range ps {
		m, err := mls.NewExternalProposal(g.groupIDBytes(), g.epoch, 0, p, g.key)
		if err != nil {
			panic(err)
		}
		b, err := m.MarshalBinary()
		if err != nil {
			panic(err)
		}
		body = append(body, b...)
	}
	out := []byte{0}
	out = appendVarint(out, len(body))
	return append(out, body...)
}

func splitCommitWelcome(b []byte) (commit, welcome []byte) {
	_, n, err := mls.DecodeMLSMessage(b)
	if err != nil {
		panic(err)
	}
	return b[:n], b[n:]
}

func (g *gateway) uids() []string {
	var out []string
	for _, u := range g.leaves {
		if u != "" {
			out = append(out, u)
		}
	}
	return out
}

func (g *gateway) allocate(uid string) {
	for i, u := range g.leaves {
		if u == "" {
			g.leaves[i] = uid
			return
		}
	}
	g.leaves = append(g.leaves, uid)
}

func (g *gateway) leafOf(uid string) uint32 {
	for i, u := range g.leaves {
		if u == uid {
			return uint32(i)
		}
	}
	panic("unknown member " + uid)
}

func kind(m member) string {
	if _, ok := m.(*pMember); ok {
		return "puredave"
	}
	return "libdave"
}

// commitRound sends proposals to all current members, picks a random
// committer and announces its commit; returns the welcome bytes.
func (g *gateway) commitRound(body []byte) ([]byte, member) {
	uids := g.uids()
	type out struct {
		m  member
		cw []byte
	}
	var outs []out
	for _, u := range uids {
		m := g.members[u]
		cw := m.ProcessProposals(body)
		if cw == nil {
			fail("%s (%s) produced no commit", u, kind(m))
		}
		outs = append(outs, out{m, cw})
	}
	winner := outs[g.rng.Intn(len(outs))]
	commit, welcome := splitCommitWelcome(winner.cw)
	var rejected []string
	for _, o := range outs {
		if !o.m.ProcessCommit(commit) {
			if kind(o.m) == "puredave" {
				fail("%s (%s) rejected commit from %s (%s)", o.m.UID(), kind(o.m), winner.m.UID(), kind(winner.m))
			}
			fmt.Printf("  KNOWN: %s (libdave) rejected commit from %s (%s)\n", o.m.UID(), winner.m.UID(), kind(winner.m))
			knownLibdaveRejections++
			rejected = append(rejected, o.m.UID())
		}
	}
	g.epoch++
	g.pendingEvict = append(g.pendingEvict, rejected...)
	return welcome, winner.m
}

func (g *gateway) add(m member) {
	kpb := m.KeyPackage()
	kp, err := mls.UnmarshalKeyPackage(kpb)
	if err != nil {
		fail("key package from %s (%s) does not parse: %v", m.UID(), kind(m), err)
	}
	welcome, winner := g.commitRound(g.proposalsMsg(&mls.Proposal{Type: mls.ProposalTypeAdd, KeyPackage: kp}))
	if len(welcome) == 0 {
		fail("no welcome for add")
	}
	if !m.ProcessWelcome(welcome) {
		fail("%s (%s) rejected welcome from %s (%s)", m.UID(), kind(m), winner.UID(), kind(winner))
	}
	g.members[m.UID()] = m
	g.allocate(m.UID())
	fmt.Printf("epoch %d: added %s (%s), committed by %s (%s)\n", g.epoch, m.UID(), kind(m), winner.UID(), kind(winner))
}

func (g *gateway) remove(uid string) {
	leaf := g.leafOf(uid)
	g.leaves[leaf] = ""
	removed := g.members[uid]
	delete(g.members, uid)
	_, winner := g.commitRound(g.proposalsMsg(&mls.Proposal{Type: mls.ProposalTypeRemove, Removed: mls.LeafIndex(leaf)}))
	for len(g.leaves) > 0 && g.leaves[len(g.leaves)-1] == "" {
		g.leaves = g.leaves[:len(g.leaves)-1]
	}
	fmt.Printf("epoch %d: removed %s (%s), committed by %s (%s)\n", g.epoch, uid, kind(removed), winner.UID(), kind(winner))
}

func (g *gateway) evict() {
	for len(g.pendingEvict) > 0 {
		uid := g.pendingEvict[0]
		g.pendingEvict = g.pendingEvict[1:]
		if _, ok := g.members[uid]; ok {
			g.remove(uid)
		}
	}
}

func (g *gateway) check() {
	g.evict()
	uids := g.uids()
	var auth []byte
	for _, u := range uids {
		a := g.members[u].EpochAuthenticator()
		if auth == nil {
			auth = a
		} else if !bytes.Equal(a, auth) {
			fail("epoch authenticator mismatch at %s", u)
		}
	}
	for _, u := range uids {
		var peers []string
		for _, p := range uids {
			if p != u {
				peers = append(peers, p)
			}
		}
		g.members[u].SetupRatchets(peers)
	}
	for _, u := range uids {
		frame := make([]byte, 20+g.rng.Intn(200))
		rand.Read(frame)
		for i := 0; i < 3; i++ {
			ct := g.members[u].Encrypt(frame)
			if ct == nil {
				fail("%s failed to encrypt", u)
			}
			for _, v := range uids {
				if v == u {
					continue
				}
				pt := g.members[v].Decrypt(u, ct)
				if !bytes.Equal(pt, frame) {
					fail("%s (%s) could not decrypt frame from %s (%s)", v, kind(g.members[v]), u, kind(g.members[u]))
				}
			}
		}
	}
	fmt.Printf("  ok: %d members agree on epoch authenticator %x..., frames decrypt both ways\n", len(uids), auth[:6])
}

func fail(format string, args ...any) {
	fmt.Printf("FAIL: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	seedFlag := flag.Int64("seed", 1, "random seed")
	roundsFlag := flag.Int("rounds", 40, "number of add/remove rounds")
	flag.Parse()
	seed, rounds := *seedFlag, *roundsFlag
	key, _ := mls.GenerateSignaturePrivateKey()
	es := &mls.ExternalSender{SignatureKey: key.PublicKey(), Credential: mls.NewBasicCredential([]byte("gateway"))}
	ext, _ := es.MarshalBinary()
	g := &gateway{key: key, ext: ext, groupID: 1234567890123, members: map[string]member{}, rng: mrand.New(mrand.NewSource(seed))}

	var all []string
	for i := 0; i < 64; i++ {
		all = append(all, strconv.Itoa(1000000000000+i))
	}
	next := 0
	newMember := func() member {
		uid := all[next]
		next++
		if g.rng.Intn(2) == 0 {
			return newPMember(uid, g.groupID, ext, all)
		}
		return newCMember(uid, g.groupID, ext, all)
	}

	// Initial group: two pending members; one commits the other's add.
	a, b := newPMember(all[0], g.groupID, ext, all), member(newCMember(all[1], g.groupID, ext, all))
	next = 2
	if g.rng.Intn(2) == 0 {
		a2 := member(a)
		a2, b = b, a2
		g.initial(a2, b)
	} else {
		g.initial(a, b)
	}
	g.check()

	for r := 0; r < rounds; r++ {
		if len(g.uids()) > 2 && g.rng.Intn(3) == 0 {
			uids := g.uids()
			g.remove(uids[g.rng.Intn(len(uids))])
		} else if next < len(all) {
			g.add(newMember())
		}
		g.check()
	}
	differential(g)
	fmt.Println("PASS seed", seed, "known libdave rejections:", knownLibdaveRejections)
}

// initial runs DAVE initial group creation: the committer's pending group
// commits an add for the joiner, which processes only the welcome.
func (g *gateway) initial(committer, joiner member) {
	kp, err := mls.UnmarshalKeyPackage(joiner.KeyPackage())
	if err != nil {
		fail("key package: %v", err)
	}
	_ = committer.KeyPackage()
	body := g.proposalsMsg(&mls.Proposal{Type: mls.ProposalTypeAdd, KeyPackage: kp})
	cw := committer.ProcessProposals(body)
	if cw == nil {
		fail("initial committer %s produced no commit", kind(committer))
	}
	commit, welcome := splitCommitWelcome(cw)
	if !committer.ProcessCommit(commit) {
		fail("initial committer %s rejected own commit", kind(committer))
	}
	if !joiner.ProcessWelcome(welcome) {
		fail("initial joiner %s rejected welcome from %s", kind(joiner), kind(committer))
	}
	g.epoch = 1
	g.leaves = []string{committer.UID(), joiner.UID()}
	g.members[committer.UID()] = committer
	g.members[joiner.UID()] = joiner
	fmt.Printf("epoch 1: group created by %s (%s), joined by %s (%s)\n", committer.UID(), kind(committer), joiner.UID(), kind(joiner))
}
